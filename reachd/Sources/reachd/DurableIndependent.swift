import ArgumentParser
import Foundation
import Darwin
import ReachDurableRuntime

struct DurableIndependent: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "durable-independent", abstract: "Independently initialized durable roles on pinned 127.0.0.1 mTLS QUIC.", subcommands: [Provision.self, Initialize.self, Host.self, Begin.self, Recover.self, Cancel.self, Retire.self])
    struct Provision: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Prepare public pair agreement and separate private TLS leaves; remove this staging before serving.")
        @Option(name: .long) var publicModel: String
        @Option(name: .long) var output: String
        @Option(name: .long) var port: UInt16
        @Option(name: .long) var retentionSeconds: UInt64 = 86400
        func run() async throws {
            guard (1...86400).contains(retentionSeconds) else { throw ValidationError("Retention must be 1...86400 seconds.") }
            try IndependentPairAgreement.provision(publicModel: publicModel, directory: output, port: port, retentionCap: retentionSeconds * 1_000_000_000) {
                try DurableTransportIdentity.provision($0, application: IndependentContract.application)
            }
        }
    }
    struct Initialize: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "init", abstract: "Initialize this role; explicitly finish with a durable ownership receipt or retain foreground cleanup.")
        @Option(name: .long) var root: String
        @Option(name: .long) var role: String
        @Option(name: .long) var provisioned: String
        @Option(name: .long) var model: String?
        @Flag(name: .long) var finish = false
        @Option(name: .long) var ownerReceipt: String?
        func run() async throws {
            guard let selected = TransportRole(rawValue: role), (selected == .host) == (model != nil) else { throw ValidationError("Host requires a model; client accepts no model.") }
            guard finish == (ownerReceipt != nil) else { throw ValidationError("--finish and --owner-receipt must be selected together.") }
            let stop = finish ? nil : IndependentStop()
            do {
                let owner: IndependentRootOwner
                if selected == .host {
                    owner = try LocalDurableRuntime.withCPU { try IndependentRootOwner(root: root, role: selected, provisioned: provisioned, modelSource: model, ownerReceipt: ownerReceipt) }
                } else { owner = try IndependentRootOwner(root: root, role: selected, provisioned: provisioned, ownerReceipt: ownerReceipt) }
                struct Ready: Encodable { let stage = "ready"; let role: String, epoch: String, boot: String; let origin: UInt64; let backupExcluded: Bool; let ownerReceiptDigest: String? }
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                let bytes = try encoder.encode(Ready(role: role, epoch: owner.ready.core.epoch, boot: owner.ready.core.boot, origin: owner.ready.core.origin, backupExcluded: owner.backupExcluded, ownerReceiptDigest: owner.ownershipReceiptDigest))
                try FileHandle.standardOutput.write(contentsOf: bytes + Data([10]))
                if finish { return }
                guard let stop else { throw ExitCode.failure }
                for await _ in stop.signals {
                    do { try owner.retire(); print("{\"stage\":\"retired\"}"); fflush(stdout); return }
                    catch { independentDiagnostic(error); print("{\"stage\":\"cleanup-blocked\"}"); fflush(stdout) }
                }
            } catch { independentDiagnostic(error); throw ExitCode.failure }
        }
    }
    struct Host: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Serve the selected host journal on its literal loopback endpoint.")
        @Option(name: .long) var root: String
        @Option(name: .long) var report: String?
        @Flag(name: .long) var progress = false
        func run() async throws {
            let root = root, report = report, progress = progress
            try await independentRun { try await TransportHostEndpoint().run(root: root, report: report, progress: progress, independent: true) }
        }
    }
    struct Begin: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Begin once and persist original recovery authority in the client journal.")
        @Option(name: .long) var root: String
        @Option(name: .long) var request: String
        @Option(name: .long) var report: String?
        @Flag(name: .long) var progress = false
        func run() async throws {
            let root = root, report = report, progress = progress, request = request
            try await independentRun { try await TransportClientEndpoint(root: root, independent: true).run(requestPath: request, report: report, progress: progress) }
        }
    }
    struct Recover: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Recover using only the client's original encrypted selection.")
        @Option(name: .long) var root: String
        @Option(name: .long) var report: String?
        @Flag(name: .long) var progress = false
        func run() async throws {
            let root = root, report = report, progress = progress
            try await independentRun { try await TransportClientEndpoint(root: root, independent: true).run(requestPath: nil, report: report, progress: progress) }
        }
    }
    struct Retire: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Retire one stopped role using its original ownership receipt and retained expected digest.")
        @Option(name: .long) var ownerReceipt: String
        @Option(name: .long) var expectedDigest: String
        @Flag(name: .long) var progress = false
        func run() async throws {
            do {
                let result = try IndependentRoleLifecycle.retire(receipt: ownerReceipt, expectedDigest: expectedDigest) { boundary in
                    if progress {
                        let stage = boundary == .authorized ? "retiring" : "keychain-deleted"
                        print("{\"stage\":\"" + stage + "\"}"); fflush(stdout)
                    }
                }
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                try FileHandle.standardOutput.write(contentsOf: encoder.encode(result) + Data([10]))
            } catch { independentDiagnostic(error); throw ExitCode.failure }
        }
    }
    struct Cancel: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Retire host-local generation after the serving host has stopped.")
        @Option(name: .long) var root: String
        @Option(name: .long) var report: String?
        func run() async throws {
            let root = root, report = report
            try await independentRun { try await TransportHostEndpoint().cancelLocal(root: root, report: report, independent: true) }
        }
    }
}
private final class IndependentStop {
    let signals: AsyncStream<Void>
    private let continuation: AsyncStream<Void>.Continuation
    private var sources: [DispatchSourceSignal] = []
    init() {
        (signals, continuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(1))
        for value in [SIGINT, SIGTERM] {
            signal(value, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: value, queue: .global())
            source.setEventHandler { [weak self] in self?.continuation.yield(()) }
            source.resume(); sources.append(source)
        }
    }
    deinit { sources.forEach { $0.cancel() }; continuation.finish() }
}
private func independentRun(_ body: @escaping @Sendable () async throws -> Void) async throws {
    let stop = IndependentStop()
    let signals = stop.signals
    defer { withExtendedLifetime(stop) {} }
    do {
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await body() }
            group.addTask { for await _ in signals { break } }
            try await group.next()
        }
    } catch is CancellationError {} catch { independentDiagnostic(error); throw ExitCode.failure }
}
private func independentDiagnostic(_ error: Error) {
    // Do not print potentially content-bearing framework error descriptions.
    fputs("durable-independent stopped (\(String(describing: type(of: error)).prefix(96))).\n", stderr)
}
