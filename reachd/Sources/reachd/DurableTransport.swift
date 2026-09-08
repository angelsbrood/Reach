import ArgumentParser
import Foundation
import Darwin
import ReachDurableRuntime

struct DurableTransport: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "durable-transport", abstract: "Explicit same-boot durable generation over pinned loopback mTLS QUIC.", subcommands: [Initialize.self, Host.self, Begin.self, Recover.self, Cancel.self])
    struct Initialize: AsyncParsableCommand {
        static let configuration = CommandConfiguration(commandName: "init", abstract: "Create a fresh private pair and retain its cleanup authority until signalled.")
        @Option(name: .long) var root: String
        @Option(name: .long) var model: String
        @Option(name: .long) var port: UInt16
        func run() async throws {
            let stop = TransportStop()
            do {
                let owner = try LocalDurableRuntime.withCPU { try TransportRootOwner(root: root, modelSource: model, port: port, provision: DurableTransportIdentity.provision) }
                print("{\"stage\":\"ready\",\"backupExcluded\":\(owner.backupExcluded)}"); fflush(stdout)
                for await _ in stop.signals {
                    do { try owner.retire(); print("{\"stage\":\"retired\"}"); fflush(stdout); return }
                    catch { transportDiagnostic(error); print("{\"stage\":\"cleanup-blocked\"}"); fflush(stdout) }
                }
            } catch { transportDiagnostic(error); throw ExitCode.failure }
        }
    }
    struct Host: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Serve the selected host journal on its literal loopback endpoint.")
        @Option(name: .long) var root: String
        @Option(name: .long) var report: String?
        @Flag(name: .long) var progress = false
        func run() async throws {
            let root = root, report = report, progress = progress
            try await transportRun { try await TransportHostEndpoint().run(root: root, report: report, progress: progress) }
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
            try await transportRun { try await TransportClientEndpoint(root: root).run(requestPath: request, report: report, progress: progress) }
        }
    }
    struct Recover: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Recover using only the client's original encrypted selection.")
        @Option(name: .long) var root: String
        @Option(name: .long) var report: String?
        @Flag(name: .long) var progress = false
        func run() async throws {
            let root = root, report = report, progress = progress
            try await transportRun { try await TransportClientEndpoint(root: root).run(requestPath: nil, report: report, progress: progress) }
        }
    }
    struct Cancel: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Retire host-local generation after the serving host has stopped.")
        @Option(name: .long) var root: String
        @Option(name: .long) var report: String?
        func run() async throws {
            let root = root, report = report
            try await transportRun { try await TransportHostEndpoint().cancelLocal(root: root, report: report) }
        }
    }
}
private final class TransportStop {
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
private func transportRun(_ body: @escaping @Sendable () async throws -> Void) async throws {
    let stop = TransportStop()
    let signals = stop.signals
    defer { withExtendedLifetime(stop) {} }
    do {
        try await withThrowingTaskGroup(of: Void.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await body() }
            group.addTask { for await _ in signals { break } }
            try await group.next()
        }
    } catch is CancellationError {} catch { transportDiagnostic(error); throw ExitCode.failure }
}
private func transportDiagnostic(_ error: Error) {
    // Do not print potentially content-bearing framework error descriptions.
    fputs("durable-transport stopped (\(String(describing: type(of: error)).prefix(96))).\n", stderr)
}
