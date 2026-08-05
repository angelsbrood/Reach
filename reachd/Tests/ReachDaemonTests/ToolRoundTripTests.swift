import Foundation
import FoundationModels
import ReachIdentity
import ReachKit
import ReachWire
import Security
import Testing
@testable import ReachDaemon

/// The whole round trip, over a real wire, without weights.
///
/// An app defines a framework `Tool`; the cluster's model calls it; the tool
/// runs **in the app, on the device**; the generation finishes with the tool's
/// answer woven in. The filling is scripted so the only thing under test is the
/// path — but the session, the executor, the QUIC/mTLS transport, the daemon's
/// residency and the framework's own tool loop are all real.
///
/// This is the pass's acceptance sentence. Spike S6a proved the framework
/// re-invokes the executor; this proves it still does with the wire in between.
@Suite(.serialized) struct ToolRoundTripTests {
    /// What the app's tool did, observed from the test rather than claimed by
    /// it. A tool that never ran and a tool whose answer was ignored look the
    /// same in the final text unless something counts.
    final class Ledger: @unchecked Sendable {
        private let lock = NSLock()
        private var timezones: [String] = []

        func record(_ timezone: String) {
            lock.lock()
            defer { lock.unlock() }
            timezones.append(timezone)
        }

        var calls: [String] {
            lock.lock()
            defer { lock.unlock() }
            return timezones
        }
    }

    @Generable
    struct ClockArguments {
        @Guide(description: "IANA timezone identifier, for example Europe/Vienna")
        var timezone: String
    }

    struct ClockTool: Tool {
        let name = "current_time"
        let description = "The current time on this device."
        let ledger: Ledger

        func call(arguments: ClockArguments) async throws -> String {
            ledger.record(arguments.timezone)
            return "08:15 in \(arguments.timezone)"
        }
    }

    /// Calls once, then answers. The branch is the transcript itself: a turn
    /// that already carries a tool's answer is the second turn, which is
    /// exactly how a real filling knows too.
    struct ToolCallingFilling: SlotFilling {
        let modelID = "scripted-tools"
        let displayName = "Scripted (tools)"
        let capabilities: [String] = []
        let seen: Ledger

        func prewarm() async throws {}

        func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error> {
            let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
            let answered = request.transcript.contains { entry in
                if case .toolOutput = entry { return true }
                return false
            }
            // Recorded so the test can assert the daemon was actually told
            // about the tool, rather than inferring it from a happy ending.
            seen.record(request.tools.map(\.name).joined(separator: ","))

            let task = Task {
                if answered {
                    for word in ["It ", "is ", "08:15 ", "in ", "Vienna."] {
                        continuation.yield(.responseAppend(entryID: nil, text: word, segmentID: nil, tokenCount: 1))
                    }
                } else {
                    continuation.yield(.toolCallAppendArguments(
                        entryID: UUID().uuidString,
                        id: "call-1",
                        name: "current_time",
                        content: #"{"timezone":"Europe/Vienna"}"#,
                        tokenCount: 1
                    ))
                }
                continuation.yield(.finished(.complete))
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
            return stream
        }
    }

    /// Cleans up exactly the two identities this suite minted.
    ///
    /// Deliberately NOT `IdentityTrash`: that is a single global bin whose
    /// `drain()` empties it entirely, and `.serialized` only orders a suite
    /// against itself — so one suite's teardown can delete an identity a
    /// concurrent suite is still handshaking with. That is a latent hazard in
    /// the existing suites rather than something observed here, and this one
    /// simply declines to join it: owning the cleanup costs a closure.
    ///
    /// ⚠️ Ports are hand-picked literals scattered across test files, and the
    /// first pair chosen here silently collided with `GrantTests`' 47440–47453
    /// — which fails as `.unreachable`, i.e. as a *product* error about roads,
    /// several layers from the cause. Check `grep -rioE 'port[a-z]*:? ?=? ?47[0-9]{3}'`
    /// before claiming a range; a case-sensitive grep misses `sessionPort:`.
    private func startDaemon(
        port: UInt16,
        filling: any SlotFilling
    ) async throws -> (Daemon, ReachExecutor.Configuration, @Sendable () -> Void) {
        let ca = try ClusterCA.create(commonName: "Reach Tools CA")
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let client = try ca.issueClient(commonName: "tools-app", uri: "reach://device/tools-app")
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-tools-server-\(UUID())")
        let clientIdentity = try IdentityMaterializer.materialize(client, label: "reach-tools-client-\(UUID())")
        // Boxed because `SecIdentity` is a CF type with no Sendable
        // conformance and this closure crosses into one.
        let boxes = [IdentityBox(serverIdentity), IdentityBox(clientIdentity)]
        let discard: @Sendable () -> Void = {
            for box in boxes { KeychainIdentity.remove(identity: box.identity) }
        }
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        var config = DaemonConfig()
        config.port = port
        config.clusterName = "tools"
        config.modelID = filling.modelID
        let daemon = Daemon(
            config: config,
            filling: filling,
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert)
        )
        try await daemon.start(advertise: false)

        let label = "tools-\(UUID().uuidString)"
        await ReachIdentityRegistry.shared.register(
            label: label,
            material: .init(identity: clientIdentity, caCertificate: caCert)
        )
        return (daemon, ReachExecutor.Configuration(
            host: "127.0.0.1",
            port: port,
            modelID: filling.modelID,
            identityLabel: label,
            connectTimeout: 45
        ), discard)
    }

    @Test(.timeLimit(.minutes(1)))
    func anAppsToolRunsInTheAppAndTheAnswerComesBack() async throws {
        let ranInTheApp = Ledger()
        let toolsOffered = Ledger()
        let (daemon, configuration, discard) = try await startDaemon(
            port: 47460,
            filling: ToolCallingFilling(seen: toolsOffered)
        )
        defer { Task { await daemon.stop() } }
        defer { discard() }

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            tools: [ClockTool(ledger: ranInTheApp)],
            instructions: "Answer using the tools you are given."
        )
        let reply = try await session.respond(to: "What time is it in Vienna?")

        // The tool ran here, in this process, with the arguments the cluster's
        // model chose. That is the grant boundary holding: the daemon asked and
        // was answered, and executed nothing.
        #expect(ranInTheApp.calls == ["Europe/Vienna"])
        #expect(reply.content == "It is 08:15 in Vienna.")

        // Two generations, and the daemon was told about the tool on both —
        // the second turn re-renders the definitions, so a model that wants a
        // second call can still make one.
        #expect(toolsOffered.calls == ["current_time", "current_time"])

        // The transcript a person could inspect afterwards holds the whole
        // exchange, not just its conclusion.
        let entries = session.transcript.map { entry -> String in
            switch entry {
            case .instructions: "instructions"
            case .prompt: "prompt"
            case .toolCalls: "toolCalls"
            case .toolOutput: "toolOutput"
            case .response: "response"
            case .reasoning: "reasoning"
            @unknown default: "unknown"
            }
        }
        #expect(entries == ["instructions", "prompt", "toolCalls", "toolOutput", "response"])
    }

    /// The regression that matters most: a session that was given no tools must
    /// behave exactly as it did before this pass, including that declaring
    /// `.toolCalling` on the model changed nothing for it.
    @Test(.timeLimit(.minutes(1)))
    func aSessionWithNoToolsIsUntouched() async throws {
        let toolsOffered = Ledger()
        let (daemon, configuration, discard) = try await startDaemon(
            port: 47461,
            filling: ToolCallingFilling(seen: toolsOffered)
        )
        defer { Task { await daemon.stop() } }
        defer { discard() }

        let session = LanguageModelSession(
            model: ReachLanguageModel(configuration: configuration),
            instructions: "Be terse."
        )
        // The filling calls a tool on any turn without an answer in it, so
        // with no tools attached the framework has nothing to run — which is
        // the shape a v0 daemon emitting a stray call would put an app in.
        _ = try? await session.respond(to: "What time is it in Vienna?")

        #expect(toolsOffered.calls == [""], "a tool-less session was offered tools")
    }
}
