import Foundation
import FoundationModels
import Darwin
import ReachWire
import Testing
@testable import ReachDaemon

/// Gated S26 acceptance against the installed Gemma vocabulary. The ordinary
/// suite stays model-free; run with `REACH_REPLAY_S26_REAL=1` on the accepted
/// Metal host with the MLX metallib beside the test executable.
@Suite(.serialized) struct ReplayCapacityMLXTests {
    @Generable struct GuidedResult {
        var name: String
        var count: Int
    }

    @Generable struct ToolArguments {
        var name: String
        var count: Int
    }

    @Test(
        .enabled(if: ProcessInfo.processInfo.environment["REACH_REPLAY_S26_REAL"] == "1",
                 "S26 real-weight replay is an explicit host acceptance run"),
        .timeLimit(.minutes(10))
    )
    func detachedRealWeightRoutesReplayWholeFromExactFrames() async throws {
        let filling = MLXFilling(modelID: "gemma-4-e4b")
        let prewarm = ContinuousClock.now
        try await filling.prewarm()
        print("[S26 after] prewarm=\(Self.seconds(prewarm.duration(to: .now)))s rss=\(Self.residentBytes())")

        let tool = WireToolDefinition(
            name: "record_river",
            description: "Record the requested river value.",
            parameters: ToolArguments.generationSchema
        )
        let requests: [(String, WireGenerationRequest)] = [
            ("ordinary", Self.request("In one sentence, describe the mouth of a river.")),
            ("guided", WireGenerationRequest(
                id: UUID(),
                transcript: Self.transcript("Return a short river name and the integer 3."),
                schema: GuidedResult.generationSchema,
                options: WireGenerationOptions(maximumResponseTokens: 256),
                context: WireContextOptions(includeSchemaInPrompt: false)
            )),
            ("allowed-tool", WireGenerationRequest(
                id: UUID(),
                transcript: Self.transcript("Call record_river with name mouth and count 3."),
                tools: [tool],
                options: WireGenerationOptions(maximumResponseTokens: 512, toolCalling: .allowed)
            )),
            ("required-tool", WireGenerationRequest(
                id: UUID(),
                transcript: Self.transcript("Call record_river with name mouth and count 3."),
                tools: [tool],
                options: WireGenerationOptions(maximumResponseTokens: 512, toolCalling: .required)
            )),
        ]

        for (label, request) in requests {
            let registry = SessionRegistry(receiptSink: { _ in })
            let session = await registry.openSession()
            let genID = UUID()
            let began = ContinuousClock.now
            let (_, epoch, _) = try await registry.begin(
                sessionID: session.sessionID,
                genID: genID
            ) {
                filling.generate(request)
            }
            await registry.detach(sessionID: session.sessionID, genID: genID, epoch: epoch)

            let finished = await Self.eventually(timeout: .seconds(180)) {
                guard let status = try? await registry.resumeStatus(
                    sessionID: session.sessionID,
                    token: session.token
                ).first(where: { $0.genID == genID }) else { return false }
                return status.state != .streaming
            }
            #expect(finished, "\(label) never reached a terminal state")

            let replayed = try await registry.attach(
                sessionID: session.sessionID,
                genID: genID,
                fromSeq: nil
            )
            var events: [Ev] = []
            for await event in replayed.stream { events.append(event) }
            #expect(events.map(\.seq) == events.indices.map(UInt64.init))
            #expect(events.last?.event == .finished(.complete))
            let exact = try events.map { try FrameCodec.encode($0).count }.reduce(0, +)
            let counters = await registry.replayCounters
            #expect(counters.currentBytes == exact)
            print("[S26 after] \(label) elapsed=\(Self.seconds(began.duration(to: .now)))s events=\(events.count) exactReplayBytes=\(exact) rss=\(Self.residentBytes())")
            await registry.shutdown()
            #expect(await registry.replayCounters.currentBytes == 0)
        }
    }

    private static func request(_ prompt: String) -> WireGenerationRequest {
        WireGenerationRequest(
            id: UUID(),
            transcript: transcript(prompt),
            options: WireGenerationOptions(maximumResponseTokens: 128)
        )
    }

    private static func transcript(_ prompt: String) -> Transcript {
        Transcript(entries: [
            .prompt(Transcript.Prompt(segments: [
                .text(Transcript.TextSegment(content: prompt))
            ]))
        ])
    }

    private static func eventually(
        timeout: Duration,
        condition: @escaping @Sendable () async -> Bool
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if await condition() { return true }
            try? await Task.sleep(for: .milliseconds(20))
        }
        return await condition()
    }

    private static func seconds(_ duration: Duration) -> String {
        let components = duration.components
        let value = Double(components.seconds) + Double(components.attoseconds) / 1e18
        return String(format: "%.3f", value)
    }

    private static func residentBytes() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? UInt64(info.resident_size) : 0
    }
}
