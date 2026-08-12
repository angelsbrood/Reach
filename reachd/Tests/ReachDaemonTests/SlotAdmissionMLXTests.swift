import Foundation
import FoundationModels
import MLX
import ReachWire
import Testing
@testable import ReachDaemon

/// Gated S25 acceptance against the real Gemma filling. The ordinary suite
/// keeps this disabled because it loads the filmed weights and takes minutes;
/// run with `REACH_SLOT_S25_REAL=1` on the accepted Metal host.
@Suite(.serialized) struct SlotAdmissionMLXTests {
    @Generable
    struct GuidedResult {
        var name: String
        var count: Int
    }

    @Generable
    struct AuditArguments {
        var name: String
        var count: Int
    }

    @Test(
        .enabled(if: ProcessInfo.processInfo.environment["REACH_SLOT_S25_REAL"] == "1",
                 "S25 real-weight admission is an explicit host acceptance run"),
        .timeLimit(.minutes(15))
    )
    func realWeightMatrixKeepsOnePublicGenerationInTheFilling() async throws {
        let base = MLXFilling(modelID: "gemma-4-e4b")
        let probe = S25RealProbe()
        let filling = S25MeasuredFilling(base: base, probe: probe)
        let prewarmStart = ContinuousClock.now
        try await filling.prewarm()
        print("[S25 after] prewarm=\(Self.format(prewarmStart.duration(to: .now)))s rss=\(Self.residentBytes()) mlx=\(Memory.snapshot())")

        for count in 1 ... 4 {
            try await runBatch(
                label: "ordinary-\(count)",
                requests: (0 ..< count).map {
                    Self.request(prompt: "Reply with exactly: river \($0)", maximumTokens: 32)
                },
                filling: filling,
                probe: probe
            )
        }

        try await runBatch(
            label: "guided-4",
            requests: (0 ..< 4).map {
                WireGenerationRequest(
                    id: UUID(),
                    transcript: Self.transcript("Return a short name and integer \($0)."),
                    schema: GuidedResult.generationSchema,
                    options: WireGenerationOptions(maximumResponseTokens: 256),
                    context: WireContextOptions(includeSchemaInPrompt: false)
                )
            },
            filling: filling,
            probe: probe
        )

        let tool = WireToolDefinition(
            name: "record_audit",
            description: "Record the requested audit.",
            parameters: AuditArguments.generationSchema
        )
        for mode in [WireToolCalling.allowed, .required] {
            try await runBatch(
                label: "\(mode)-tools-4",
                requests: (0 ..< 4).map {
                    WireGenerationRequest(
                        id: UUID(),
                        transcript: Self.transcript("Call record_audit with name river and count \($0)."),
                        tools: [tool],
                        options: WireGenerationOptions(
                            maximumResponseTokens: 512,
                            toolCalling: mode
                        )
                    )
                },
                filling: filling,
                probe: probe
            )
        }

        let long = String(repeating: "river ", count: 25_000)
        try await runBatch(
            label: "long-prefill-4",
            requests: (0 ..< 4).map {
                Self.request(
                    prompt: long + "\nReply with exactly: current \($0)",
                    maximumTokens: 32
                )
            },
            filling: filling,
            probe: probe
        )

        try await cancellationPromotesNext(filling: filling, probe: probe)
        #expect(probe.snapshot.peak == 1)
        print("[S25 after] final mlx=\(Memory.snapshot())")
    }

    private func runBatch(
        label: String,
        requests: [WireGenerationRequest],
        filling: S25MeasuredFilling,
        probe: S25RealProbe
    ) async throws {
        let registry = SessionRegistry()
        let admission = SlotAdmission(eventSink: { _ in })
        let sessions = await withTaskGroup(of: (UUID, String).self) { group in
            for _ in requests { group.addTask { await registry.openSession() } }
            var values: [(UUID, String)] = []
            for await value in group { values.append(value) }
            return values
        }
        let gate = S25StartGate(expected: requests.count)
        let began = ContinuousClock.now
        let rssBefore = Self.residentBytes()

        let opened = try await withThrowingTaskGroup(
            of: (Int, AsyncStream<Ev>, ContinuousClock.Instant).self
        ) { group in
            for index in requests.indices {
                group.addTask {
                    await gate.wait()
                    let acceptedAt = ContinuousClock.now
                    let result = try await registry.begin(
                        sessionID: sessions[index].0,
                        genID: UUID(),
                        receiptSource: .loopback,
                        admission: admission,
                        events: { filling.generate(requests[index]) }
                    )
                    return (index, result.stream, acceptedAt)
                }
            }
            var values: [(Int, AsyncStream<Ev>, ContinuousClock.Instant)] = []
            for try await value in group { values.append(value) }
            return values.sorted { $0.0 < $1.0 }
        }

        if requests.count == 4 {
            let state = await admission.counters
            #expect(state.active == 1)
            #expect(state.waiting == 3)
        }

        let results = await withTaskGroup(of: S25RealResult.self) { group in
            for (index, stream, acceptedAt) in opened {
                group.addTask {
                    var first: ContinuousClock.Instant?
                    var events = 0
                    var ending: WireFinishReason?
                    for await event in stream {
                        if first == nil { first = .now }
                        events += 1
                        if case .finished(let reason) = event.event { ending = reason }
                    }
                    return S25RealResult(
                        index: index,
                        first: first.map { acceptedAt.duration(to: $0) } ?? .zero,
                        elapsed: acceptedAt.duration(to: .now),
                        events: events,
                        ending: ending
                    )
                }
            }
            var values: [S25RealResult] = []
            for await value in group { values.append(value) }
            return values.sorted { $0.index < $1.index }
        }

        #expect(results.allSatisfy { $0.ending == .complete })
        #expect(probe.snapshot.peak == 1)
        let counters = await admission.counters
        #expect(counters.active == 0)
        #expect(counters.waiting == 0)
        print("[S25 after] \(label) wall=\(Self.format(began.duration(to: .now)))s rssBefore=\(rssBefore) rssAfter=\(Self.residentBytes())")
        for result in results {
            print("  [\(result.index)] first=\(Self.format(result.first))s elapsed=\(Self.format(result.elapsed))s events=\(result.events) ending=\(String(describing: result.ending))")
        }
    }

    private func cancellationPromotesNext(
        filling: S25MeasuredFilling,
        probe: S25RealProbe
    ) async throws {
        let registry = SessionRegistry()
        let admission = SlotAdmission(eventSink: { _ in })
        let firstSession = await registry.openSession()
        let secondSession = await registry.openSession()
        let firstID = UUID()
        let long = String(repeating: "river ", count: 10_000)
        let first = try await registry.begin(
            sessionID: firstSession.sessionID,
            genID: firstID,
            receiptSource: .loopback,
            admission: admission,
            events: { filling.generate(Self.request(prompt: long, maximumTokens: 512)) }
        )
        let second = try await registry.begin(
            sessionID: secondSession.sessionID,
            genID: UUID(),
            receiptSource: .loopback,
            admission: admission,
            events: { filling.generate(Self.request(prompt: "Reply with exactly: promoted", maximumTokens: 32)) }
        )
        let entered = await Self.eventually { probe.snapshot.active == 1 }
        #expect(entered)
        await registry.cancel(sessionID: firstSession.sessionID, genID: firstID, epoch: first.epoch)

        let firstTerminal = await Self.terminal(first.stream)
        #expect(firstTerminal == .cancelled)
        let secondTerminal = await Self.terminal(second.stream)
        #expect(secondTerminal == .complete)
        let released = await Self.eventually {
            let counters = await admission.counters
            return counters.active == 0 && counters.waiting == 0
        }
        #expect(released)
        let counters = await admission.counters
        #expect(counters.cancelled == 1)
        print("[S25 after] cancellation promoted the FIFO waiter; admitted=\(counters.admitted) cancelled=\(counters.cancelled)")
    }

    private static func terminal(_ stream: AsyncStream<Ev>) async -> WireFinishReason? {
        for await event in stream {
            if case .finished(let reason) = event.event { return reason }
        }
        return nil
    }

    private static func eventually(
        _ predicate: @escaping @Sendable () async -> Bool
    ) async -> Bool {
        for _ in 0 ..< 1_000 {
            if await predicate() { return true }
            try? await Task.sleep(for: .milliseconds(5))
        }
        return false
    }

    private static func request(prompt: String, maximumTokens: Int) -> WireGenerationRequest {
        WireGenerationRequest(
            id: UUID(),
            transcript: transcript(prompt),
            options: WireGenerationOptions(maximumResponseTokens: maximumTokens)
        )
    }

    private static func transcript(_ prompt: String) -> Transcript {
        Transcript(entries: [
            .prompt(Transcript.Prompt(segments: [
                .text(Transcript.TextSegment(content: prompt))
            ]))
        ])
    }

    private static func residentBytes() -> Int64 {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-o", "rss=", "-p", "\(getpid())"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let text = String(decoding: data, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return (Int64(text) ?? -1) * 1_024
        } catch {
            return -1
        }
    }

    private static func format(_ duration: Duration) -> String {
        let components = duration.components
        let value = Double(components.seconds) + Double(components.attoseconds) / 1e18
        return String(format: "%.3f", value)
    }
}

private actor S25StartGate {
    private let expected: Int
    private var arrived = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(expected: Int) { self.expected = expected }

    func wait() async {
        arrived += 1
        if arrived == expected {
            let ready = waiters
            waiters.removeAll()
            for waiter in ready { waiter.resume() }
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }
}

private struct S25RealResult: Sendable {
    var index: Int
    var first: Duration
    var elapsed: Duration
    var events: Int
    var ending: WireFinishReason?
}

private final class S25RealProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var activeStorage = 0
    private var peakStorage = 0

    func entered() {
        lock.lock()
        activeStorage += 1
        peakStorage = max(peakStorage, activeStorage)
        lock.unlock()
    }

    func left() {
        lock.lock()
        activeStorage -= 1
        lock.unlock()
    }

    var snapshot: (active: Int, peak: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (activeStorage, peakStorage)
    }
}

private struct S25MeasuredFilling: SlotFilling {
    let base: MLXFilling
    let probe: S25RealProbe

    var modelID: String { base.modelID }
    var displayName: String { base.displayName }
    var capabilities: [String] { base.capabilities }
    var maximumConcurrentGenerations: Int { base.maximumConcurrentGenerations }

    func prewarm() async throws { try await base.prewarm() }

    func generate(
        _ request: WireGenerationRequest
    ) -> AsyncThrowingStream<WireEvent, any Error> {
        probe.entered()
        let upstream = base.generate(request)
        return AsyncThrowingStream { continuation in
            let task = Task {
                defer { probe.left() }
                do {
                    for try await event in upstream { continuation.yield(event) }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}
