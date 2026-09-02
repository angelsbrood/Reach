import Foundation
import ReachWire
import Testing
@testable import ReachHost

private enum PortableStreamError: Error {
    case disconnected
}

final class PortableMemoryStream: SessionHostStream, @unchecked Sendable {
    let frames: AsyncThrowingStream<RawFrame, any Error>
    private let input: AsyncThrowingStream<RawFrame, any Error>.Continuation
    private let lock = NSLock()
    private let endpoint: String?
    private let failAfterSends: Int?
    private var encodedOutput: [Data] = []
    private var sendingFinished = false
    private var cancelled = false

    init(endpoint: String? = "127.0.0.1:47000", failAfterSends: Int? = nil) {
        let pair = AsyncThrowingStream<RawFrame, any Error>.makeStream()
        frames = pair.stream
        input = pair.continuation
        self.endpoint = endpoint
        self.failAfterSends = failAfterSends
    }

    func yield<Frame: WireFrame>(_ frame: Frame, version: UInt8 = Wire.baselineVersion) throws {
        let encoded = try FrameCodec.encode(frame, for: version)
        var reassembler = FrameReassembler()
        let decoded = try reassembler.feed(encoded)
        input.yield(try #require(decoded.count == 1 ? decoded[0] : nil))
    }

    func finishInput() { input.finish() }

    func send<Frame: WireFrame>(_ frame: Frame, for negotiatedVersion: UInt8) async throws {
        let encoded = try FrameCodec.encode(frame, for: negotiatedVersion)
        try lock.withLock {
            if let failAfterSends, encodedOutput.count >= failAfterSends {
                throw PortableStreamError.disconnected
            }
            encodedOutput.append(encoded)
        }
    }

    func finishSending() {
        lock.lock()
        sendingFinished = true
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func remoteEndpointDescription() -> String? { endpoint }

    var outputCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return encodedOutput.count
    }

    var didFinishSending: Bool {
        lock.lock()
        defer { lock.unlock() }
        return sendingFinished
    }

    var didCancel: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    func outputFrames() throws -> [RawFrame] {
        lock.lock()
        let snapshot = encodedOutput
        lock.unlock()
        return try snapshot.map { data in
            var reassembler = FrameReassembler()
            let decoded = try reassembler.feed(data)
            return try #require(decoded.count == 1 ? decoded[0] : nil)
        }
    }
}

final class PortableReceiptRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [GenerationReceipt] = []

    func record(_ receipt: GenerationReceipt) {
        lock.lock()
        storage.append(receipt)
        lock.unlock()
    }

    var receipts: [GenerationReceipt] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private final class PortableMessageRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    func record(_ message: String) {
        lock.lock()
        storage.append(message)
        lock.unlock()
    }

    var messages: [String] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private final class PortableExecutionProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var continuations: [UUID: AsyncThrowingStream<WireEvent, any Error>.Continuation] = [:]
    private var orderStorage: [UUID] = []
    private var activeStorage = 0
    private var peakStorage = 0
    private var terminatedStorage = 0

    func stream(for id: UUID) -> AsyncThrowingStream<WireEvent, any Error> {
        let pair = AsyncThrowingStream<WireEvent, any Error>.makeStream()
        lock.lock()
        continuations[id] = pair.continuation
        orderStorage.append(id)
        activeStorage += 1
        peakStorage = max(peakStorage, activeStorage)
        lock.unlock()
        pair.continuation.onTermination = { [weak self] _ in self?.terminated(id) }
        pair.continuation.yield(.responseAppend(
            entryID: "fixed-entry",
            text: "fixed-delta",
            segmentID: "fixed-segment",
            tokenCount: 1
        ))
        return pair.stream
    }

    func finish(_ id: UUID) {
        lock.lock()
        let continuation = continuations[id]
        lock.unlock()
        continuation?.yield(.usage(inputTokens: 1, outputTokens: 1))
        continuation?.yield(.finished(.complete))
        continuation?.finish()
    }

    private func terminated(_ id: UUID) {
        lock.lock()
        if continuations.removeValue(forKey: id) != nil {
            activeStorage -= 1
            terminatedStorage += 1
        }
        lock.unlock()
    }

    var snapshot: (order: [UUID], active: Int, peak: Int, terminated: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (orderStorage, activeStorage, peakStorage, terminatedStorage)
    }
}

private struct PortableImmediateFilling: SlotFilling {
    let modelID = "fixed-model"
    let displayName = "Fixed Model"
    let capabilities = ["text"]

    func prewarm() async throws {}

    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, any Error> {
        AsyncThrowingStream { continuation in
            continuation.yield(.responseAppend(
                entryID: "fixed-entry",
                text: "fixed-delta",
                segmentID: "fixed-segment",
                tokenCount: 1
            ))
            continuation.yield(.usage(inputTokens: 2, outputTokens: 1))
            continuation.yield(.finished(.complete))
            continuation.finish()
        }
    }
}

private struct PortableControlledFilling: SlotFilling {
    let modelID = "fixed-model"
    let displayName = "Fixed Model"
    let capabilities = ["text"]
    let probe: PortableExecutionProbe
    var maximumConcurrentGenerations: Int { 1 }

    func prewarm() async throws {}

    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, any Error> {
        probe.stream(for: request.id)
    }
}

func portableRequest(_ id: UUID = UUID()) -> WireGenerationRequest {
    WireGenerationRequest(id: id, portableTranscript: WireTranscript())
}

func portableHost(
    filling: any SlotFilling,
    registry: SessionRegistry,
    admission: SlotAdmission? = nil
) -> SessionHost {
    SessionHost(
        filling: filling,
        registry: registry,
        admission: admission,
        helloAck: { version in
            HelloAck(
                version: version,
                cluster: "fixed-cluster",
                models: [ModelDescriptor(
                    id: filling.modelID,
                    displayName: filling.displayName,
                    capabilities: filling.capabilities
                )]
            )
        },
        sessionOpened: { "session \($0) opened from \($1)" },
        info: { _ in },
        error: { _ in }
    )
}

func portableEventually(
    _ predicate: @escaping @Sendable () async -> Bool
) async -> Bool {
    for _ in 0 ..< 5_000 {
        if await predicate() { return true }
        try? await Task.sleep(for: .milliseconds(1))
    }
    return false
}

func portableOpenSession(
    on host: SessionHost,
    expectedCapabilities: [String] = ["text"]
) async throws -> (UUID, String) {
    let stream = PortableMemoryStream()
    try stream.yield(Hello(versions: [1, 0], client: "portable-test"))
    try stream.yield(SessionOpen(modelID: "fixed-model"), version: 1)
    stream.finishInput()
    await host.serve(stream)
    let output = try stream.outputFrames()
    #expect(output.map(\.type) == [.helloAck, .sessionOpened])
    let ack = try output[0].decode(HelloAck.self)
    #expect(ack.version == 1)
    #expect(ack.cluster == "fixed-cluster")
    let opened = try output[1].decode(SessionOpened.self)
    #expect(opened.capabilities == expectedCapabilities)
    return (opened.sessionID, opened.token)
}

@Suite(.serialized) struct PortableHostTests {
    @Test func sessionOpenedLogUsesTheInjectedSharedFormatter() async throws {
        let recorder = PortableMessageRecorder()
        let registry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let host = SessionHost(
            filling: PortableImmediateFilling(),
            registry: registry,
            helloAck: { version in
                HelloAck(version: version, cluster: "fixed-cluster", models: [])
            },
            sessionOpened: { "shared-format:\($0):\($1)" },
            info: recorder.record,
            error: recorder.record
        )
        let (sessionID, _) = try await portableOpenSession(on: host)
        #expect(recorder.messages.contains("shared-format:\(sessionID):127.0.0.1:47000"))
        await host.shutdown()
    }

    @Test func missingEXORefusesBeforeALoaderExists() throws {
        let configuration = PortableEXOHostConfiguration(modelID: "fixed-model", exo: nil)
        #expect(throws: PortableEXOConfigurationError.explicitEXORequired) {
            try configuration.makeFilling()
        }
    }

    @Test func explicitEXOConstructsWithoutStartingTheLoader() throws {
        let configuration = PortableEXOHostConfiguration(
            modelID: "fixed-model",
            exo: try EXOConfiguration(endpoint: "http://127.0.0.1:52415")
        )
        let filling = try configuration.makeFilling()
        #expect(filling.modelID == "fixed-model")
        #expect(filling.loaderStartCount == 0)
    }

    @Test func negotiationOpenOrderedEventsAckAndShutdownUseTheSharedHost() async throws {
        let recorder = PortableReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record, replayEventSink: { _ in })
        let admission = SlotAdmission(eventSink: { _ in })
        let host = portableHost(filling: PortableImmediateFilling(), registry: registry, admission: admission)
        let (sessionID, _) = try await portableOpenSession(on: host)
        let genID = UUID()
        let stream = PortableMemoryStream(endpoint: "127.0.0.1:47001")
        try stream.yield(GenerateBegin(
            sessionID: sessionID,
            genID: genID,
            request: portableRequest()
        ))
        let serving = Task { await host.serve(stream) }
        #expect(await portableEventually { stream.outputCount >= 1 })
        try stream.yield(EvAck(seq: 0))
        stream.finishInput()
        await serving.value

        let events = try stream.outputFrames().map { try $0.decode(Ev.self) }
        #expect(events.map(\.seq) == [0, 1, 2])
        #expect(events.map(\.event) == [
            .responseAppend(entryID: "fixed-entry", text: "fixed-delta", segmentID: "fixed-segment", tokenCount: 1),
            .usage(inputTokens: 2, outputTokens: 1),
            .finished(.complete),
        ])
        #expect(stream.didFinishSending)
        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: genID, source: .loopback),
            .terminal(sessionID: sessionID, genID: genID, finalSequence: 2, ending: .complete),
        ])
        let settled = await admission.counters
        #expect(settled.active == 0)
        #expect(settled.waiting == 0)
        #expect(settled.admitted == 1)
        #expect(settled.refused == 0)
        #expect(settled.cancelled == 0)
        #expect(settled.timedOut == 0)

        await host.shutdown()
        #expect(await registry.residentSessions == 0)
        #expect(await registry.replayCounters.currentBytes == 0)
    }

    @Test func disconnectReattachesFromTheExactNextSequenceWithoutDuplicateWork() async throws {
        let recorder = PortableReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record, replayEventSink: { _ in })
        let probe = PortableExecutionProbe()
        let admission = SlotAdmission(eventSink: { _ in })
        let host = portableHost(
            filling: PortableControlledFilling(probe: probe),
            registry: registry,
            admission: admission
        )
        let (sessionID, token) = try await portableOpenSession(on: host)
        let genID = UUID()
        let requestID = UUID()

        let first = PortableMemoryStream(failAfterSends: 1)
        try first.yield(GenerateBegin(
            sessionID: sessionID,
            genID: genID,
            request: portableRequest(requestID)
        ))
        first.finishInput()
        let firstServing = Task { await host.serve(first) }
        #expect(await portableEventually { first.outputCount == 1 })
        probe.finish(requestID)
        await firstServing.value
        let head = try first.outputFrames().map { try $0.decode(Ev.self) }
        #expect(head.map(\.seq) == [0])
        #expect(await portableEventually { probe.snapshot.active == 0 })

        let second = PortableMemoryStream()
        try second.yield(GenerateReattach(
            sessionID: sessionID,
            token: token,
            genID: genID,
            fromSeq: 0
        ))
        second.finishInput()
        await host.serve(second)
        let tail = try second.outputFrames().map { try $0.decode(Ev.self) }
        #expect(tail.map(\.seq) == [1, 2])
        #expect(probe.snapshot.order == [requestID])
        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: genID, source: .loopback),
            .terminal(sessionID: sessionID, genID: genID, finalSequence: 2, ending: .complete),
        ])

        await host.shutdown()
        #expect(await registry.residentSessions == 0)
        #expect(await registry.replayCounters.currentBytes == 0)
    }

    @Test func publicCancelTerminatesWorkAndLeavesExactZeroAccounting() async throws {
        let recorder = PortableReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record, replayEventSink: { _ in })
        let probe = PortableExecutionProbe()
        let admission = SlotAdmission(eventSink: { _ in })
        let host = portableHost(
            filling: PortableControlledFilling(probe: probe),
            registry: registry,
            admission: admission
        )
        let (sessionID, _) = try await portableOpenSession(on: host)
        let genID = UUID()
        let requestID = UUID()
        let stream = PortableMemoryStream()
        try stream.yield(GenerateBegin(
            sessionID: sessionID,
            genID: genID,
            request: portableRequest(requestID)
        ))
        let serving = Task { await host.serve(stream) }
        #expect(await portableEventually { stream.outputCount >= 1 })
        try stream.yield(GenerateCancel(genID: genID))
        stream.finishInput()
        await serving.value

        let events = try stream.outputFrames().map { try $0.decode(Ev.self) }
        #expect(events.map(\.seq) == [0, 1])
        #expect(events.last?.event == .finished(.cancelled))
        #expect(await portableEventually { probe.snapshot.active == 0 })
        #expect(await portableEventually {
            let counters = await admission.counters
            return counters.active == 0 && counters.waiting == 0
        })
        let counters = await admission.counters
        #expect(counters.active == 0)
        #expect(counters.waiting == 0)
        #expect(counters.admitted == 1)
        #expect(counters.refused == 0)
        #expect(counters.cancelled == 1)
        #expect(counters.timedOut == 0)
        #expect(recorder.receipts == [
            .accepted(sessionID: sessionID, genID: genID, source: .loopback),
            .terminal(sessionID: sessionID, genID: genID, finalSequence: 1, ending: .cancelled),
        ])

        await host.shutdown()
        #expect(await registry.residentSessions == 0)
        #expect(await registry.replayCounters.currentBytes == 0)
        #expect(probe.snapshot.active == 0)
    }

    @Test func oneActiveThreeFIFOAndFifthRefusalAreDeterministic() async throws {
        let recorder = PortableReceiptRecorder()
        let registry = SessionRegistry(receiptSink: recorder.record, replayEventSink: { _ in })
        let probe = PortableExecutionProbe()
        let admission = SlotAdmission(eventSink: { _ in })
        let host = portableHost(
            filling: PortableControlledFilling(probe: probe),
            registry: registry,
            admission: admission
        )

        var sessions: [UUID] = []
        for _ in 0 ..< 5 { sessions.append(await registry.openSession().sessionID) }
        let generationIDs = (0 ..< 5).map { _ in UUID() }
        let requestIDs = (0 ..< 5).map { _ in UUID() }
        var streams: [PortableMemoryStream] = []
        var tasks: [Task<Void, Never>] = []

        for index in 0 ..< 4 {
            let stream = PortableMemoryStream(endpoint: "127.0.0.1:\(47100 + index)")
            try stream.yield(GenerateBegin(
                sessionID: sessions[index],
                genID: generationIDs[index],
                request: portableRequest(requestIDs[index])
            ))
            stream.finishInput()
            streams.append(stream)
            tasks.append(Task { await host.serve(stream) })
            #expect(await portableEventually {
                let counters = await admission.counters
                return counters.active == 1 && counters.waiting == index
            })
            if index == 0 {
                #expect(await portableEventually { probe.snapshot.order == [requestIDs[0]] })
            }
        }
        #expect(await portableEventually {
            let counters = await admission.counters
            return counters.active == 1 && counters.waiting == 3
        })

        let refused = PortableMemoryStream(endpoint: "127.0.0.1:47104")
        try refused.yield(GenerateBegin(
            sessionID: sessions[4],
            genID: generationIDs[4],
            request: portableRequest(requestIDs[4])
        ))
        refused.finishInput()
        await host.serve(refused)
        let refusal = try #require(try refused.outputFrames().first?.decode(ErrorFrame.self))
        #expect(refusal.code == "cluster-busy")
        #expect(refusal.message == SlotAdmission.AdmissionError.waitingRoomFull.description)

        for index in 0 ..< 4 {
            probe.finish(requestIDs[index])
            await tasks[index].value
            if index + 1 < 4 {
                let expected = Array(requestIDs[0 ... index + 1])
                #expect(await portableEventually { probe.snapshot.order == expected })
            }
        }

        #expect(await portableEventually {
            let counters = await admission.counters
            return counters.active == 0 && counters.waiting == 0
        })
        let counters = await admission.counters
        #expect(counters.active == 0)
        #expect(counters.waiting == 0)
        #expect(counters.admitted == 4)
        #expect(counters.refused == 1)
        #expect(counters.cancelled == 0)
        #expect(counters.timedOut == 0)
        #expect(probe.snapshot.order == Array(requestIDs.prefix(4)))
        #expect(probe.snapshot.peak == 1)
        #expect(probe.snapshot.active == 0)
        #expect(probe.snapshot.terminated == 4)
        #expect(recorder.receipts.count == 8)
        for stream in streams {
            let events = try stream.outputFrames().map { try $0.decode(Ev.self) }
            #expect(events.map(\.seq) == [0, 1, 2])
            #expect(events.last?.event == .finished(.complete))
        }

        await host.shutdown()
        #expect(await registry.residentSessions == 0)
        #expect(await registry.replayCounters.currentBytes == 0)
    }
}
