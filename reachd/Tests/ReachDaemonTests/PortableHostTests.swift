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
    private let peerCertificate: Data?
    private let failAfterSends: Int?
    private var encodedOutput: [Data] = []
    private var sendingFinished = false
    private var cancelled = false

    init(
        endpoint: String? = "127.0.0.1:47000",
        failAfterSends: Int? = nil,
        peerCertificate: Data? = nil
    ) {
        let pair = AsyncThrowingStream<RawFrame, any Error>.makeStream()
        frames = pair.stream
        input = pair.continuation
        self.endpoint = endpoint
        self.failAfterSends = failAfterSends
        self.peerCertificate = peerCertificate
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

    func peerCertificateDER() -> Data? { peerCertificate }

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

private struct PortableLeasedFrame: Sendable {
    var type: FrameType
    var body: [UInt8]

    init<Frame: WireFrame>(_ frame: Frame) throws {
        type = Frame.frameType
        body = Array(try JSONEncoder().encode(frame))
    }
}

private final class PortableFrameLeaseProbe: @unchecked Sendable {
    typealias Continuation = CheckedContinuation<RawFrame?, Never>

    private let lock = NSLock()
    private let frames: [PortableLeasedFrame]
    private var index = 0
    private var released: Set<Int> = []
    private var waiter: (index: Int, continuation: Continuation)?
    private var requestsStorage = 0
    private var blockedStorage = 0
    private var activeStorage = 0
    private var peakStorage = 0

    init(_ frames: [PortableLeasedFrame]) {
        self.frames = frames
    }

    func next() async -> RawFrame? {
        await withCheckedContinuation { continuation in
            request(continuation)
        }
    }

    private func request(_ continuation: Continuation) {
        var exhausted = false
        let delivery: (Int, PortableLeasedFrame)? = lock.withLock {
            requestsStorage += 1
            guard index < frames.count else {
                exhausted = true
                return nil
            }
            if index > 0, !released.contains(index - 1) {
                precondition(waiter == nil)
                blockedStorage += 1
                waiter = (index, continuation)
                return nil
            }
            let delivery = (index, frames[index])
            index += 1
            activeStorage += 1
            peakStorage = max(peakStorage, activeStorage)
            return delivery
        }
        if let delivery {
            continuation.resume(returning: makeFrame(index: delivery.0, frame: delivery.1))
        } else if exhausted {
            continuation.resume(returning: nil)
        }
    }

    private func makeFrame(index: Int, frame: PortableLeasedFrame) -> RawFrame {
        let pointer = UnsafeMutableRawPointer.allocate(
            byteCount: frame.body.count,
            alignment: MemoryLayout<UInt8>.alignment
        )
        frame.body.withUnsafeBytes { bytes in
            pointer.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
        }
        let body = Data(
            bytesNoCopy: pointer,
            count: frame.body.count,
            deallocator: .custom { [self] pointer, _ in
                pointer.deallocate()
                release(index)
            }
        )
        return RawFrame(type: frame.type, body: body)
    }

    private func release(_ releasedIndex: Int) {
        let delivery: (Continuation, Int, PortableLeasedFrame)? = lock.withLock {
            precondition(released.insert(releasedIndex).inserted)
            activeStorage -= 1
            guard let waiter, waiter.index == releasedIndex + 1 else { return nil }
            self.waiter = nil
            let delivery = (waiter.continuation, index, frames[index])
            index += 1
            activeStorage += 1
            peakStorage = max(peakStorage, activeStorage)
            return delivery
        }
        if let delivery {
            delivery.0.resume(returning: makeFrame(index: delivery.1, frame: delivery.2))
        }
    }

    var snapshot: (requests: Int, blocked: Int, active: Int, peak: Int, released: Int) {
        lock.withLock {
            (requestsStorage, blockedStorage, activeStorage, peakStorage, released.count)
        }
    }
}

private final class PortableLeasedStream: SessionHostStream, @unchecked Sendable {
    let frames: AsyncThrowingStream<RawFrame, any Error>
    let probe: PortableFrameLeaseProbe
    private let lock = NSLock()
    private var encodedOutput: [Data] = []
    private var sendingFinished = false
    private var cancelled = false

    init(_ input: [PortableLeasedFrame]) {
        let probe = PortableFrameLeaseProbe(input)
        self.probe = probe
        frames = AsyncThrowingStream<RawFrame, any Error>(unfolding: {
            await probe.next()
        })
    }

    func send<Frame: WireFrame>(_ frame: Frame, for negotiatedVersion: UInt8) async throws {
        let encoded = try FrameCodec.encode(frame, for: negotiatedVersion)
        lock.withLock { encodedOutput.append(encoded) }
    }

    func finishSending() { lock.withLock { sendingFinished = true } }
    func cancel() { lock.withLock { cancelled = true } }
    func remoteEndpointDescription() -> String? { "127.0.0.1:47999" }

    func outputFrames() throws -> [RawFrame] {
        let snapshot = lock.withLock { encodedOutput }
        return try snapshot.map { data in
            var reassembler = FrameReassembler()
            let decoded = try reassembler.feed(data)
            return try #require(decoded.count == 1 ? decoded[0] : nil)
        }
    }
}

private final class PortableRetainingExtension: HostControlExtension, @unchecked Sendable {
    private let lock = NSLock()
    private var retained: RawFrame?

    func handle(_ frame: RawFrame) async throws -> HostControlAction {
        lock.withLock { retained = frame }
        return .handled
    }

    func release() { lock.withLock { retained = nil } }
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

final class PortableFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = false

    var value: Bool { lock.withLock { storage } }
    func set() { lock.withLock { storage = true } }
}

private final class PortableBlockedTerminationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: AsyncThrowingStream<WireEvent, any Error>.Continuation?
    private var streamTerminationObserved = false
    private var settlementEntered = false
    private var settlementFinished = false
    private var releaseSettlement = false
    private var settlementWaiter: CheckedContinuation<Void, Never>?

    func stream() -> AsyncThrowingStream<WireEvent, any Error> {
        let pair = AsyncThrowingStream<WireEvent, any Error>.makeStream()
        lock.withLock { continuation = pair.continuation }
        pair.continuation.onTermination = { [weak self] _ in
            guard let self else { return }
            lock.withLock {
                continuation = nil
                streamTerminationObserved = true
            }
        }
        pair.continuation.yield(.responseAppend(
            entryID: "fixed-entry",
            text: "fixed-delta",
            segmentID: "fixed-segment",
            tokenCount: 1
        ))
        return pair.stream
    }

    func settleTask() async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock {
                settlementEntered = true
                if releaseSettlement { return true }
                settlementWaiter = continuation
                return false
            }
            if resumeNow { continuation.resume() }
        }
        lock.withLock { settlementFinished = true }
    }

    func allowTermination() {
        let waiter = lock.withLock { () -> CheckedContinuation<Void, Never>? in
            releaseSettlement = true
            let result = settlementWaiter
            settlementWaiter = nil
            return result
        }
        waiter?.resume()
    }

    var snapshot: (entered: Bool, finished: Bool, streamTerminated: Bool) {
        lock.withLock { (settlementEntered, settlementFinished, streamTerminationObserved) }
    }
}

private final class PortableShutdownFillingProbe: @unchecked Sendable {
    struct Snapshot: Sendable {
        var activeChildren: Int
        var streamTerminations: Int
        var shutdownCalls: Int
        var shutdownReturned: Bool
    }

    private let lock = NSLock()
    private var continuation: AsyncThrowingStream<WireEvent, any Error>.Continuation?
    private var activeChildren = 0
    private var streamTerminations = 0
    private var shutdownCalls = 0
    private var shutdownReturned = false
    private var releaseShutdown = false
    private var shutdownWaiters: [CheckedContinuation<Void, Never>] = []

    func stream() -> AsyncThrowingStream<WireEvent, any Error> {
        let pair = AsyncThrowingStream<WireEvent, any Error>.makeStream()
        lock.withLock {
            continuation = pair.continuation
            activeChildren += 1
        }
        pair.continuation.onTermination = { [weak self] _ in
            guard let self else { return }
            lock.withLock { streamTerminations += 1 }
        }
        pair.continuation.yield(.responseAppend(
            entryID: "fixed-entry",
            text: "fixed-delta",
            segmentID: "fixed-segment",
            tokenCount: 1
        ))
        return pair.stream
    }

    func shutDown() async {
        let stream = lock.withLock { () -> AsyncThrowingStream<WireEvent, any Error>.Continuation? in
            shutdownCalls += 1
            return continuation
        }
        stream?.finish()
        await withCheckedContinuation { waiter in
            let resumeNow = lock.withLock {
                if releaseShutdown { return true }
                shutdownWaiters.append(waiter)
                return false
            }
            if resumeNow { waiter.resume() }
        }
        lock.withLock {
            continuation = nil
            activeChildren = 0
            shutdownReturned = true
        }
    }

    func allowShutdown() {
        let waiters = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            releaseShutdown = true
            let result = shutdownWaiters
            shutdownWaiters.removeAll()
            return result
        }
        waiters.forEach { $0.resume() }
    }

    var snapshot: Snapshot {
        lock.withLock {
            .init(
                activeChildren: activeChildren,
                streamTerminations: streamTerminations,
                shutdownCalls: shutdownCalls,
                shutdownReturned: shutdownReturned
            )
        }
    }
}

private struct PortableShutdownFilling: SlotFilling {
    let modelID = "fixed-model"
    let displayName = "Fixed Model"
    let capabilities = ["text"]
    let probe: PortableShutdownFillingProbe

    func prewarm() async throws {}
    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, any Error> {
        probe.stream()
    }
    func shutdown() async { await probe.shutDown() }
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
    @Test func registryShutdownJoinsSweptOwnershipAndConcurrentCallers() async throws {
        let probe = PortableBlockedTerminationProbe()
        let registry = SessionRegistry(
            receiptSink: { _ in },
            replayEventSink: { _ in },
            generationTaskSettlement: probe.settleTask
        )
        let session = await registry.openSession()
        let begun = try await registry.begin(
            sessionID: session.sessionID,
            genID: UUID(),
            events: probe.stream
        )
        _ = begun.stream
        #expect(await portableEventually {
            let active = await registry.activeGenerationTasks
            let replay = await registry.replayCounters
            return active == 1 && replay.currentBytes > 0
        })

        let firstReturned = PortableFlag()
        let secondReturned = PortableFlag()
        let first = Task {
            await registry.shutdown()
            firstReturned.set()
        }
        #expect(await portableEventually { probe.snapshot.entered })
        let second = Task {
            await registry.shutdown()
            secondReturned.set()
        }
        for _ in 0 ..< 100 { await Task.yield() }

        #expect(!firstReturned.value)
        #expect(!secondReturned.value)
        #expect(await registry.activeGenerationTasks == 1)
        #expect(await registry.residentSessions == 0)
        #expect(await registry.replayCounters.currentBytes == 0)
        do {
            _ = try await registry.openSessionIfAccepting()
            Issue.record("registry accepted a session after shutdown began")
        } catch {
            #expect(error as? SessionRegistry.RegistryError == .shuttingDown)
        }
        do {
            _ = try await registry.begin(
                sessionID: session.sessionID,
                genID: UUID(),
                events: probe.stream
            )
            Issue.record("registry accepted generation work after shutdown began")
        } catch {
            #expect(error as? SessionRegistry.RegistryError == .shuttingDown)
        }

        probe.allowTermination()
        await first.value
        await second.value
        #expect(firstReturned.value)
        #expect(secondReturned.value)
        #expect(probe.snapshot.finished)
        #expect(probe.snapshot.streamTerminated)
        #expect(await registry.activeGenerationTasks == 0)
        await registry.shutdown()
        #expect(await registry.activeGenerationTasks == 0)
    }

    @Test func hostShutdownOrdersAdmissionRegistryAndProviderAndIsIdempotent() async throws {
        let registry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let admission = SlotAdmission(eventSink: { _ in })
        let probe = PortableShutdownFillingProbe()
        let filling = PortableShutdownFilling(probe: probe)
        let host = portableHost(filling: filling, registry: registry, admission: admission)
        let session = await registry.openSession()
        let begun = try await registry.begin(
            sessionID: session.sessionID,
            genID: UUID(),
            receiptSource: .loopback,
            admission: admission,
            events: { filling.generate(portableRequest()) }
        )
        _ = begun.stream
        #expect(await portableEventually {
            let counters = await admission.counters
            return counters.active == 1 && probe.snapshot.activeChildren == 1
        })

        let firstReturned = PortableFlag()
        let secondReturned = PortableFlag()
        let first = Task {
            await host.shutdown()
            firstReturned.set()
        }
        #expect(await portableEventually { probe.snapshot.shutdownCalls == 1 })
        let second = Task {
            await host.shutdown()
            secondReturned.set()
        }
        for _ in 0 ..< 100 { await Task.yield() }

        let held = probe.snapshot
        #expect(held.shutdownCalls == 1)
        #expect(held.activeChildren == 1)
        #expect(!held.shutdownReturned)
        #expect(!firstReturned.value)
        #expect(!secondReturned.value)
        #expect(await registry.activeGenerationTasks == 0)
        #expect(await registry.residentSessions == 0)
        let counters = await admission.counters
        #expect(counters.active == 0)
        #expect(counters.waiting == 0)

        probe.allowShutdown()
        await first.value
        await second.value
        await host.shutdown()
        let settled = probe.snapshot
        #expect(settled.shutdownCalls == 1)
        #expect(settled.shutdownReturned)
        #expect(settled.activeChildren == 0)
        #expect(settled.streamTerminations == 1)
        #expect(firstReturned.value)
        #expect(secondReturned.value)
    }

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

    @Test func peerLeafFingerprintIsTheFirstHostObservation() async throws {
        let recorder = PortableMessageRecorder()
        let registry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let host = SessionHost(
            filling: PortableImmediateFilling(),
            registry: registry,
            helloAck: { version in
                HelloAck(version: version, cluster: "fixed-cluster", models: [])
            },
            sessionOpened: { "session \($0) opened from \($1)" },
            info: recorder.record,
            error: recorder.record
        )
        let stream = PortableMemoryStream(peerCertificate: Data([1, 2, 3]))
        try stream.yield(Hello(versions: [1], client: "fingerprint-test"))
        try stream.yield(SessionOpen(modelID: "fixed-model"), version: 1)
        stream.finishInput()

        await host.serve(stream)

        #expect(recorder.messages.first == "authenticated peer leaf sha256 039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81")
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

    @Test func ordinaryOpeningControlAndPumpFramesReleaseBeforeNextIteratorRequest() async throws {
        let controlRegistry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let controlHost = portableHost(filling: PortableImmediateFilling(), registry: controlRegistry)
        let control = PortableLeasedStream(try [
            PortableLeasedFrame(Hello(versions: [1], client: "lease-test")),
            PortableLeasedFrame(SessionOpen(modelID: "fixed-model")),
            PortableLeasedFrame(Ping(nonce: 91)),
        ])
        await controlHost.serve(control)
        #expect(try control.outputFrames().map(\.type) == [.helloAck, .sessionOpened, .pong])
        #expect(control.probe.snapshot.requests == 4)
        #expect(control.probe.snapshot.blocked == 0)
        #expect(control.probe.snapshot.active == 0)
        #expect(control.probe.snapshot.peak == 1)
        #expect(control.probe.snapshot.released == 3)
        await controlHost.shutdown()

        let generationProbe = PortableExecutionProbe()
        let generationRegistry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let admission = SlotAdmission(eventSink: { _ in })
        let generationHost = portableHost(
            filling: PortableControlledFilling(probe: generationProbe),
            registry: generationRegistry,
            admission: admission
        )
        let sessionID = await generationRegistry.openSession().sessionID
        let genID = UUID()
        let requestID = UUID()
        let generation = PortableLeasedStream(try [
            PortableLeasedFrame(GenerateBegin(
                sessionID: sessionID,
                genID: genID,
                request: portableRequest(requestID)
            )),
            PortableLeasedFrame(EvAck(seq: 0)),
            PortableLeasedFrame(GenerateCancel(genID: genID)),
        ])
        await generationHost.serve(generation)
        #expect(generation.probe.snapshot.requests == 4)
        #expect(generation.probe.snapshot.blocked == 0)
        #expect(generation.probe.snapshot.active == 0)
        #expect(generation.probe.snapshot.peak == 1)
        #expect(generation.probe.snapshot.released == 3)
        #expect(await portableEventually { generationProbe.snapshot.active == 0 })
        #expect(await admission.counters.active == 0)
        await generationHost.shutdown()
    }

    @Test func deliberatelyRetainedExtensionFrameBackpressuresWithoutAllocatingTheNextFrame() async throws {
        let retainedExtension = PortableRetainingExtension()
        let registry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let filling = PortableImmediateFilling()
        let host = SessionHost(
            filling: filling,
            registry: registry,
            helloAck: { version in
                HelloAck(version: version, cluster: "fixed-cluster", models: [])
            },
            sessionOpened: { "session \($0) opened from \($1)" },
            info: { _ in },
            error: { _ in },
            controlExtension: { _ in retainedExtension }
        )
        let stream = PortableLeasedStream(try [
            PortableLeasedFrame(Hello(versions: [1], client: "retaining-test")),
            PortableLeasedFrame(ErrorFrame(
                code: "retained-extension-frame",
                message: String(repeating: "x", count: 1_024)
            )),
            PortableLeasedFrame(Ping(nonce: 92)),
        ])
        let serving = Task { await host.serve(stream) }

        #expect(await portableEventually { stream.probe.snapshot.blocked == 1 })
        let held = stream.probe.snapshot
        #expect(held.requests == 3)
        #expect(held.active == 1)
        #expect(held.peak == 1)
        #expect(held.released == 1)
        #expect(try stream.outputFrames().map(\.type) == [.helloAck])

        retainedExtension.release()
        await serving.value
        #expect(try stream.outputFrames().map(\.type) == [.helloAck, .pong])
        #expect(stream.probe.snapshot.requests == 4)
        #expect(stream.probe.snapshot.blocked == 1)
        #expect(stream.probe.snapshot.active == 0)
        #expect(stream.probe.snapshot.peak == 1)
        #expect(stream.probe.snapshot.released == 3)
        await host.shutdown()
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
