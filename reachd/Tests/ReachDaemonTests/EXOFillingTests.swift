import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import ReachWire
import Testing
@testable import ReachHost

private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = false

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func set() {
        lock.lock()
        stored = true
        lock.unlock()
    }
}

private final class ManualEXOClock: EXOClock, @unchecked Sendable {
    private struct Waiter {
        var deadline: Int64
        var continuation: CheckedContinuation<Void, any Error>
    }

    private let lock = NSLock()
    private var value: Int64
    private var waiters: [UUID: Waiter] = [:]

    init(_ value: Int64 = 0) {
        self.value = value
    }

    func now() async -> Int64 {
        currentValue()
    }

    private func currentValue() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func sleep(until deadline: Int64) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                register(id: id, deadline: deadline, continuation: continuation)
            }
        } onCancel: {
            self.cancel(id)
        }
    }

    private func register(
        id: UUID,
        deadline: Int64,
        continuation: CheckedContinuation<Void, any Error>
    ) {
        lock.lock()
        if Task.isCancelled {
            lock.unlock()
            continuation.resume(throwing: CancellationError())
        } else if value >= deadline {
            lock.unlock()
            continuation.resume()
        } else {
            waiters[id] = Waiter(deadline: deadline, continuation: continuation)
            lock.unlock()
        }
    }

    func advance(to newValue: Int64) {
        let ready: [CheckedContinuation<Void, any Error>]
        lock.lock()
        precondition(newValue >= value)
        value = newValue
        let ids = waiters.compactMap { key, waiter in
            waiter.deadline <= newValue ? key : nil
        }
        ready = ids.compactMap { waiters.removeValue(forKey: $0)?.continuation }
        lock.unlock()
        ready.forEach { $0.resume() }
    }

    private func cancel(_ id: UUID) {
        lock.lock()
        let continuation = waiters.removeValue(forKey: id)?.continuation
        lock.unlock()
        continuation?.resume(throwing: CancellationError())
    }
}

private final class FakeEXOHTTPTask: EXOHTTPTasking, @unchecked Sendable {
    private let lock = NSLock()
    private var queue: [EXOHTTPEvent] = []
    private var terminalError: (any Error)?
    private var eventWaiter: CheckedContinuation<EXOHTTPEvent?, any Error>?
    private var terminated = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var cancellationCallsValue = 0

    var cancellationCalls: Int {
        lock.lock()
        defer { lock.unlock() }
        return cancellationCallsValue
    }

    func send(_ event: EXOHTTPEvent) {
        let receiver: CheckedContinuation<EXOHTTPEvent?, any Error>?
        lock.lock()
        guard !terminated else {
            lock.unlock()
            return
        }
        if queue.isEmpty, let eventWaiter {
            receiver = eventWaiter
            self.eventWaiter = nil
        } else {
            queue.append(event)
            receiver = nil
        }
        lock.unlock()
        receiver?.resume(returning: event)
    }

    func complete() {
        send(.complete)
        terminate()
    }

    func fail(_ error: any Error) {
        terminate(error)
    }

    func cancel() {
        lock.lock()
        cancellationCallsValue += 1
        lock.unlock()
        terminate(CancellationError())
    }

    func nextEvent() async throws -> EXOHTTPEvent? {
        try await withCheckedThrowingContinuation { continuation in
            let event: EXOHTTPEvent?
            let error: (any Error)?
            lock.lock()
            if !queue.isEmpty {
                event = queue.removeFirst()
                error = nil
            } else if terminated {
                event = nil
                error = terminalError
            } else {
                precondition(eventWaiter == nil)
                eventWaiter = continuation
                lock.unlock()
                return
            }
            lock.unlock()
            if let event { continuation.resume(returning: event) }
            else if let error { continuation.resume(throwing: error) }
            else { continuation.resume(returning: nil) }
        }
    }

    func waitForTermination() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if terminated {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    private func terminate(_ error: (any Error)? = nil) {
        let resumed: [CheckedContinuation<Void, Never>]
        let eventReceiver: CheckedContinuation<EXOHTTPEvent?, any Error>?
        lock.lock()
        guard !terminated else {
            lock.unlock()
            return
        }
        terminated = true
        terminalError = error
        eventReceiver = queue.isEmpty ? eventWaiter : nil
        if eventReceiver != nil { eventWaiter = nil }
        resumed = waiters
        waiters.removeAll()
        lock.unlock()
        if let error { eventReceiver?.resume(throwing: error) }
        else { eventReceiver?.resume(returning: nil) }
        resumed.forEach { $0.resume() }
    }
}

private final class FakeEXOLoader: EXOHTTPLoading, @unchecked Sendable {
    let operation: FakeEXOHTTPTask
    private let lock = NSLock()
    private var requestsValue: [URLRequest] = []

    init(operation: FakeEXOHTTPTask = FakeEXOHTTPTask()) {
        self.operation = operation
    }

    var startCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return requestsValue.count
    }

    var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requestsValue
    }

    func start(_ request: URLRequest) -> any EXOHTTPTasking {
        lock.lock()
        requestsValue.append(request)
        lock.unlock()
        return operation
    }
}

private final class FixedEXOLoader: EXOHTTPLoading, @unchecked Sendable {
    let operation: any EXOHTTPTasking
    private let lock = NSLock()
    private var starts = 0

    init(operation: any EXOHTTPTasking) {
        self.operation = operation
    }

    var startCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return starts
    }

    func start(_ request: URLRequest) -> any EXOHTTPTasking {
        lock.lock()
        starts += 1
        lock.unlock()
        return operation
    }
}

private struct CollectedEXOStream: Sendable {
    var events: [WireEvent]
    var error: EXOFillingError?
    var cancelled: Bool
}

private func collectEXOStream(
    _ stream: AsyncThrowingStream<WireEvent, any Error>
) async -> CollectedEXOStream {
    var events: [WireEvent] = []
    do {
        for try await event in stream { events.append(event) }
        return .init(events: events, error: nil, cancelled: false)
    } catch let error as EXOFillingError {
        return .init(events: events, error: error, cancelled: false)
    } catch is CancellationError {
        return .init(events: events, error: nil, cancelled: true)
    } catch {
        Issue.record("unexpected stream error: \(error)")
        return .init(events: events, error: nil, cancelled: false)
    }
}

private func eventually(
    _ label: String,
    _ predicate: () -> Bool
) async {
    for _ in 0 ..< 20_000 {
        if predicate() { return }
        await Task.yield()
    }
    Issue.record("timed out yielding for \(label)")
}

private func eventuallyAsync(
    _ label: String,
    _ predicate: () async -> Bool
) async {
    for _ in 0 ..< 20_000 {
        if await predicate() { return }
        await Task.yield()
    }
    Issue.record("timed out yielding for \(label)")
}

private final class EXOChallengeSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
    func cancel(_ challenge: URLAuthenticationChallenge) {}
    func performDefaultHandling(for challenge: URLAuthenticationChallenge) {}
    func rejectProtectionSpaceAndContinue(with challenge: URLAuthenticationChallenge) {}
}

@Suite struct EXOFillingTests {
    private static let modelID = "model-a"

    /// Literal EXO 0.3.70 ModelList/ModelCard shape. Reach intentionally reads
    /// only object, data and id; retaining every frozen field here prevents a
    /// convenient invented mini-catalog from becoming the contract fixture.
    private static let catalogFixture = #"""
    {
      "object": "list",
      "data": [
        {
          "id": "other-model",
          "object": "model",
          "created": 1720000000,
          "owned_by": "exo",
          "hugging_face_id": "example/other-model",
          "name": "Other Model",
          "description": "another catalog member",
          "context_length": 32768,
          "tags": ["text-generation"],
          "storage_size_megabytes": 1024,
          "supports_tensor": true,
          "tasks": ["text-generation"],
          "is_custom": false,
          "family": "other",
          "quantization": "4bit",
          "base_model": null,
          "capabilities": [],
          "reasoning_dialect": null
        },
        {
          "id": "model-a",
          "object": "model",
          "created": 1720000001,
          "owned_by": "exo",
          "hugging_face_id": "example/model-a",
          "name": "Model A",
          "description": "configured catalog member",
          "context_length": 131072,
          "tags": ["text-generation"],
          "storage_size_megabytes": 2048,
          "supports_tensor": true,
          "tasks": ["text-generation"],
          "is_custom": false,
          "family": "model-a",
          "quantization": null,
          "base_model": "example/base",
          "capabilities": ["chat"],
          "reasoning_dialect": "none"
        }
      ]
    }
    """#

    /// Literal one-choice EXO 0.3.70 stream shape: accumulated usage is on
    /// the terminal one-choice object, followed by the optional statistics
    /// comment and one [DONE] event.
    private static let streamFixture = #"""
    : prefill statistics

    data: {"id":"cmd-1","object":"chat.completion.chunk","created":1720000000,"model":"model-a","choices":[{"index":0,"delta":{"content":"Hé"},"finish_reason":null}]}

    data: {"id":"cmd-1","object":"chat.completion.chunk","created":1720000001,"model":"model-a","choices":[{"index":0,"delta":{"content":" moon"},"finish_reason":null}]}

    data: {"id":"cmd-1","object":"chat.completion.chunk","created":1720000002,"model":"model-a","choices":[{"index":0,"delta":{"content":"!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}

    : generation statistics

    data: [DONE]

    """# + "\n"

    private static func request(
        entries: [WireTranscript.Entry]? = nil,
        tools: [WireToolDefinition] = [],
        schema: WireGenerationSchema? = nil,
        options: WireGenerationOptions = .init(),
        context: WireContextOptions = .init()
    ) -> WireGenerationRequest {
        let defaultEntries: [WireTranscript.Entry] = [
            .instructions(.init(
                id: "instructions",
                segments: [.text(.init(id: "is", content: "Be exact."))],
                toolDefinitions: []
            )),
            .prompt(.init(
                id: "prompt",
                segments: [.text(.init(id: "ps", content: "Hello"))]
            )),
            .response(.init(
                id: "response",
                assetIDs: [],
                segments: [.text(.init(id: "rs", content: "Earlier"))]
            )),
        ]
        return WireGenerationRequest(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            portableTranscript: WireTranscript(entries: entries ?? defaultEntries),
            tools: tools,
            portableSchema: schema,
            options: options,
            context: context
        )
    }

    private static func wireDecoded(
        _ request: WireGenerationRequest
    ) throws -> WireGenerationRequest {
        let begin = GenerateBegin(
            sessionID: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            genID: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
            request: request
        )
        var reassembler = FrameReassembler()
        let frames = try reassembler.feed(FrameCodec.encode(begin))
        let frame = try #require(frames.first)
        #expect(frames.count == 1)
        return try frame.decode(GenerateBegin.self).request
    }

    private static func filling(
        loader: FakeEXOLoader,
        clock: ManualEXOClock = ManualEXOClock(),
        probe: EXOOperationTestProbe? = nil
    ) throws -> EXOFilling {
        try EXOFilling(
            modelID: modelID,
            endpoint: "http://127.0.0.1:52415",
            loader: loader,
            clock: clock,
            testProbe: probe
        )
    }

    private func capturedError(_ body: () throws -> Void) -> EXOFillingError? {
        do {
            try body()
            return nil
        } catch let error as EXOFillingError {
            return error
        } catch {
            Issue.record("unexpected error: \(error)")
            return nil
        }
    }

    private static func parse(
        _ data: Data,
        chunks: [Range<Data.Index>]? = nil
    ) throws -> ([WireEvent], EXOTerminalResult) {
        var parser = EXOSSEParser(modelID: modelID)
        var events: [WireEvent] = []
        if let chunks {
            for range in chunks { events += try parser.feed(Data(data[range])) }
        } else {
            events += try parser.feed(data)
        }
        return (events, try parser.finish())
    }

    private static func object(
        content: Any = "",
        finish: Any = NSNull(),
        id: String = "cmd-1",
        model: String = modelID,
        index: Any = 0,
        usage: Any? = nil,
        choiceAdditions: [String: Any] = [:],
        deltaAdditions: [String: Any] = [:],
        rootAdditions: [String: Any] = [:]
    ) throws -> String {
        var delta: [String: Any] = ["content": content]
        deltaAdditions.forEach { delta[$0.key] = $0.value }
        var choice: [String: Any] = [
            "index": index,
            "delta": delta,
            "finish_reason": finish,
        ]
        choiceAdditions.forEach { choice[$0.key] = $0.value }
        var root: [String: Any] = [
            "id": id,
            "model": model,
            "choices": [choice],
        ]
        if let usage { root["usage"] = usage }
        rootAdditions.forEach { root[$0.key] = $0.value }
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private static func event(_ payload: String, newline: String = "\n") -> String {
        "data: \(payload)\(newline)\(newline)"
    }

    private static func terminal(
        finish: String = "stop",
        usage: Any? = ["prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7]
    ) throws -> String {
        try object(content: "", finish: finish, usage: usage)
    }

    private static func validClose(
        first: String? = nil,
        finish: String = "stop",
        usage: Any? = ["prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7],
        newline: String = "\n"
    ) throws -> Data {
        var text = ""
        if let first { text += event(first, newline: newline) }
        text += event(try terminal(finish: finish, usage: usage), newline: newline)
        text += event("[DONE]", newline: newline)
        return Data(text.utf8)
    }

    private static func largeValidStream() throws -> Data {
        let content = String(repeating: "x", count: 200 * 1024)
        var text = ""
        for _ in 0 ..< 6 {
            text += event(try object(content: content))
        }
        text += event(try terminal())
        text += event("[DONE]")
        return Data(text.utf8)
    }

    private static func catalogObject() throws -> [String: Any] {
        try #require(
            JSONSerialization.jsonObject(with: Data(catalogFixture.utf8)) as? [String: Any]
        )
    }

    private static func catalogData(_ mutate: (inout [String: Any]) -> Void) throws -> Data {
        var object = try catalogObject()
        mutate(&object)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private static func expectQuiescent(_ snapshot: EXOOperationSnapshot) {
        #expect(snapshot.survivorCount == 0)
        #expect(snapshot.outcomes == 1)
        #expect(snapshot.terminalEmissions == 1)
        for (kind, count) in snapshot.started {
            #expect(snapshot.terminated[kind] == count)
            #expect((snapshot.cancelled[kind] ?? 0) <= count)
        }
    }

    private static func response(
        status: Int = 200,
        contentType: String? = "text/event-stream"
    ) -> EXOHTTPEvent {
        var headers: [String: String] = [:]
        if let contentType { headers["Content-Type"] = contentType }
        return .response(.init(statusCode: status, headers: headers))
    }

    private static func prewarmResult(_ filling: EXOFilling) async -> (EXOFillingError?, Bool) {
        do {
            try await filling.prewarm()
            return (nil, false)
        } catch let error as EXOFillingError {
            return (error, false)
        } catch is CancellationError {
            return (nil, true)
        } catch {
            Issue.record("unexpected prewarm error: \(error)")
            return (nil, false)
        }
    }

    private static func runCatalog(
        clock: ManualEXOClock = ManualEXOClock(),
        deliver: (FakeEXOHTTPTask) -> Void
    ) async throws -> (
        result: (EXOFillingError?, Bool),
        snapshot: EXOOperationSnapshot,
        loader: FakeEXOLoader
    ) {
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try Self.filling(loader: loader, clock: clock, probe: probe)
        let task = Task { await Self.prewarmResult(filling) }
        await eventually("catalog loader start") { loader.startCount == 1 }
        deliver(loader.operation)
        let result = await task.value
        let snapshot = await probe.waitForQuiescence()
        return (result, snapshot, loader)
    }

    private static func runGeneration(
        clock: ManualEXOClock = ManualEXOClock(),
        request: WireGenerationRequest = Self.request(),
        deliver: (FakeEXOHTTPTask) -> Void
    ) async throws -> (
        result: CollectedEXOStream,
        snapshot: EXOOperationSnapshot,
        loader: FakeEXOLoader
    ) {
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try Self.filling(loader: loader, clock: clock, probe: probe)
        let task = Task { await collectEXOStream(filling.generate(request)) }
        await eventually("generation loader start") { loader.startCount == 1 }
        deliver(loader.operation)
        let result = await task.value
        let snapshot = await probe.waitForQuiescence()
        return (result, snapshot, loader)
    }

    private static func feedSuccessfulGeneration(_ operation: FakeEXOHTTPTask) {
        operation.send(Self.response())
        let data = Data(Self.streamFixture.utf8)
        var offset = 0
        while offset < data.count {
            let end = min(offset + 7, data.count)
            operation.send(.bytes(Data(data[offset ..< end])))
            offset = end
        }
        operation.complete()
    }

    private static func keepGenerationAlive(
        clock: ManualEXOClock,
        operation: FakeEXOHTTPTask,
        probe: EXOOperationTestProbe,
        through target: Int64
    ) async {
        var now: Int64 = 0
        var idleResets = 1
        while now + 59 * EXOLimits.second <= target {
            now += 59 * EXOLimits.second
            clock.advance(to: now)
            operation.send(.bytes(Data(": keepalive\n\n".utf8)))
            idleResets += 1
            let expected = idleResets
            await eventually("idle reset \(expected)") {
                probe.snapshot().idleDeadlineResets >= expected
            }
        }
        if now < target { clock.advance(to: target) }
    }

    @Test func identityEndpointGrammarAndRequestPathsAreExact() throws {
        for endpoint in ["http://127.0.0.1:1", "http://127.0.0.1:65535", "http://[::1]:52415"] {
            let value = try EXOEndpoint(endpoint)
            #expect(value.rawValue == endpoint)
            #expect(value.url(path: "/v1/models").absoluteString == endpoint + "/v1/models")
        }
        let rejected = [
            "", "https://127.0.0.1:1", "http://localhost:1", "http://0.0.0.0:1",
            "http://127.0.0.1", "http://127.0.0.1:", "http://127.0.0.1:0",
            "http://127.0.0.1:65536", "http://127.0.0.1:01", "http://127.0.0.1:+1",
            "http://127.0.0.1: 1", "http://127.0.0.1:1/", "http://127.0.0.1:1/path",
            "http://user@127.0.0.1:1", "http://127.0.0.1:1?q", "http://127.0.0.1:1#f",
            "http://127%2e0%2e0%2e1:1", "http://127.1:1", "http://2130706433:1",
            "http://[0:0:0:0:0:0:0:1]:1", "http://[::ffff:127.0.0.1]:1",
            "http://[::1%25lo0]:1", "http://[::1]:01", "http://[::1]:1/",
        ]
        for endpoint in rejected {
            #expect(capturedError { _ = try EXOEndpoint(endpoint) } == .invalidEndpoint)
        }

        let loader = FakeEXOLoader()
        let filling = try Self.filling(loader: loader)
        #expect(filling.modelID == Self.modelID)
        #expect(filling.displayName == "model-a (EXO)")
        #expect(filling.capabilities.isEmpty)
        #expect(filling.maximumConcurrentGenerations == 1)
        #expect(filling.catalogRequest().url?.absoluteString == "http://127.0.0.1:52415/v1/models")
        #expect(filling.catalogRequest().httpMethod == "GET")
        #expect(try filling.generationRequest(Self.request()).url?.absoluteString == "http://127.0.0.1:52415/v1/chat/completions")
    }

    @Test func productionConstructionIsLockedAndTestLoaderIsNotInstalled() throws {
        let production = try EXOFilling(modelID: Self.modelID, endpoint: "http://127.0.0.1:52415")
        let configuration = try #require(production.productionConfiguration)
        #expect(configuration.identifier == nil)
        #expect(configuration.connectionProxyDictionary?.isEmpty == true)
        #expect(configuration.urlCredentialStorage == nil)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.httpShouldSetCookies == false)
        #expect(configuration.urlCache == nil)
        #expect(configuration.requestCachePolicy == .reloadIgnoringLocalCacheData)
        #expect(configuration.protocolClasses == nil)
        #expect(production.loader is EXOURLSessionLoader)

        let injected = try Self.filling(loader: FakeEXOLoader())
        #expect(injected.productionConfiguration == nil)
        #expect(injected.productionDelegate == nil)
        #expect(!(production.loader is FakeEXOLoader))
    }

    @Test func boundedTransportRefusesSaturationAndParserHandoffBackpressuresInOrder() async throws {
        let bytes = Data((0 ..< 11).map { UInt8($0) })

        let transport = EXOURLSessionOperation(
            bufferedEvents: 2,
            maximumBufferedBytes: 8,
            fragmentBytes: 4
        )
        #expect(transport.send(.bytes(Data(bytes.prefix(8)))))
        #expect(!transport.send(.bytes(Data(bytes.suffix(3)))))
        var transportBytes = Data()
        var transportError: EXOFillingError?
        do {
            while let event = try await transport.nextEvent() {
                if case .bytes(let fragment) = event { transportBytes.append(fragment) }
            }
        } catch let error as EXOFillingError {
            transportError = error
        } catch {
            Issue.record("unexpected transport saturation error: \(error)")
        }
        #expect(transportBytes == Data(bytes.prefix(8)))
        #expect(transportError == .responseLimit("transport event buffer"))
        let transportSnapshot = transport.bufferSnapshot
        #expect(transportSnapshot.peakBufferedEvents == 2)
        #expect(transportSnapshot.peakBufferedBytes == 8)
        #expect(transportSnapshot.enqueuedEvents == 2)
        #expect(transportSnapshot.overflowRefusals == 1)
        #expect(transportSnapshot.cancellationSignals == 1)
        #expect(transportSnapshot.streamFinished)
        #expect(!transportSnapshot.taskTerminated)

        let waiterReturned = LockedFlag()
        let waiter = Task {
            await transport.waitForTermination()
            waiterReturned.set()
        }
        for _ in 0 ..< 100 { await Task.yield() }
        #expect(!waiterReturned.value)
        transport.taskDidComplete(CancellationError())
        await waiter.value
        #expect(waiterReturned.value)
        #expect(transport.bufferSnapshot.taskTerminated)
        transport.cancel()
        #expect(transport.bufferSnapshot.cancellationSignals == 1)

        let pipe = EXOBoundedBodyPipe(bufferedFragments: 2, fragmentBytes: 4)
        let producerReturned = LockedFlag()
        let producer = Task {
            for byte in bytes {
                guard await pipe.send(Data([byte])) else { return false }
            }
            await pipe.finish()
            producerReturned.set()
            return true
        }
        await eventuallyAsync("parser handoff reaches fixed capacity") {
            await pipe.snapshot.sendWaits == 1
        }
        let saturated = await pipe.snapshot
        #expect(saturated.bufferedFragments == 2)
        #expect(saturated.bufferedBytes == 8)
        #expect(saturated.peakBufferedFragments == 2)
        #expect(saturated.peakBufferedBytes == 8)
        #expect(saturated.acceptedFragments == 2)
        #expect(!producerReturned.value)

        var orderedBytes = Data()
        while let fragment = await pipe.next() { orderedBytes.append(fragment) }
        let producerAccepted = await producer.value
        #expect(producerAccepted)
        #expect(producerReturned.value)
        #expect(orderedBytes == bytes)
        let drained = await pipe.snapshot
        #expect(drained.bufferedFragments == 0)
        #expect(drained.bufferedBytes == 0)
        #expect(drained.peakBufferedFragments == 2)
        #expect(drained.peakBufferedBytes == 8)
        #expect(drained.sendWaits == 1)
    }

    @Test func validGenerationIsEquivalentAllAtOnceAndHighlyFragmented() async throws {
        let data = Data(Self.streamFixture.utf8)
        let allAtOnce = try await Self.runGeneration { operation in
            operation.send(Self.response())
            operation.send(.bytes(data))
            operation.complete()
        }
        let fragmented = try await Self.runGeneration { operation in
            operation.send(Self.response())
            for byte in data { operation.send(.bytes(Data([byte]))) }
            operation.complete()
        }
        #expect(allAtOnce.result.events == fragmented.result.events)
        #expect(allAtOnce.result.error == nil)
        #expect(fragmented.result.error == nil)
        #expect(allAtOnce.result.cancelled == fragmented.result.cancelled)
        #expect(allAtOnce.snapshot.outcome == "success")
        #expect(fragmented.snapshot.outcome == "success")
        Self.expectQuiescent(allAtOnce.snapshot)
        Self.expectQuiescent(fragmented.snapshot)

        func drain(
            _ operation: EXOURLSessionOperation
        ) async throws -> (controls: [EXOHTTPEvent], bytes: Data) {
            var controls: [EXOHTTPEvent] = []
            var bytes = Data()
            while let event = try await operation.nextEvent() {
                if case .bytes(let fragment) = event { bytes.append(fragment) }
                else { controls.append(event) }
            }
            return (controls, bytes)
        }

        let coalescedTransport = EXOURLSessionOperation()
        #expect(coalescedTransport.send(Self.response()))
        #expect(coalescedTransport.send(.bytes(data)))
        #expect(coalescedTransport.send(.complete))
        coalescedTransport.taskDidComplete()

        let fragmentedTransport = EXOURLSessionOperation()
        #expect(fragmentedTransport.send(Self.response()))
        for byte in data { #expect(fragmentedTransport.send(.bytes(Data([byte])))) }
        #expect(fragmentedTransport.send(.complete))
        fragmentedTransport.taskDidComplete()

        let coalescedDelivery = try await drain(coalescedTransport)
        let fragmentedDelivery = try await drain(fragmentedTransport)
        #expect(coalescedDelivery.controls == fragmentedDelivery.controls)
        #expect(coalescedDelivery.bytes == data)
        #expect(fragmentedDelivery.bytes == data)
        #expect(coalescedTransport.bufferSnapshot.enqueuedEvents
            == fragmentedTransport.bufferSnapshot.enqueuedEvents)
        #expect(fragmentedTransport.bufferSnapshot.peakBufferedBytes <= data.count)
        #expect(fragmentedTransport.bufferSnapshot.peakBufferedEvents
            <= EXOLimits.transportBufferedEvents)

        let largeData = try Self.largeValidStream()
        #expect(largeData.count > (
            EXOLimits.parserBufferedFragments * EXOLimits.handoffFragmentBytes
        ))
        let largeAllAtOnce = try await Self.runGeneration { operation in
            operation.send(Self.response())
            operation.send(.bytes(largeData))
            operation.complete()
        }
        let largeFragmented = try await Self.runGeneration { operation in
            operation.send(Self.response())
            var offset = 0
            while offset < largeData.count {
                let end = min(offset + 1_024, largeData.count)
                operation.send(.bytes(Data(largeData[offset ..< end])))
                offset = end
            }
            operation.complete()
        }
        #expect(largeAllAtOnce.result.events == largeFragmented.result.events)
        #expect(largeAllAtOnce.result.error == nil)
        #expect(largeFragmented.result.error == nil)
        #expect(largeAllAtOnce.snapshot.outcome == "success")
        #expect(largeFragmented.snapshot.outcome == "success")
        Self.expectQuiescent(largeAllAtOnce.snapshot)
        Self.expectQuiescent(largeFragmented.snapshot)
    }

    @Test func transportOverflowRemainsTypedUntilDelayedTaskTermination() async throws {
        let operation = EXOURLSessionOperation(bufferedEvents: 3, fragmentBytes: 4)
        #expect(operation.send(Self.response()))
        #expect(!operation.send(.bytes(Data(repeating: 0x3A, count: 12))))
        #expect(operation.bufferSnapshot.streamFinished)
        #expect(!operation.bufferSnapshot.taskTerminated)

        let loader = FixedEXOLoader(operation: operation)
        let probe = EXOOperationTestProbe()
        let cancellation = EXOCancellationRegistry()
        let coordinator = EXOOperationCoordinator(
            mode: .generation(modelID: Self.modelID),
            loader: loader,
            clock: ManualEXOClock(),
            cancellation: cancellation,
            probe: probe,
            emit: { _ in true }
        )
        cancellation.setWake { Task { await coordinator.consumerCancelled() } }
        probe.started(.settlement)
        let task = Task {
            let outcome = await coordinator.run(request: URLRequest(
                url: URL(string: "http://127.0.0.1:52415/v1/chat/completions")!
            ))
            probe.record(outcome: outcome.label)
            probe.terminalEmitted()
            probe.terminated(.settlement)
            probe.settled()
            return outcome
        }
        await eventually("overflow loader start") { loader.startCount == 1 }
        await eventuallyAsync("typed overflow before URL acknowledgement") {
            await coordinator.ownershipSnapshot().outcome == "failure"
        }
        #expect(!operation.bufferSnapshot.taskTerminated)
        #expect(probe.snapshot().terminated[.urlTask] == nil)
        #expect(probe.snapshot().survivorCount > 0)

        operation.taskDidComplete(CancellationError())
        let outcome = await task.value
        if case .failure(let error) = outcome {
            #expect(error == .responseLimit("transport event buffer"))
        } else {
            Issue.record("transport overflow did not remain a typed failure")
        }
        let snapshot = await probe.waitForQuiescence()
        #expect(operation.bufferSnapshot.taskTerminated)
        #expect(operation.bufferSnapshot.cancellationSignals == 1)
        #expect(snapshot.terminated[.urlTask] == 1)
        Self.expectQuiescent(snapshot)
    }

    @Test func delegateRefusesRedirectAndBothAuthenticationChallengePaths() async throws {
        let delegate = EXOSessionDelegate()
        let session = URLSession(configuration: .ephemeral)
        let task = session.dataTask(with: URL(string: "http://127.0.0.1:52415/v1/models")!)
        let operation = EXOURLSessionOperation()
        operation.attach(task)
        delegate.register(operation, for: task)

        let redirect = HTTPURLResponse(
            url: task.originalRequest!.url!,
            statusCode: 307,
            httpVersion: "HTTP/1.1",
            headerFields: ["Location": "http://127.0.0.1:52416/v1/models"]
        )!
        var followed: URLRequest? = URLRequest(url: redirect.url!)
        delegate.urlSession(
            session,
            task: task,
            willPerformHTTPRedirection: redirect,
            newRequest: URLRequest(url: URL(string: "http://127.0.0.1:52416/v1/models")!)
        ) { followed = $0 }
        #expect(followed == nil)
        #expect(try await operation.nextEvent() == .redirect(307))

        let challenge = URLAuthenticationChallenge(
            protectionSpace: URLProtectionSpace(
                host: "127.0.0.1",
                port: 52415,
                protocol: "http",
                realm: "EXO",
                authenticationMethod: NSURLAuthenticationMethodHTTPBasic
            ),
            proposedCredential: nil,
            previousFailureCount: 0,
            failureResponse: nil,
            error: nil,
            sender: EXOChallengeSender()
        )
        var sessionDisposition: URLSession.AuthChallengeDisposition?
        delegate.urlSession(session, didReceive: challenge) { disposition, credential in
            sessionDisposition = disposition
            #expect(credential == nil)
        }
        #expect(sessionDisposition == .cancelAuthenticationChallenge)

        var taskDisposition: URLSession.AuthChallengeDisposition?
        delegate.urlSession(session, task: task, didReceive: challenge) { disposition, credential in
            taskDisposition = disposition
            #expect(credential == nil)
        }
        #expect(taskDisposition == .cancelAuthenticationChallenge)
        #expect(try await operation.nextEvent() == .authenticationChallenge)
        task.cancel()
    }

    @Test func requestBytesMatchTheFrozenPlainTextShape() throws {
        let request = Self.request(options: .init(
            temperature: 0.5,
            maximumResponseTokens: 42,
            sampling: .topK(40, seed: 7),
            toolCalling: .allowed
        ))
        let body = try EXORequestEncoder.encode(request, modelID: Self.modelID)
        let expected = #"{"enable_thinking":false,"max_tokens":42,"messages":[{"content":"Be exact.","role":"system"},{"content":"Hello","role":"user"},{"content":"Earlier","role":"assistant"}],"model":"model-a","n":1,"seed":7,"stream":true,"stream_options":{"include_usage":true},"temperature":0.5,"top_k":40}"#
        #expect(body == Data(expected.utf8))

        let loader = FakeEXOLoader()
        let filling = try Self.filling(loader: loader)
        let encoded = try filling.generationRequest(request)
        #expect(encoded.httpMethod == "POST")
        #expect(encoded.value(forHTTPHeaderField: "Content-Type") == "application/json")
        #expect(encoded.value(forHTTPHeaderField: "Accept") == "text/event-stream")
        #expect(encoded.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(encoded.httpBody == body)
        #expect(loader.startCount == 0)
    }

    @Test func requestOptionsAndBoundsAcceptOnlyTheNamedNumericDomain() throws {
        let defaults = try EXORequestEncoder.encode(Self.request(), modelID: Self.modelID)
        #expect(String(decoding: defaults, as: UTF8.self).contains(#""max_tokens":512"#))

        for options in [
            WireGenerationOptions(maximumResponseTokens: 1),
            WireGenerationOptions(maximumResponseTokens: 16_384),
            WireGenerationOptions(sampling: .topK(1, seed: 0)),
            WireGenerationOptions(sampling: .topK(100_000, seed: UInt64.max)),
            WireGenerationOptions(sampling: .topP(Double.leastNonzeroMagnitude, seed: 1)),
            WireGenerationOptions(sampling: .topP(1, seed: nil)),
            WireGenerationOptions(temperature: 0, sampling: .greedy),
            WireGenerationOptions(toolCalling: .disallowed),
        ] {
            #expect(capturedError {
                _ = try EXORequestEncoder.encode(Self.request(options: options), modelID: Self.modelID)
            } == nil)
        }

        let invalid: [(WireGenerationOptions, EXOFillingError)] = [
            (.init(maximumResponseTokens: 0), .invalidNumericOption("maximum response tokens")),
            (.init(maximumResponseTokens: 16_385), .invalidNumericOption("maximum response tokens")),
            (.init(temperature: .infinity), .invalidNumericOption("temperature")),
            (.init(temperature: .nan), .invalidNumericOption("temperature")),
            (.init(sampling: .topK(0, seed: nil)), .invalidNumericOption("top-k")),
            (.init(sampling: .topK(100_001, seed: nil)), .invalidNumericOption("top-k")),
            (.init(sampling: .topP(0, seed: nil)), .invalidNumericOption("top-p")),
            (.init(sampling: .topP(1.0001, seed: nil)), .invalidNumericOption("top-p")),
            (.init(sampling: .topP(.infinity, seed: nil)), .invalidNumericOption("top-p")),
            (.init(temperature: 0.1, sampling: .greedy), .invalidNumericOption("greedy temperature")),
        ]
        for (options, expected) in invalid {
            #expect(capturedError {
                _ = try EXORequestEncoder.encode(Self.request(options: options), modelID: Self.modelID)
            } == expected)
        }

        let maxMessage = String(repeating: "a", count: EXOLimits.messageBytes)
        let exact = Self.request(entries: [.prompt(.init(segments: [.text(.init(content: maxMessage))]))])
        #expect(capturedError { _ = try EXORequestEncoder.encode(exact, modelID: Self.modelID) } == nil)
        let oversized = Self.request(entries: [.prompt(.init(segments: [.text(.init(content: maxMessage + "a"))]))])
        #expect(capturedError { _ = try EXORequestEncoder.encode(oversized, modelID: Self.modelID) } == .requestLimit("message UTF-8 bytes"))

        let small = WireTranscript.Entry.prompt(WireTranscript.Prompt(segments: [.text(.init(content: "x"))]))
        #expect(capturedError {
            _ = try EXORequestEncoder.encode(Self.request(entries: Array(repeating: small, count: 256)), modelID: Self.modelID)
        } == nil)
        #expect(capturedError {
            _ = try EXORequestEncoder.encode(Self.request(entries: Array(repeating: small, count: 257)), modelID: Self.modelID)
        } == .requestLimit("transcript message count"))

        let quarter = String(repeating: "x", count: EXOLimits.messageBytes)
        let bodyLimitEntries = (0 ..< 4).map { _ in
            WireTranscript.Entry.prompt(WireTranscript.Prompt(segments: [.text(.init(content: quarter))]))
        }
        let loader = FakeEXOLoader()
        let filling = try Self.filling(loader: loader)
        #expect(capturedError {
            _ = try filling.generationRequest(Self.request(entries: bodyLimitEntries))
        } == .requestLimit("encoded request body"))
    }

    @Test func unsupportedShapesFailBeforeTheLoaderStarts() async throws {
        let schema = try WireGenerationSchema(jsonValue: .object([
            "additionalProperties": .bool(false),
            "properties": .object([:]),
            "required": .array([]),
            "title": .string("Unsupported"),
            "type": .string("object"),
            "x-order": .array([]),
        ]))
        let tool = WireToolDefinition(name: "lookup", description: "lookup", portableParameters: schema)
        let toolCall = WireTranscript.Entry.toolCalls(.init(calls: [
            .init(id: "call-1", name: "lookup", argumentsJSON: "{}"),
        ]))
        let toolOutput = WireTranscript.Entry.toolOutput(.init(
            id: "call-1",
            toolName: "lookup",
            segments: [.text(.init(content: "answer"))]
        ))
        let structured = WireTranscript.Entry.prompt(.init(segments: [
            .structure(.init(source: "object", content: .object([:]))),
        ]))
        let reasoning = WireTranscript.Entry.reasoning(.init(segments: [.text(.init(content: "hidden"))]))
        let cases: [WireGenerationRequest] = [
            Self.request(tools: [tool]),
            Self.request(schema: schema),
            Self.request(context: .init(includeSchemaInPrompt: true)),
            Self.request(context: .init(reasoning: .moderate)),
            Self.request(options: .init(toolCalling: .required)),
            Self.request(entries: [toolCall]),
            Self.request(entries: [toolOutput]),
            Self.request(entries: [structured]),
            Self.request(entries: [reasoning]),
        ]
        for request in cases {
            let loader = FakeEXOLoader()
            let filling = try Self.filling(loader: loader)
            let result = await collectEXOStream(filling.generate(request))
            #expect(result.error != nil)
            #expect(loader.startCount == 0)
        }
    }

    @Test func nestedToolsAndResponseAssetsFailAfterWireDecodeBeforeLoaderStarts() async throws {
        let schema = try WireGenerationSchema(jsonValue: .object([
            "additionalProperties": .bool(false),
            "properties": .object([:]),
            "required": .array([]),
            "title": .string("Unsupported"),
            "type": .string("object"),
            "x-order": .array([]),
        ]))
        let transcriptTool = WireTranscript.ToolDefinition(
            name: "lookup",
            description: "Looks a thing up.",
            parameters: schema
        )
        let instructionsRequest = try Self.wireDecoded(Self.request(entries: [
            .instructions(.init(
                id: "instructions-with-tool",
                segments: [.text(.init(content: "Be exact."))],
                toolDefinitions: [transcriptTool]
            )),
        ]))
        let assetRequest = try Self.wireDecoded(Self.request(entries: [
            .response(.init(
                id: "response-with-asset",
                assetIDs: ["asset-1"],
                segments: [.text(.init(content: "Earlier"))]
            )),
        ]))

        let cases: [(WireGenerationRequest, EXOFillingError)] = [
            (instructionsRequest, .unsupportedRequest("instruction tool definitions")),
            (assetRequest, .unsupportedRequest("response assets")),
        ]
        for (request, expected) in cases {
            let loader = FakeEXOLoader()
            let filling = try Self.filling(loader: loader)
            let result = await collectEXOStream(filling.generate(request))
            #expect(result.events.isEmpty)
            #expect(result.error == expected)
            #expect(!result.cancelled)
            #expect(loader.startCount == 0)
            #expect(loader.requests.isEmpty)
            #expect(filling.loaderStartCount == 0)
        }
    }

    @Test func catalogFixtureProvesMembershipAndEveryStructuralRefusal() throws {
        let fixture = Data(Self.catalogFixture.utf8)
        try EXOCatalogParser.validate(fixture, modelID: Self.modelID)
        try EXOCatalogParser.validate(fixture, modelID: "other-model")
        #expect(capturedError {
            try EXOCatalogParser.validate(fixture, modelID: "absent")
        } == .modelUnavailable("absent"))

        let duplicate = try Self.catalogData { root in
            var records = root["data"] as! [[String: Any]]
            records.append(records[1])
            root["data"] = records
        }
        #expect(capturedError {
            try EXOCatalogParser.validate(duplicate, modelID: Self.modelID)
        } == .protocolContradiction("duplicate model id in catalog"))

        let malformedRoots: [Data] = [
            Data("[]".utf8),
            try Self.catalogData { $0.removeValue(forKey: "object") },
            try Self.catalogData { $0["object"] = "model" },
            try Self.catalogData { $0.removeValue(forKey: "data") },
            try Self.catalogData { $0["data"] = "not-an-array" },
            try Self.catalogData { $0["data"] = ["not-an-object"] },
            try Self.catalogData { root in
                var records = root["data"] as! [[String: Any]]
                records[0].removeValue(forKey: "id")
                root["data"] = records
            },
            try Self.catalogData { root in
                var records = root["data"] as! [[String: Any]]
                records[0]["id"] = ""
                root["data"] = records
            },
            try Self.catalogData { root in
                var records = root["data"] as! [[String: Any]]
                records[0]["id"] = 7
                root["data"] = records
            },
            Data("{\"object\":\"list\",\"data\":[".utf8),
            Data([0xFF]),
        ]
        for data in malformedRoots {
            let error = capturedError { try EXOCatalogParser.validate(data, modelID: Self.modelID) }
            #expect(error != nil)
        }
        #expect(capturedError {
            try EXOCatalogParser.validate(
                Data(repeating: 0x20, count: EXOLimits.catalogBytes + 1),
                modelID: Self.modelID
            )
        } == .responseLimit("model catalog bytes"))
    }

    @Test func mediaTypesAreExactWithOneOptionalCharset() {
        #expect(EXOMediaType.matches("application/json", expected: "application/json"))
        #expect(EXOMediaType.matches("Application/JSON; charset=utf-8", expected: "application/json"))
        #expect(EXOMediaType.matches(" text/event-stream ; charset=UTF-8 ", expected: "text/event-stream"))
        for value in [nil, "", "text/plain", "application/json;", "application/json; boundary=x", "application/json; charset=utf-8; x=y"] as [String?] {
            #expect(!EXOMediaType.matches(value, expected: "application/json"))
        }
    }

    @Test func frozenStreamParsesAcrossEveryByteAndAcrossCRLF() throws {
        let data = Data(Self.streamFixture.utf8)
        let byteRanges = data.indices.map { $0 ..< data.index(after: $0) }
        let (events, terminal) = try Self.parse(data, chunks: byteRanges)
        #expect(events == [
            .responseAppend(entryID: nil, text: "Hé", segmentID: nil, tokenCount: 1),
            .responseAppend(entryID: nil, text: " moon", segmentID: nil, tokenCount: 1),
            .responseAppend(entryID: nil, text: "!", segmentID: nil, tokenCount: 1),
        ])
        #expect(terminal == .init(usage: .init(inputTokens: 3, outputTokens: 4)))

        let first = try Self.object(content: "🌙", finish: NSNull())
        let crlf = try Self.validClose(first: first, finish: "length", usage: nil, newline: "\r\n")
        let (crlfEvents, crlfTerminal) = try Self.parse(crlf)
        #expect(crlfEvents == [.responseAppend(entryID: nil, text: "🌙", segmentID: nil, tokenCount: 1)])
        #expect(crlfTerminal.usage == nil)
    }

    @Test func streamTerminalOrderingAndUsageAreExhaustive() throws {
        for finish in ["stop", "length"] {
            let (_, terminal) = try Self.parse(try Self.validClose(finish: finish))
            #expect(terminal.usage == .init(inputTokens: 3, outputTokens: 4))
        }
        let (_, noUsage) = try Self.parse(try Self.validClose(usage: nil))
        #expect(noUsage.usage == nil)

        let doneEarly = Data(Self.event("[DONE]").utf8)
        let terminalOnly = Data(Self.event(try Self.terminal()).utf8)
        let terminalThenJSON = Data((Self.event(try Self.terminal()) + Self.event(try Self.object())).utf8)
        let usageOnly = #"{"id":"cmd-1","model":"model-a","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}"#
        let invalidStreams = [
            doneEarly,
            terminalOnly,
            terminalThenJSON,
            Data((Self.event(usageOnly) + Self.event("[DONE]")).utf8),
            Data((Self.event(try Self.terminal()) + Self.event("[DONE]") + "x").utf8),
            Data((Self.event(try Self.terminal()) + "data: [DONE]\n").utf8),
        ]
        for data in invalidStreams {
            #expect(capturedError { _ = try Self.parse(data) } != nil)
        }

        var parser = EXOSSEParser(modelID: Self.modelID)
        _ = try parser.feed(try Self.validClose())
        #expect(capturedError { _ = try parser.feed(Data("\n".utf8)) } == .malformedStream("bytes followed [DONE]"))
    }

    @Test func streamRejectsEveryChoiceIdentityAndUnsupportedPayloadArm() throws {
        let malformedPayloads: [String] = [
            "not-json",
            "[]",
            #"{"id":"cmd-1","model":"model-a","choices":[]}"#,
            #"{"id":"cmd-1","model":"model-a","choices":[{},{}]}"#,
            try Self.object(id: ""),
            try Self.object(model: "other"),
            try Self.object(index: 1),
            try Self.object(index: 0.5),
            try Self.object(index: true),
            try Self.object(content: 7),
            try Self.object(choiceAdditions: ["usage": ["x": 1]]),
            try Self.object(deltaAdditions: ["reasoning": "hidden"]),
            try Self.object(deltaAdditions: ["reasoning_content": "hidden"]),
            try Self.object(choiceAdditions: ["reasoning": "hidden"]),
            try Self.object(deltaAdditions: ["tool_calls": [["id": "call"]]]),
            try Self.object(deltaAdditions: ["function_call": ["name": "f"]]),
            try Self.object(choiceAdditions: ["tool_calls": [["id": "call"]]]),
            try Self.object(choiceAdditions: ["function_call": ["name": "f"]]),
            try Self.object(usage: ["prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2]),
            #"{"error":{"message":"upstream failed"}}"#,
        ]
        for payload in malformedPayloads {
            let data = Data((Self.event(payload) + Self.event(try Self.terminal()) + Self.event("[DONE]")).utf8)
            #expect(capturedError { _ = try Self.parse(data) } != nil)
        }

        let first = Self.event(try Self.object(content: "a"))
        for changed in [
            try Self.object(content: "b", id: "cmd-2"),
            try Self.object(content: "b", model: "other"),
        ] {
            let data = Data((first + Self.event(changed) + Self.event(try Self.terminal()) + Self.event("[DONE]")).utf8)
            #expect(capturedError { _ = try Self.parse(data) } != nil)
        }
    }

    @Test func streamRejectsEveryFinishAndUsageContradiction() throws {
        for finish in ["content_filter", "error", "tool_calls", "function_call", "future"] {
            let data = Data((Self.event(try Self.terminal(finish: finish)) + Self.event("[DONE]")).utf8)
            #expect(capturedError { _ = try Self.parse(data) } != nil)
        }
        let malformedUsage: [Any] = [
            [:],
            ["prompt_tokens": -1, "completion_tokens": 1, "total_tokens": 0],
            ["prompt_tokens": 1.5, "completion_tokens": 1, "total_tokens": 2],
            ["prompt_tokens": true, "completion_tokens": 1, "total_tokens": 2],
            ["prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 3],
            ["prompt_tokens": 1, "completion_tokens": 1, "total_tokens": "2"],
        ]
        for usage in malformedUsage {
            let data = Data((Self.event(try Self.terminal(usage: usage)) + Self.event("[DONE]")).utf8)
            #expect(capturedError { _ = try Self.parse(data) } != nil)
        }
    }

    @Test func usageNumberClassificationPreservesExactIntegerCategories() {
        #expect(EXONumber.integer(NSNumber(value: Int8(1))) == 1)
        #expect(EXONumber.integer(NSNumber(value: UInt8.max)) == Int(UInt8.max))
        #expect(EXONumber.integer(NSNumber(value: Int.max)) == Int.max)
        #expect(EXONumber.integer(NSNumber(value: UInt64(Int.max))) == Int.max)

        #expect(EXONumber.integer(NSNumber(value: true)) == nil)
        #expect(EXONumber.integer(NSNumber(value: -1)) == nil)
        #expect(EXONumber.integer(NSNumber(value: UInt64(Int.max) + 1)) == nil)
        #expect(EXONumber.integer(NSNumber(value: UInt64.max)) == nil)
        #expect(EXONumber.integer(NSNumber(value: Float(1))) == nil)
        #expect(EXONumber.integer(NSNumber(value: Double(1))) == nil)
        #expect(EXONumber.integer(NSNumber(value: Double.nan)) == nil)
        #expect(EXONumber.integer(NSNumber(value: Double.infinity)) == nil)
    }

    @Test func streamSyntaxAndIncrementalBoundsFailClosed() throws {
        let syntaxFailures = [
            "event: message\n\n",
            "data: {}\ndata: {}\n\n",
            "data: {}\rX\n\n",
            "data: \u{FFFD}\n\n",
        ]
        for text in syntaxFailures {
            #expect(capturedError { _ = try Self.parse(Data(text.utf8)) } != nil)
        }
        var invalidUTF8 = Data("data: ".utf8)
        invalidUTF8.append(0xFF)
        invalidUTF8.append(contentsOf: [0x0A, 0x0A])
        #expect(capturedError { _ = try Self.parse(invalidUTF8) } != nil)

        var lineParser = EXOSSEParser(modelID: Self.modelID)
        #expect(capturedError {
            _ = try lineParser.feed(Data(repeating: 0x61, count: EXOLimits.lineBytes + 1))
        } == .responseLimit("SSE line bytes"))

        var eventParser = EXOSSEParser(modelID: Self.modelID)
        let comment = Data((":" + String(repeating: "x", count: 200_000) + "\n").utf8)
        _ = try eventParser.feed(comment)
        _ = try eventParser.feed(comment)
        #expect(capturedError { _ = try eventParser.feed(comment) } == .responseLimit("SSE event bytes"))

        var countParser = EXOSSEParser(modelID: Self.modelID)
        let empty = Data(Self.event(try Self.object()).utf8)
        for _ in 0 ..< EXOLimits.eventCount { _ = try countParser.feed(empty) }
        #expect(capturedError { _ = try countParser.feed(empty) } == .responseLimit("SSE event count"))

        var commentParser = EXOSSEParser(modelID: Self.modelID)
        let inertComment = Data(": inert\n\n".utf8)
        for _ in 0 ... EXOLimits.eventCount { _ = try commentParser.feed(inertComment) }
        _ = try commentParser.feed(try Self.validClose())
        #expect(try commentParser.finish().usage == .init(inputTokens: 3, outputTokens: 4))
    }

    @Test func catalogAndGenerationTraverseTheOneHTTPTaskAndSettleCleanly() async throws {
        let catalog = try await Self.runCatalog { operation in
            operation.send(Self.response(contentType: "application/json; charset=utf-8"))
            let fixture = Data(Self.catalogFixture.utf8)
            operation.send(.bytes(Data(fixture.prefix(fixture.count / 2))))
            operation.send(.bytes(Data(fixture.dropFirst(fixture.count / 2))))
            operation.complete()
        }
        #expect(catalog.result.0 == nil)
        #expect(!catalog.result.1)
        #expect(catalog.loader.startCount == 1)
        #expect(catalog.loader.requests[0].httpMethod == "GET")
        #expect(catalog.loader.requests[0].url?.absoluteString == "http://127.0.0.1:52415/v1/models")
        #expect(catalog.loader.requests[0].value(forHTTPHeaderField: "Authorization") == nil)
        #expect(catalog.loader.operation.cancellationCalls == 0)
        #expect(catalog.snapshot.outcome == "success")
        Self.expectQuiescent(catalog.snapshot)

        let generation = try await Self.runGeneration { operation in
            Self.feedSuccessfulGeneration(operation)
        }
        #expect(generation.result.error == nil)
        #expect(generation.result.events == [
            .responseAppend(entryID: nil, text: "Hé", segmentID: nil, tokenCount: 1),
            .responseAppend(entryID: nil, text: " moon", segmentID: nil, tokenCount: 1),
            .responseAppend(entryID: nil, text: "!", segmentID: nil, tokenCount: 1),
            .usage(inputTokens: 3, outputTokens: 4),
            .finished(.complete),
        ])
        #expect(generation.loader.startCount == 1)
        #expect(generation.loader.requests[0].httpMethod == "POST")
        #expect(generation.loader.operation.cancellationCalls == 0)
        #expect(generation.snapshot.outcome == "success")
        Self.expectQuiescent(generation.snapshot)
    }

    @Test func catalogHTTPStatusMediaBodyAndTransportFailuresAreFiniteAndQuiescent() async throws {
        let status = try await Self.runCatalog { operation in
            operation.send(Self.response(status: 503, contentType: nil))
            operation.send(.bytes(Data("  temporarily\n unavailable  ".utf8)))
            operation.complete()
        }
        #expect(status.result.0 == .httpStatus(503, "temporarily unavailable"))
        Self.expectQuiescent(status.snapshot)

        let media = try await Self.runCatalog { operation in
            operation.send(Self.response(contentType: "text/plain"))
        }
        #expect(media.result.0 == .contentType(expected: "application/json", actual: "text/plain"))
        #expect(media.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(media.snapshot)

        let malformed = try await Self.runCatalog { operation in
            operation.send(Self.response(contentType: "application/json"))
            operation.send(.bytes(Data("{\"object\":\"list\"".utf8)))
            operation.complete()
        }
        if case .malformedCatalog = malformed.result.0 {} else {
            Issue.record("expected malformed catalog, got \(String(describing: malformed.result.0))")
        }
        Self.expectQuiescent(malformed.snapshot)

        let oversized = try await Self.runCatalog { operation in
            operation.send(Self.response(contentType: "application/json"))
            operation.send(.bytes(Data(repeating: 0x20, count: EXOLimits.catalogBytes + 1)))
        }
        #expect(oversized.result.0 == .responseLimit("model catalog bytes"))
        #expect(oversized.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(oversized.snapshot)

        let errorOversized = try await Self.runCatalog { operation in
            operation.send(Self.response(status: 500, contentType: nil))
            operation.send(.bytes(Data(repeating: 0x78, count: EXOLimits.errorBodyBytes + 1)))
        }
        #expect(errorOversized.result.0 == .responseLimit("non-200 error body bytes"))
        #expect(errorOversized.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(errorOversized.snapshot)

        let transport = try await Self.runCatalog { operation in
            operation.fail(URLError(.cannotConnectToHost))
        }
        if case .transport = transport.result.0 {} else {
            Issue.record("expected transport error, got \(String(describing: transport.result.0))")
        }
        Self.expectQuiescent(transport.snapshot)
    }

    @Test func generationHTTPContradictionsRedirectsChallengesAndLimitsSettle() async throws {
        let status = try await Self.runGeneration { operation in
            operation.send(Self.response(status: 429, contentType: nil))
            operation.send(.bytes(Data("slow down".utf8)))
            operation.complete()
        }
        #expect(status.result.error == .httpStatus(429, "slow down"))
        Self.expectQuiescent(status.snapshot)

        let media = try await Self.runGeneration { operation in
            operation.send(Self.response(contentType: "application/json"))
        }
        #expect(media.result.error == .contentType(expected: "text/event-stream", actual: "application/json"))
        #expect(media.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(media.snapshot)

        let redirect = try await Self.runGeneration { $0.send(.redirect(308)) }
        #expect(redirect.result.error == .redirect(308))
        #expect(redirect.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(redirect.snapshot)

        let challenge = try await Self.runGeneration { $0.send(.authenticationChallenge) }
        #expect(challenge.result.error == .authenticationChallenge)
        #expect(challenge.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(challenge.snapshot)

        let bodyFirst = try await Self.runGeneration { $0.send(.bytes(Data("x".utf8))) }
        #expect(bodyFirst.result.error == .protocolContradiction("body bytes arrived before accepted headers"))
        Self.expectQuiescent(bodyFirst.snapshot)

        let duplicateHeaders = try await Self.runGeneration { operation in
            operation.send(Self.response())
            operation.send(Self.response())
        }
        #expect(duplicateHeaders.result.error == .protocolContradiction("duplicate HTTP response headers"))
        Self.expectQuiescent(duplicateHeaders.snapshot)

        let noHeaders = try await Self.runGeneration { $0.complete() }
        #expect(noHeaders.result.error == .transport("request ended before HTTP response headers"))
        Self.expectQuiescent(noHeaders.snapshot)

        let malformed = try await Self.runGeneration { operation in
            operation.send(Self.response())
            operation.send(.bytes(Data("unknown: field\n\n".utf8)))
        }
        if case .malformedStream = malformed.result.error {} else {
            Issue.record("expected malformed stream, got \(String(describing: malformed.result.error))")
        }
        #expect(malformed.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(malformed.snapshot)

        let validPrefix = Self.event(try Self.object(content: "visible"))
        let invalidSuffix = "unknown: field\n\n"
        let coalesced = try await Self.runGeneration { operation in
            operation.send(Self.response())
            operation.send(.bytes(Data((validPrefix + invalidSuffix).utf8)))
        }
        let split = try await Self.runGeneration { operation in
            operation.send(Self.response())
            operation.send(.bytes(Data(validPrefix.utf8)))
            operation.send(.bytes(Data(invalidSuffix.utf8)))
        }
        let expectedPrefix: [WireEvent] = [
            .responseAppend(entryID: nil, text: "visible", segmentID: nil, tokenCount: 1),
        ]
        #expect(coalesced.result.events == expectedPrefix)
        #expect(split.result.events == expectedPrefix)
        #expect(coalesced.result.error == split.result.error)
        Self.expectQuiescent(coalesced.snapshot)
        Self.expectQuiescent(split.snapshot)

        let oversized = try await Self.runGeneration { operation in
            operation.send(Self.response())
            let chunk = Data((":" + String(repeating: "x", count: 240_000) + "\n\n").utf8)
            let deliveries = EXOLimits.generationBytes / chunk.count + 2
            for _ in 0 ..< deliveries { operation.send(.bytes(chunk)) }
        }
        #expect(oversized.result.error == .responseLimit("generation bytes"))
        #expect(oversized.loader.operation.cancellationCalls == 1)
        Self.expectQuiescent(oversized.snapshot)
    }

    @Test func catalogDeadlineAcceptsOnlyStrictlyBeforeTenSeconds() async throws {
        for offset: Int64 in [-1, 0, 1] {
            let clock = ManualEXOClock()
            let result = try await Self.runCatalog(clock: clock) { operation in
                clock.advance(to: EXOLimits.catalogDeadline + offset)
                if offset < 0 {
                    operation.send(Self.response(contentType: "application/json"))
                    operation.send(.bytes(Data(Self.catalogFixture.utf8)))
                    operation.complete()
                }
            }
            if offset < 0 {
                #expect(result.result.0 == nil)
                #expect(result.snapshot.outcome == "success")
                #expect(result.loader.operation.cancellationCalls == 0)
            } else {
                #expect(result.result.0 == .timeout("catalog total"))
                #expect(result.snapshot.outcome == "failure")
                #expect(result.loader.operation.cancellationCalls == 1)
            }
            Self.expectQuiescent(result.snapshot)
        }
    }

    @Test func generationHeaderDeadlineAcceptsOnlyStrictlyBeforeFifteenSeconds() async throws {
        for offset: Int64 in [-1, 0, 1] {
            let clock = ManualEXOClock()
            let result = try await Self.runGeneration(clock: clock) { operation in
                clock.advance(to: EXOLimits.headerDeadline + offset)
                if offset < 0 { Self.feedSuccessfulGeneration(operation) }
            }
            if offset < 0 {
                #expect(result.result.error == nil)
                #expect(result.snapshot.outcome == "success")
            } else {
                #expect(result.result.error == .timeout("generation response headers"))
                #expect(result.snapshot.outcome == "failure")
                #expect(result.loader.operation.cancellationCalls == 1)
            }
            Self.expectQuiescent(result.snapshot)
        }
    }

    @Test func generationIdleDeadlineUsesBytesAndIsStrictAtSixtySeconds() async throws {
        for offset: Int64 in [-1, 0, 1] {
            let clock = ManualEXOClock()
            let loader = FakeEXOLoader()
            let probe = EXOOperationTestProbe()
            let filling = try Self.filling(loader: loader, clock: clock, probe: probe)
            let task = Task { await collectEXOStream(filling.generate(Self.request())) }
            await eventually("idle test loader") { loader.startCount == 1 }
            loader.operation.send(Self.response())
            await eventually("initial idle timer") { (probe.snapshot().started[.idleTimer] ?? 0) == 1 }
            clock.advance(to: EXOLimits.idleDeadline + offset)
            if offset < 0 {
                let fixture = Data(Self.streamFixture.utf8)
                loader.operation.send(.bytes(fixture))
                loader.operation.complete()
            }
            let result = await task.value
            let snapshot = await probe.waitForQuiescence()
            if offset < 0 {
                #expect(result.error == nil)
                #expect(snapshot.outcome == "success")
            } else {
                #expect(result.error == .timeout("generation idle"))
                #expect(snapshot.outcome == "failure")
                #expect(loader.operation.cancellationCalls == 1)
            }
            Self.expectQuiescent(snapshot)
        }

        let clock = ManualEXOClock()
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try Self.filling(loader: loader, clock: clock, probe: probe)
        let task = Task { await collectEXOStream(filling.generate(Self.request())) }
        await eventually("idle reset loader") { loader.startCount == 1 }
        loader.operation.send(Self.response())
        await eventually("idle reset initial timer") { (probe.snapshot().started[.idleTimer] ?? 0) == 1 }
        clock.advance(to: 59 * EXOLimits.second)
        loader.operation.send(.bytes(Data(": byte heartbeat\n\n".utf8)))
        await eventually("idle deadline reset by bytes") {
            probe.snapshot().idleDeadlineResets == 2
        }
        #expect(probe.snapshot().started[.idleTimer] == 1)
        clock.advance(to: 118 * EXOLimits.second)
        loader.operation.send(.bytes(Data(Self.streamFixture.utf8)))
        loader.operation.complete()
        let resetResult = await task.value
        let resetSnapshot = await probe.waitForQuiescence()
        #expect(resetResult.error == nil)
        #expect(resetSnapshot.outcome == "success")
        Self.expectQuiescent(resetSnapshot)
    }

    @Test func idleWatchdogOwnershipStaysFixedAcrossThousandsOfResetsAndAStaleWake() async throws {
        let clock = ManualEXOClock()
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let cancellation = EXOCancellationRegistry()
        let coordinator = EXOOperationCoordinator(
            mode: .generation(modelID: Self.modelID),
            loader: loader,
            clock: clock,
            cancellation: cancellation,
            probe: probe,
            emit: { _ in true }
        )
        cancellation.setWake { Task { await coordinator.consumerCancelled() } }
        probe.started(.settlement)
        let task = Task {
            let outcome = await coordinator.run(request: URLRequest(
                url: URL(string: "http://127.0.0.1:52415/v1/chat/completions")!
            ))
            probe.record(outcome: outcome.label)
            probe.terminalEmitted()
            probe.terminated(.settlement)
            probe.settled()
            return outcome
        }
        await eventually("idle stress loader") { loader.startCount == 1 }
        loader.operation.send(Self.response())
        await eventually("idle stress children") {
            let snapshot = probe.snapshot()
            return snapshot.started[.parser] == 1
                && snapshot.started[.idleTimer] == 1
                && snapshot.idleDeadlineResets == 1
        }

        let baseline = await coordinator.ownershipSnapshot()
        #expect(baseline.timerTasks == 3)
        #expect(baseline.childCancels == 5)
        #expect(baseline.cancellationCallbacks == 6)
        #expect(baseline.outcome == nil)

        clock.advance(to: 59 * EXOLimits.second)
        let resetCount = 4_096
        for index in 0 ..< resetCount {
            loader.operation.send(.bytes(Data(": reset \(index)\n\n".utf8)))
            let expected = index + 2
            await eventually("idle stress reset \(expected)") {
                probe.snapshot().idleDeadlineResets >= expected
            }
        }
        let stressed = await coordinator.ownershipSnapshot()
        #expect(stressed.timerTasks == baseline.timerTasks)
        #expect(stressed.childCancels == baseline.childCancels)
        #expect(stressed.cancellationCallbacks == baseline.cancellationCallbacks)
        #expect(stressed.bodyPeakBufferedFragments <= EXOLimits.parserBufferedFragments)
        #expect(stressed.bodyPeakBufferedBytes <= (
            EXOLimits.parserBufferedFragments * EXOLimits.handoffFragmentBytes
        ))
        #expect(probe.snapshot().started[.idleTimer] == 1)

        clock.advance(to: 60 * EXOLimits.second)
        await eventually("stale idle deadline check") {
            probe.snapshot().idleDeadlineChecks == 1
        }
        let afterStaleWake = await coordinator.ownershipSnapshot()
        #expect(afterStaleWake.outcome == nil)
        #expect(afterStaleWake.timerTasks == baseline.timerTasks)
        #expect(afterStaleWake.childCancels == baseline.childCancels)
        #expect(afterStaleWake.cancellationCallbacks == baseline.cancellationCallbacks)

        clock.advance(to: 118 * EXOLimits.second)
        loader.operation.send(.bytes(Data(Self.streamFixture.utf8)))
        loader.operation.complete()
        let outcome = await task.value
        #expect(outcome.label == "success")
        let snapshot = await probe.waitForQuiescence()
        #expect(loader.operation.cancellationCalls == 0)
        #expect(snapshot.started[.idleTimer] == 1)
        #expect(snapshot.terminated[.idleTimer] == 1)
        Self.expectQuiescent(snapshot)

        let released = await coordinator.ownershipSnapshot()
        #expect(released.timerTasks == 0)
        #expect(released.childCancels == 0)
        #expect(released.cancellationCallbacks == 0)
        #expect(released.outcome == "success")
    }

    @Test func generationTotalDeadlineIsStrictAndOutranksAnEqualIdleDeadline() async throws {
        for offset: Int64 in [-1, 0, 1] {
            let clock = ManualEXOClock()
            let loader = FakeEXOLoader()
            let probe = EXOOperationTestProbe()
            let filling = try Self.filling(loader: loader, clock: clock, probe: probe)
            let task = Task { await collectEXOStream(filling.generate(Self.request())) }
            await eventually("total test loader") { loader.startCount == 1 }
            loader.operation.send(Self.response())
            await eventually("total test idle timer") { (probe.snapshot().started[.idleTimer] ?? 0) == 1 }
            let target = EXOLimits.generationDeadline + offset
            await Self.keepGenerationAlive(clock: clock, operation: loader.operation, probe: probe, through: target)
            if offset < 0 {
                loader.operation.send(.bytes(Data(Self.streamFixture.utf8)))
                loader.operation.complete()
            }
            let result = await task.value
            let snapshot = await probe.waitForQuiescence()
            if offset < 0 {
                #expect(result.error == nil)
                #expect(snapshot.outcome == "success")
            } else {
                #expect(result.error == .timeout("generation total"))
                #expect(snapshot.outcome == "failure")
                #expect(loader.operation.cancellationCalls == 1)
            }
            Self.expectQuiescent(snapshot)
        }

        let clock = ManualEXOClock()
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try Self.filling(loader: loader, clock: clock, probe: probe)
        let task = Task { await collectEXOStream(filling.generate(Self.request())) }
        await eventually("equal deadline loader") { loader.startCount == 1 }
        loader.operation.send(Self.response())
        await eventually("equal deadline initial idle") { (probe.snapshot().started[.idleTimer] ?? 0) == 1 }
        await Self.keepGenerationAlive(
            clock: clock,
            operation: loader.operation,
            probe: probe,
            through: EXOLimits.generationDeadline - EXOLimits.idleDeadline - 29 * EXOLimits.second
        )
        clock.advance(to: EXOLimits.generationDeadline - EXOLimits.idleDeadline)
        loader.operation.send(.bytes(Data(": equal deadline\n\n".utf8)))
        let expectedIdleResets = probe.snapshot().idleDeadlineResets + 1
        await eventually("idle equals total") {
            probe.snapshot().idleDeadlineResets >= expectedIdleResets
        }
        clock.advance(to: EXOLimits.generationDeadline)
        let equalResult = await task.value
        let equalSnapshot = await probe.waitForQuiescence()
        #expect(equalResult.error == .timeout("generation total"))
        Self.expectQuiescent(equalSnapshot)
    }

    @Test func recordedCancellationOutranksDeadlineAndAllOwnedChildrenQuiesce() async throws {
        let clock = ManualEXOClock()
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let cancellation = EXOCancellationRegistry()
        let coordinator = EXOOperationCoordinator(
            mode: .generation(modelID: Self.modelID),
            loader: loader,
            clock: clock,
            cancellation: cancellation,
            probe: probe,
            emit: { _ in true }
        )
        cancellation.setWake { Task { await coordinator.consumerCancelled() } }
        let task = Task {
            await coordinator.run(request: URLRequest(url: URL(string: "http://127.0.0.1:52415/v1/chat/completions")!))
        }
        await eventually("precedence loader") { loader.startCount == 1 }
        cancellation.cancel()
        clock.advance(to: EXOLimits.headerDeadline)
        let outcome = await task.value
        #expect(outcome.label == "cancelled")
        #expect(loader.operation.cancellationCalls == 1)
        #expect(probe.snapshot().survivorCount == 0)
    }

    @Test func consumerCancellationBeforeHeadersAfterHeadersAndAfterTerminalSettlesOnce() async throws {
        enum Stage { case beforeHeaders, afterHeaders, afterTerminal }
        for stage in [Stage.beforeHeaders, .afterHeaders, .afterTerminal] {
            let loader = FakeEXOLoader()
            let probe = EXOOperationTestProbe()
            let filling = try Self.filling(loader: loader, probe: probe)
            let task = Task { await collectEXOStream(filling.generate(Self.request())) }
            await eventually("cancellation loader") { loader.startCount == 1 }
            switch stage {
            case .beforeHeaders:
                break
            case .afterHeaders:
                loader.operation.send(Self.response())
                await eventually("parser after headers") { (probe.snapshot().started[.parser] ?? 0) == 1 }
            case .afterTerminal:
                loader.operation.send(Self.response())
                await eventually("parser before terminal") { (probe.snapshot().started[.parser] ?? 0) == 1 }
                loader.operation.send(.bytes(Data(Self.event(try Self.terminal()).utf8)))
                for _ in 0 ..< 1_000 { await Task.yield() }
            }
            task.cancel()
            _ = await task.value
            let snapshot = await probe.waitForQuiescence()
            #expect(snapshot.outcome == "cancelled")
            #expect(loader.operation.cancellationCalls == 1)
            for (kind, count) in snapshot.started where kind != .settlement {
                #expect(snapshot.cancelled[kind] == count)
            }
            Self.expectQuiescent(snapshot)
        }
    }

    @Test func callerCancellationOfCatalogPrewarmSettlesTheOneTaskOnce() async throws {
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try Self.filling(loader: loader, probe: probe)
        let task = Task { await Self.prewarmResult(filling) }
        await eventually("prewarm cancellation loader") { loader.startCount == 1 }
        task.cancel()
        let result = await task.value
        let snapshot = await probe.waitForQuiescence()
        #expect(result.0 == nil)
        #expect(result.1)
        #expect(snapshot.outcome == "cancelled")
        #expect(loader.operation.cancellationCalls == 1)
        for (kind, count) in snapshot.started where kind != .settlement {
            #expect(snapshot.cancelled[kind] == count)
        }
        Self.expectQuiescent(snapshot)
    }

    @Test func cancellationAfterSettlementIsAnIdempotentNoOp() async throws {
        let loader = FakeEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try Self.filling(loader: loader, probe: probe)
        let task = Task { await collectEXOStream(filling.generate(Self.request())) }
        await eventually("settled cancellation loader") { loader.startCount == 1 }
        Self.feedSuccessfulGeneration(loader.operation)
        let result = await task.value
        let settled = await probe.waitForQuiescence()
        #expect(result.events.last == .finished(.complete))
        #expect(settled.outcome == "success")
        #expect(loader.operation.cancellationCalls == 0)
        task.cancel()
        for _ in 0 ..< 100 { await Task.yield() }
        #expect(probe.snapshot() == settled)
        #expect(loader.operation.cancellationCalls == 0)
        Self.expectQuiescent(settled)
    }
}
