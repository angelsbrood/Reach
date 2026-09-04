import Dispatch
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if os(Linux)
import Glibc
#else
import Darwin
#endif
import ReachWire
import Testing
@testable import ReachHost

private enum LoopbackFixtureError: Error, CustomStringConvertible {
    case system(String, Int32)
    case malformedRequest(String)
    case timedOutWaitingForCancellation

    var description: String {
        switch self {
        case .system(let operation, let code):
            "\(operation) failed with errno \(code)"
        case .malformedRequest(let reason):
            "malformed HTTP request: \(reason)"
        case .timedOutWaitingForCancellation:
            "timed out waiting for cancellation to close the HTTP connection"
        }
    }
}

private struct LoopbackHTTPRequest: Sendable, Equatable {
    var method: String
    var path: String
    var headers: [String: String]
    var body: Data
}

private struct LoopbackServerSnapshot: Sendable, Equatable {
    var requests: [LoopbackHTTPRequest]
    var successfulBodyWrites: Int
    var cancellationResponseStarted: Bool
    var cancellationPeerClosed: Bool
    var activeClients: Int
    var completed: Bool
    var failure: String?
}

/// A fixed three-request HTTP/1.1 fixture. It binds only numeric IPv4
/// loopback, has no DNS or remote route, and records only synthetic bytes.
private final class LoopbackEXOServer: @unchecked Sendable {
    static let modelID = "model-a"

    static let catalog = Data(#"""
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
    """#.utf8)

    static let successfulStream = Data(#"""
    : prefill statistics

    data: {"id":"cmd-1","object":"chat.completion.chunk","created":1720000000,"model":"model-a","choices":[{"index":0,"delta":{"content":"Hé"},"finish_reason":null}]}

    data: {"id":"cmd-1","object":"chat.completion.chunk","created":1720000001,"model":"model-a","choices":[{"index":0,"delta":{"content":" moon"},"finish_reason":null}]}

    data: {"id":"cmd-1","object":"chat.completion.chunk","created":1720000002,"model":"model-a","choices":[{"index":0,"delta":{"content":"!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}

    : generation statistics

    data: [DONE]

    """#.utf8) + Data("\n".utf8)

    static let cancellationPrefix = Data(#"""
    data: {"id":"cmd-cancel","object":"chat.completion.chunk","created":1720000003,"model":"model-a","choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}]}

    """#.utf8) + Data("\n".utf8)

    private let lock = NSLock()
    private let group = DispatchGroup()
    private let queue = DispatchQueue(label: "reach.linux-loopback-exo")
    private var listener: Int32
    private var clients: Set<Int32> = []
    private var stopping = false
    private var requestsStorage: [LoopbackHTTPRequest] = []
    private var successfulBodyWritesStorage = 0
    private var cancellationResponseStartedStorage = false
    private var cancellationPeerClosedStorage = false
    private var completedStorage = false
    private var failureStorage: String?

    let port: UInt16

    init() throws {
        #if os(Linux)
        let socketType = Int32(SOCK_STREAM.rawValue)
        #else
        let socketType = SOCK_STREAM
        #endif
        let descriptor = socket(AF_INET, socketType, 0)
        guard descriptor >= 0 else { throw LoopbackFixtureError.system("socket", errno) }

        var reuse: Int32 = 1
        let reuseResult = withUnsafePointer(to: &reuse) {
            setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_REUSEADDR,
                $0,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }
        guard reuseResult == 0 else {
            let code = errno
            systemClose(descriptor)
            throw LoopbackFixtureError.system("setsockopt(SO_REUSEADDR)", code)
        }

        var address = sockaddr_in()
        #if !os(Linux)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(0).bigEndian
        var numericLoopback = in_addr()
        let conversion = "127.0.0.1".withCString {
            inet_pton(AF_INET, $0, &numericLoopback)
        }
        guard conversion == 1 else {
            systemClose(descriptor)
            throw LoopbackFixtureError.malformedRequest("numeric loopback conversion failed")
        }
        address.sin_addr = numericLoopback

        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let code = errno
            systemClose(descriptor)
            throw LoopbackFixtureError.system("bind", code)
        }
        guard listen(descriptor, 3) == 0 else {
            let code = errno
            systemClose(descriptor)
            throw LoopbackFixtureError.system("listen", code)
        }

        var bound = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &boundLength)
            }
        }
        guard nameResult == 0 else {
            let code = errno
            systemClose(descriptor)
            throw LoopbackFixtureError.system("getsockname", code)
        }
        listener = descriptor
        port = UInt16(bigEndian: bound.sin_port)
    }

    var endpoint: String { "http://127.0.0.1:\(port)" }

    func start() {
        group.enter()
        queue.async { [self] in
            defer { group.leave() }
            do {
                for requestIndex in 0 ..< 3 {
                    let client = try acceptClient()
                    try withClient(client) {
                        let request = try readRequest(from: client)
                        record(request)
                        switch requestIndex {
                        case 0:
                            try writeResponse(
                                to: client,
                                contentType: "application/json; charset=utf-8",
                                body: Self.catalog
                            )
                        case 1:
                            try writeFragmentedSuccess(to: client)
                        default:
                            try writeCancellationPrefix(to: client)
                            try waitForCancellationClose(on: client)
                        }
                    }
                }
                lock.withLock { completedStorage = true }
            } catch {
                lock.withLock {
                    if !stopping { failureStorage = String(describing: error) }
                }
            }
            let descriptor = lock.withLock { () -> Int32 in
                let value = listener
                listener = -1
                return value
            }
            if descriptor >= 0 { systemClose(descriptor) }
        }
    }

    func stop() {
        lock.withLock {
            guard !stopping else { return }
            stopping = true
            if listener >= 0 { systemShutdown(listener) }
            clients.forEach(systemShutdown)
        }
        _ = group.wait(timeout: .now() + 5)
    }

    var snapshot: LoopbackServerSnapshot {
        lock.withLock {
            .init(
                requests: requestsStorage,
                successfulBodyWrites: successfulBodyWritesStorage,
                cancellationResponseStarted: cancellationResponseStartedStorage,
                cancellationPeerClosed: cancellationPeerClosedStorage,
                activeClients: clients.count,
                completed: completedStorage,
                failure: failureStorage
            )
        }
    }

    private func acceptClient() throws -> Int32 {
        while true {
            let descriptor = lock.withLock { listener }
            guard descriptor >= 0 else { throw LoopbackFixtureError.system("accept", EBADF) }
            let client = accept(descriptor, nil, nil)
            if client >= 0 {
                #if !os(Linux)
                var noSignal: Int32 = 1
                _ = withUnsafePointer(to: &noSignal) {
                    setsockopt(
                        client,
                        SOL_SOCKET,
                        SO_NOSIGPIPE,
                        $0,
                        socklen_t(MemoryLayout<Int32>.size)
                    )
                }
                #endif
                _ = lock.withLock { clients.insert(client) }
                return client
            }
            if errno == EINTR { continue }
            throw LoopbackFixtureError.system("accept", errno)
        }
    }

    private func withClient(_ client: Int32, body: () throws -> Void) rethrows {
        defer {
            _ = lock.withLock { clients.remove(client) }
            systemClose(client)
        }
        try body()
    }

    private func record(_ request: LoopbackHTTPRequest) {
        lock.withLock { requestsStorage.append(request) }
    }

    private func readRequest(from client: Int32) throws -> LoopbackHTTPRequest {
        var bytes = Data()
        let marker = Data("\r\n\r\n".utf8)
        var headerRange: Range<Data.Index>?
        while headerRange == nil {
            guard bytes.count <= 64 * 1024 else {
                throw LoopbackFixtureError.malformedRequest("headers exceed 64 KiB")
            }
            let next = try readSome(from: client)
            guard !next.isEmpty else {
                throw LoopbackFixtureError.malformedRequest("peer closed before headers")
            }
            bytes.append(next)
            headerRange = bytes.range(of: marker)
        }
        let range = headerRange!
        guard let headerText = String(data: bytes[..<range.lowerBound], encoding: .utf8) else {
            throw LoopbackFixtureError.malformedRequest("headers are not UTF-8")
        }
        let lines = headerText.components(separatedBy: "\r\n")
        guard let first = lines.first else {
            throw LoopbackFixtureError.malformedRequest("missing request line")
        }
        let requestLine = first.split(separator: " ", omittingEmptySubsequences: false)
        guard requestLine.count == 3, requestLine[2] == "HTTP/1.1" else {
            throw LoopbackFixtureError.malformedRequest("invalid request line")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else {
                throw LoopbackFixtureError.malformedRequest("invalid header")
            }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard headers.updateValue(value, forKey: name) == nil else {
                throw LoopbackFixtureError.malformedRequest("duplicate header")
            }
        }
        let expectedBodyCount: Int
        if let value = headers["content-length"] {
            guard let parsed = Int(value), parsed >= 0, parsed <= 1024 * 1024 else {
                throw LoopbackFixtureError.malformedRequest("invalid content length")
            }
            expectedBodyCount = parsed
        } else {
            expectedBodyCount = 0
        }
        var body = Data(bytes[range.upperBound...])
        while body.count < expectedBodyCount {
            let next = try readSome(from: client)
            guard !next.isEmpty else {
                throw LoopbackFixtureError.malformedRequest("peer closed before body")
            }
            body.append(next)
        }
        guard body.count == expectedBodyCount else {
            throw LoopbackFixtureError.malformedRequest("body length mismatch")
        }
        return .init(
            method: String(requestLine[0]),
            path: String(requestLine[1]),
            headers: headers,
            body: body
        )
    }

    private func readSome(from client: Int32) throws -> Data {
        var storage = [UInt8](repeating: 0, count: 8 * 1024)
        while true {
            let count = storage.withUnsafeMutableBytes {
                systemReceive(client, $0.baseAddress, $0.count)
            }
            if count > 0 { return Data(storage.prefix(count)) }
            if count == 0 { return Data() }
            if errno == EINTR { continue }
            throw LoopbackFixtureError.system("recv", errno)
        }
    }

    private func writeResponse(to client: Int32, contentType: String, body: Data) throws {
        let headers = Data((
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: \(contentType)\r\n" +
            "Content-Length: \(body.count)\r\n" +
            "Connection: close\r\n\r\n"
        ).utf8)
        try writeAll(headers, to: client)
        try writeAll(body, to: client)
    }

    private func writeFragmentedSuccess(to client: Int32) throws {
        let body = Self.successfulStream
        let headers = Data((
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/event-stream; charset=utf-8\r\n" +
            "Content-Length: \(body.count)\r\n" +
            "Connection: close\r\n\r\n"
        ).utf8)
        try writeAll(headers, to: client)
        let pattern = [1, 2, 3, 5, 8, 13]
        var offset = 0
        var writes = 0
        while offset < body.count {
            let count = min(pattern[writes % pattern.count], body.count - offset)
            try writeAll(Data(body[offset ..< offset + count]), to: client)
            offset += count
            writes += 1
        }
        lock.withLock { successfulBodyWritesStorage = writes }
    }

    private func writeCancellationPrefix(to client: Int32) throws {
        let headers = Data((
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/event-stream\r\n" +
            "Connection: close\r\n\r\n"
        ).utf8)
        try writeAll(headers, to: client)
        try writeAll(Self.cancellationPrefix, to: client)
        lock.withLock { cancellationResponseStartedStorage = true }
    }

    private func waitForCancellationClose(on client: Int32) throws {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(
                client,
                SOL_SOCKET,
                SO_RCVTIMEO,
                $0,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }
        var byte: UInt8 = 0
        while true {
            let count = withUnsafeMutablePointer(to: &byte) {
                systemReceive(client, $0, 1)
            }
            if count == 0 || (count < 0 && errno == ECONNRESET) {
                lock.withLock { cancellationPeerClosedStorage = true }
                return
            }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                throw LoopbackFixtureError.timedOutWaitingForCancellation
            }
            if count < 0 { throw LoopbackFixtureError.system("recv(cancellation)", errno) }
        }
    }

    private func writeAll(_ data: Data, to client: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < data.count {
                let count = systemSend(client, bytes.baseAddress?.advanced(by: offset), data.count - offset)
                if count > 0 {
                    offset += count
                } else if count < 0 && errno == EINTR {
                    continue
                } else {
                    throw LoopbackFixtureError.system("send", errno)
                }
            }
        }
    }
}

private func systemSend(_ descriptor: Int32, _ bytes: UnsafeRawPointer?, _ count: Int) -> Int {
    #if os(Linux)
    Glibc.send(descriptor, bytes, count, Int32(MSG_NOSIGNAL))
    #else
    Darwin.send(descriptor, bytes, count, 0)
    #endif
}

private func systemReceive(_ descriptor: Int32, _ bytes: UnsafeMutableRawPointer?, _ count: Int) -> Int {
    #if os(Linux)
    Glibc.recv(descriptor, bytes, count, 0)
    #else
    Darwin.recv(descriptor, bytes, count, 0)
    #endif
}

private func systemShutdown(_ descriptor: Int32) {
    #if os(Linux)
    _ = Glibc.shutdown(descriptor, Int32(SHUT_RDWR))
    #else
    _ = Darwin.shutdown(descriptor, SHUT_RDWR)
    #endif
}

private func systemClose(_ descriptor: Int32) {
    #if os(Linux)
    _ = Glibc.close(descriptor)
    #else
    _ = Darwin.close(descriptor)
    #endif
}

private func loopbackRequest() -> WireGenerationRequest {
    WireGenerationRequest(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        portableTranscript: WireTranscript(entries: [
            .instructions(.init(
                id: "instructions",
                segments: [.text(.init(id: "is", content: "Be exact."))]
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
        ]),
        options: .init(
            temperature: 0.5,
            maximumResponseTokens: 42,
            sampling: .topK(40, seed: 7),
            toolCalling: .allowed
        )
    )
}

private let loopbackRequestBytes = Data(#"{"enable_thinking":false,"max_tokens":42,"messages":[{"content":"Be exact.","role":"system"},{"content":"Hello","role":"user"},{"content":"Earlier","role":"assistant"}],"model":"model-a","n":1,"seed":7,"stream":true,"stream_options":{"include_usage":true},"temperature":0.5,"top_k":40}"#.utf8)

private func productionLoopbackFilling(
    endpoint: String,
    probe: EXOOperationTestProbe
) throws -> EXOFilling {
    let configuration = EXOFilling.lockedSessionConfiguration()
    let delegate = EXOSessionDelegate()
    let loader = EXOURLSessionLoader(configuration: configuration, delegate: delegate)
    return try EXOFilling(
        modelID: LoopbackEXOServer.modelID,
        endpoint: endpoint,
        loader: loader,
        clock: EXOContinuousClock(),
        testProbe: probe
    )
}

private func expectLoopbackQuiescence(_ snapshot: EXOOperationSnapshot) {
    #expect(snapshot.survivorCount == 0)
    #expect(snapshot.outcomes == 1)
    #expect(snapshot.terminalEmissions == 1)
    #expect(snapshot.started == snapshot.terminated)
}

private final class LoopbackCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = 0

    func increment() { lock.withLock { storage += 1 } }
    var value: Int { lock.withLock { storage } }
}

private final class DelayedTerminationEXOTask: EXOHTTPTasking, @unchecked Sendable {
    struct Snapshot: Sendable {
        var cancellationCalls: Int
        var logicalStreamFinished: Bool
        var taskTerminated: Bool
        var terminationWaiters: Int
    }

    private let lock = NSLock()
    private var eventWaiter: CheckedContinuation<EXOHTTPEvent?, any Error>?
    private var logicalStreamFinished = false
    private var taskTerminated = false
    private var cancellationCalls = 0
    private var terminationWaiters: [CheckedContinuation<Void, Never>] = []

    func nextEvent() async throws -> EXOHTTPEvent? {
        try await withCheckedThrowingContinuation { continuation in
            let cancelled = lock.withLock { () -> Bool in
                if logicalStreamFinished { return true }
                precondition(eventWaiter == nil)
                eventWaiter = continuation
                return false
            }
            if cancelled { continuation.resume(throwing: CancellationError()) }
        }
    }

    func cancel() {
        let waiter = lock.withLock { () -> CheckedContinuation<EXOHTTPEvent?, any Error>? in
            cancellationCalls += 1
            guard !logicalStreamFinished else { return nil }
            logicalStreamFinished = true
            let result = eventWaiter
            eventWaiter = nil
            return result
        }
        waiter?.resume(throwing: CancellationError())
    }

    func waitForTermination() async {
        await withCheckedContinuation { continuation in
            let resumeNow = lock.withLock {
                if taskTerminated { return true }
                terminationWaiters.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    func acknowledgeTermination() {
        let waiters = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
            taskTerminated = true
            let result = terminationWaiters
            terminationWaiters.removeAll()
            return result
        }
        waiters.forEach { $0.resume() }
    }

    var snapshot: Snapshot {
        lock.withLock {
            .init(
                cancellationCalls: cancellationCalls,
                logicalStreamFinished: logicalStreamFinished,
                taskTerminated: taskTerminated,
                terminationWaiters: terminationWaiters.count
            )
        }
    }
}

private final class DelayedTerminationEXOLoader: EXOHTTPLoading, @unchecked Sendable {
    let operation = DelayedTerminationEXOTask()
    private let lock = NSLock()
    private var starts = 0

    var startCount: Int { lock.withLock { starts } }

    func start(_ request: URLRequest) -> any EXOHTTPTasking {
        lock.withLock { starts += 1 }
        return operation
    }
}

@Suite(.serialized) struct LinuxLoopbackEXOTests {
    @Test func providerRegistryClosesRegistrationRacesAndAwaitsRealTaskTermination() async throws {
        let racingRegistry = EXOOperationRegistry()
        let ticket = try #require(racingRegistry.reserve())
        let cancellationCount = LoopbackCounter()
        let firstRaceShutdown = Task { await racingRegistry.shutdown() }
        let secondRaceShutdown = Task { await racingRegistry.shutdown() }
        #expect(await portableEventually { racingRegistry.snapshot.closing })
        racingRegistry.install(
            EXOCancelOnce(kind: .settlement, probe: nil, action: cancellationCount.increment),
            for: ticket
        )
        #expect(cancellationCount.value == 1)
        #expect(racingRegistry.snapshot.registered == 1)
        #expect(racingRegistry.reserve() == nil)
        racingRegistry.finish(ticket)
        await firstRaceShutdown.value
        await secondRaceShutdown.value
        #expect(racingRegistry.snapshot == .init(registered: 0, peakRegistered: 1, closing: true))

        let loader = DelayedTerminationEXOLoader()
        let probe = EXOOperationTestProbe()
        let filling = try EXOFilling(
            modelID: LoopbackEXOServer.modelID,
            endpoint: "http://127.0.0.1:52415",
            loader: loader,
            clock: EXOContinuousClock(),
            testProbe: probe
        )
        let retainedStream = filling.generate(loopbackRequest())
        _ = retainedStream
        #expect(await portableEventually {
            loader.startCount == 1 && filling.operationRegistrySnapshot.registered == 1
        })

        let firstReturned = PortableFlag()
        let secondReturned = PortableFlag()
        let first = Task {
            await filling.shutdown()
            firstReturned.set()
        }
        let second = Task {
            await filling.shutdown()
            secondReturned.set()
        }
        #expect(await portableEventually {
            let snapshot = loader.operation.snapshot
            return snapshot.cancellationCalls == 1 && snapshot.terminationWaiters == 1
        })
        let held = loader.operation.snapshot
        #expect(held.logicalStreamFinished)
        #expect(!held.taskTerminated)
        #expect(!firstReturned.value)
        #expect(!secondReturned.value)
        #expect(filling.operationRegistrySnapshot.registered == 1)
        #expect(filling.operationRegistrySnapshot.closing)

        var lateWasCancelled = false
        do {
            for try await _ in filling.generate(loopbackRequest()) {}
        } catch is CancellationError {
            lateWasCancelled = true
        }
        #expect(lateWasCancelled)
        do {
            try await filling.prewarm()
            Issue.record("prewarm started after provider shutdown")
        } catch is CancellationError {
            // Expected: shutdown permanently closes this filling instance.
        }
        #expect(loader.startCount == 1)

        loader.operation.acknowledgeTermination()
        await first.value
        await second.value
        await filling.shutdown()
        #expect(firstReturned.value)
        #expect(secondReturned.value)
        #expect(loader.operation.snapshot.taskTerminated)
        #expect(filling.operationRegistrySnapshot == .init(
            registered: 0,
            peakRegistered: 1,
            closing: true
        ))
        let settled = await probe.waitForQuiescence()
        #expect(settled.outcome == "cancelled")
        expectLoopbackQuiescence(settled)
    }

    @Test func productionNetworkingCatalogGenerationAndCancellationAreBoundedAndQuiescent() async throws {
        let server = try LoopbackEXOServer()
        server.start()
        defer { server.stop() }

        let catalogProbe = EXOOperationTestProbe()
        let catalog = try productionLoopbackFilling(endpoint: server.endpoint, probe: catalogProbe)
        try await catalog.prewarm()
        #expect(catalog.loaderStartCount == 1)
        let catalogSettlement = await catalogProbe.waitForQuiescence()
        #expect(catalogSettlement.outcome == "success")
        expectLoopbackQuiescence(catalogSettlement)

        let successProbe = EXOOperationTestProbe()
        let successFilling = try productionLoopbackFilling(endpoint: server.endpoint, probe: successProbe)
        let successRegistry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let successAdmission = SlotAdmission(eventSink: { _ in })
        let successHost = portableHost(
            filling: successFilling,
            registry: successRegistry,
            admission: successAdmission
        )
        let (successSessionID, _) = try await portableOpenSession(
            on: successHost,
            expectedCapabilities: []
        )
        let successGenerationID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        let successStream = PortableMemoryStream(endpoint: "127.0.0.1:47010")
        try successStream.yield(GenerateBegin(
            sessionID: successSessionID,
            genID: successGenerationID,
            request: loopbackRequest()
        ))
        let successServing = Task { await successHost.serve(successStream) }
        #expect(await portableEventually { successStream.outputCount == 5 })
        try successStream.yield(EvAck(seq: 4))
        successStream.finishInput()
        await successServing.value

        let successEvents = try successStream.outputFrames().map { try $0.decode(Ev.self) }
        #expect(successEvents.map(\.seq) == [0, 1, 2, 3, 4])
        #expect(successEvents.map(\.event) == [
            .responseAppend(entryID: nil, text: "Hé", segmentID: nil, tokenCount: 1),
            .responseAppend(entryID: nil, text: " moon", segmentID: nil, tokenCount: 1),
            .responseAppend(entryID: nil, text: "!", segmentID: nil, tokenCount: 1),
            .usage(inputTokens: 3, outputTokens: 4),
            .finished(.complete),
        ])
        let successSettlement = await successProbe.waitForQuiescence()
        #expect(successSettlement.outcome == "success")
        expectLoopbackQuiescence(successSettlement)
        let successCounters = await successAdmission.counters
        #expect(successCounters.active == 0)
        #expect(successCounters.waiting == 0)
        #expect(successCounters.admitted == 1)
        await successHost.shutdown()
        #expect(await successRegistry.residentSessions == 0)
        #expect(await successRegistry.replayCounters.currentBytes == 0)

        let cancellationProbe = EXOOperationTestProbe()
        let cancellationFilling = try productionLoopbackFilling(
            endpoint: server.endpoint,
            probe: cancellationProbe
        )
        let cancellationRegistry = SessionRegistry(receiptSink: { _ in }, replayEventSink: { _ in })
        let cancellationAdmission = SlotAdmission(eventSink: { _ in })
        let cancellationHost = portableHost(
            filling: cancellationFilling,
            registry: cancellationRegistry,
            admission: cancellationAdmission
        )
        let (cancellationSessionID, _) = try await portableOpenSession(
            on: cancellationHost,
            expectedCapabilities: []
        )
        let cancellationGenerationID = UUID(uuidString: "00000000-0000-0000-0000-000000000003")!
        let cancellationStream = PortableMemoryStream(endpoint: "127.0.0.1:47011")
        try cancellationStream.yield(GenerateBegin(
            sessionID: cancellationSessionID,
            genID: cancellationGenerationID,
            request: loopbackRequest()
        ))
        let cancellationServing = Task { await cancellationHost.serve(cancellationStream) }
        #expect(await portableEventually {
            server.snapshot.cancellationResponseStarted && cancellationStream.outputCount == 1
        })
        try cancellationStream.yield(GenerateCancel(genID: cancellationGenerationID))
        #expect(await portableEventually { cancellationStream.outputCount == 2 })
        try cancellationStream.yield(EvAck(seq: 1))
        cancellationStream.finishInput()
        await cancellationServing.value

        let cancellationEvents = try cancellationStream.outputFrames().map { try $0.decode(Ev.self) }
        #expect(cancellationEvents.map(\.seq) == [0, 1])
        #expect(cancellationEvents.map(\.event) == [
            .responseAppend(entryID: nil, text: "partial", segmentID: nil, tokenCount: 1),
            .finished(.cancelled),
        ])
        let cancellationSettlement = await cancellationProbe.waitForQuiescence()
        #expect(cancellationSettlement.outcome == "cancelled")
        expectLoopbackQuiescence(cancellationSettlement)
        let cancellationCounters = await cancellationAdmission.counters
        #expect(cancellationCounters.active == 0)
        #expect(cancellationCounters.waiting == 0)
        #expect(cancellationCounters.cancelled == 1)
        await cancellationHost.shutdown()
        #expect(await cancellationRegistry.residentSessions == 0)
        #expect(await cancellationRegistry.replayCounters.currentBytes == 0)

        #expect(await portableEventually {
            let snapshot = server.snapshot
            return snapshot.completed && snapshot.activeClients == 0
        })
        let serverSnapshot = server.snapshot
        #expect(serverSnapshot.failure == nil)
        #expect(serverSnapshot.completed)
        #expect(serverSnapshot.activeClients == 0)
        #expect(serverSnapshot.successfulBodyWrites > 16)
        #expect(serverSnapshot.cancellationResponseStarted)
        #expect(serverSnapshot.cancellationPeerClosed)
        #expect(serverSnapshot.requests.count == 3)
        if serverSnapshot.requests.count == 3 {
            let catalogRequest = serverSnapshot.requests[0]
            #expect(catalogRequest.method == "GET")
            #expect(catalogRequest.path == "/v1/models")
            #expect(catalogRequest.body.isEmpty)

            for request in serverSnapshot.requests.dropFirst() {
                #expect(request.method == "POST")
                #expect(request.path == "/v1/chat/completions")
                #expect(request.headers["content-type"] == "application/json")
                #expect(request.headers["accept"] == "text/event-stream")
                #expect(request.body == loopbackRequestBytes)
            }
            for request in serverSnapshot.requests {
                #expect(request.headers["authorization"] == nil)
                #expect(request.headers["cookie"] == nil)
                #expect(request.headers["proxy-authorization"] == nil)
            }
        }
    }
}
