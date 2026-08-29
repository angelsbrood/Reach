import CoreFoundation
import Foundation
import FoundationModels
import ReachWire

/// One operator-managed EXO API behind Reach's existing provider slot.
///
/// The public construction path is deliberately narrow: an exact numeric
/// loopback endpoint and a private, locked ephemeral URL session. Tests use the
/// internal loader and clock seams below; neither can be supplied by reachd or
/// another package client.
public final class EXOFilling: SlotFilling, @unchecked Sendable {
    public let modelID: String
    public let displayName: String
    public let capabilities: [String] = []

    let endpoint: EXOEndpoint
    let loader: any EXOHTTPLoading
    let clock: any EXOClock
    let testProbe: EXOOperationTestProbe?
    let productionConfiguration: URLSessionConfiguration?
    let productionDelegate: EXOSessionDelegate?

    public init(modelID: String, endpoint: String) throws {
        let validated = try EXOEndpoint(endpoint)
        let configuration = Self.lockedSessionConfiguration()
        let delegate = EXOSessionDelegate()
        let loader = EXOURLSessionLoader(configuration: configuration, delegate: delegate)
        self.modelID = modelID
        self.displayName = "\(modelID) (EXO)"
        self.endpoint = validated
        self.loader = loader
        self.clock = EXOContinuousClock()
        self.testProbe = nil
        self.productionConfiguration = configuration
        self.productionDelegate = delegate
    }

    init(
        modelID: String,
        endpoint: String,
        loader: any EXOHTTPLoading,
        clock: any EXOClock,
        testProbe: EXOOperationTestProbe? = nil
    ) throws {
        self.modelID = modelID
        self.displayName = "\(modelID) (EXO)"
        self.endpoint = try EXOEndpoint(endpoint)
        self.loader = loader
        self.clock = clock
        self.testProbe = testProbe
        self.productionConfiguration = nil
        self.productionDelegate = nil
    }

    var loaderStartCount: Int { loader.startCount }

    static func lockedSessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        configuration.urlCredentialStorage = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.protocolClasses = nil
        // Reach's own monotonic deadlines always expire first. These are only
        // a backstop in Foundation, never the provider contract.
        configuration.timeoutIntervalForRequest = 31 * 60
        configuration.timeoutIntervalForResource = 31 * 60
        return configuration
    }

    public func prewarm() async throws {
        let cancellation = EXOCancellationRegistry()
        let coordinator = EXOOperationCoordinator(
            mode: .catalog(modelID: modelID),
            loader: loader,
            clock: clock,
            cancellation: cancellation,
            probe: testProbe,
            emit: nil
        )
        cancellation.setWake {
            Task { await coordinator.consumerCancelled() }
        }
        testProbe?.started(.settlement)
        let outcome = await withTaskCancellationHandler {
            await coordinator.run(request: catalogRequest())
        } onCancel: {
            cancellation.cancel()
        }
        testProbe?.record(outcome: outcome.label)
        testProbe?.terminalEmitted()
        testProbe?.terminated(.settlement)
        testProbe?.settled()
        switch outcome {
        case .success:
            return
        case .failure(let error):
            throw error
        case .cancelled:
            throw CancellationError()
        }
    }

    public func generate(
        _ request: WireGenerationRequest
    ) -> AsyncThrowingStream<WireEvent, Error> {
        let httpRequest: URLRequest
        do {
            httpRequest = try generationRequest(request)
        } catch {
            let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
            testProbe?.started(.settlement)
            testProbe?.record(outcome: "failure")
            continuation.finish(throwing: error)
            testProbe?.terminalEmitted()
            testProbe?.terminated(.settlement)
            testProbe?.settled()
            return stream
        }

        let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
        let cancellation = EXOCancellationRegistry()
        let emitter: @Sendable (WireEvent) -> Bool = { event in
            if case .terminated = continuation.yield(event) { return false }
            return true
        }
        let coordinator = EXOOperationCoordinator(
            mode: .generation(modelID: modelID),
            loader: loader,
            clock: clock,
            cancellation: cancellation,
            probe: testProbe,
            emit: emitter
        )
        cancellation.setWake {
            Task { await coordinator.consumerCancelled() }
        }

        let retention = EXOSettlementRetention()
        testProbe?.started(.settlement)
        retention.task = Task { [testProbe] in
            let outcome = await coordinator.run(request: httpRequest)
            testProbe?.record(outcome: outcome.label)
            switch outcome {
            case .success(let terminal):
                if let usage = terminal.usage {
                    _ = continuation.yield(.usage(
                        inputTokens: usage.inputTokens,
                        outputTokens: usage.outputTokens
                    ))
                }
                _ = continuation.yield(.finished(.complete))
                continuation.finish()
            case .failure(let error):
                continuation.finish(throwing: error)
            case .cancelled:
                // Consumer termination has already made the stream
                // unreachable. Cleanup is the outcome; do not emit after it.
                continuation.finish()
            }
            testProbe?.terminalEmitted()
            testProbe?.terminated(.settlement)
            testProbe?.settled()
        }
        continuation.onTermination = { termination in
            _ = retention
            if case .cancelled = termination {
                cancellation.cancel()
            }
        }
        return stream
    }

    func catalogRequest() -> URLRequest {
        var request = URLRequest(
            url: endpoint.url(path: "/v1/models"),
            cachePolicy: .reloadIgnoringLocalCacheData
        )
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    func generationRequest(_ request: WireGenerationRequest) throws -> URLRequest {
        let body = try EXORequestEncoder.encode(request, modelID: modelID)
        guard body.count <= EXOLimits.requestBodyBytes else {
            throw EXOFillingError.requestLimit("encoded request body")
        }
        var result = URLRequest(
            url: endpoint.url(path: "/v1/chat/completions"),
            cachePolicy: .reloadIgnoringLocalCacheData
        )
        result.httpMethod = "POST"
        result.setValue("application/json", forHTTPHeaderField: "Content-Type")
        result.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        result.httpBody = body
        return result
    }
}

// MARK: - Public finite errors

public enum EXOFillingError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case invalidEndpoint
    case unsupportedRequest(String)
    case invalidNumericOption(String)
    case requestLimit(String)
    case responseLimit(String)
    case transport(String)
    case timeout(String)
    case httpStatus(Int, String?)
    case contentType(expected: String, actual: String?)
    case malformedCatalog(String)
    case malformedStream(String)
    case modelUnavailable(String)
    case upstreamError(String)
    case protocolContradiction(String)
    case redirect(Int)
    case authenticationChallenge

    public var description: String {
        switch self {
        case .invalidEndpoint:
            "EXO endpoint must be canonical numeric loopback HTTP with an explicit nonzero port"
        case .unsupportedRequest(let reason):
            "EXO does not support this Reach request: \(reason)"
        case .invalidNumericOption(let option):
            "EXO request has an invalid \(option) option"
        case .requestLimit(let limit):
            "EXO request crossed the \(limit) limit"
        case .responseLimit(let limit):
            "EXO response crossed the \(limit) limit"
        case .transport(let message):
            "EXO transport failed: \(message)"
        case .timeout(let limit):
            "EXO timed out at the \(limit) deadline"
        case .httpStatus(let status, let message):
            if let message { "EXO returned HTTP \(status): \(message)" }
            else { "EXO returned HTTP \(status)" }
        case .contentType(let expected, let actual):
            "EXO response content type must be \(expected), not \(actual ?? "missing")"
        case .malformedCatalog(let reason):
            "EXO model catalog is malformed: \(reason)"
        case .malformedStream(let reason):
            "EXO stream is malformed: \(reason)"
        case .modelUnavailable(let model):
            "EXO model catalog does not contain exactly one \(model) entry"
        case .upstreamError(let message):
            "EXO reported an error: \(message)"
        case .protocolContradiction(let reason):
            "EXO protocol contradiction: \(reason)"
        case .redirect(let status):
            "EXO redirect was refused (HTTP \(status))"
        case .authenticationChallenge:
            "EXO authentication challenge was refused"
        }
    }

    public var errorDescription: String? { description }
}

// MARK: - Exact endpoint and request mapping

struct EXOEndpoint: Sendable, Equatable {
    let rawValue: String
    let authority: String
    let baseURL: URL

    init(_ rawValue: String) throws {
        let portText: Substring
        let authority: String
        if rawValue.hasPrefix("http://127.0.0.1:") {
            portText = rawValue.dropFirst("http://127.0.0.1:".count)
            authority = "127.0.0.1:\(portText)"
        } else if rawValue.hasPrefix("http://[::1]:") {
            portText = rawValue.dropFirst("http://[::1]:".count)
            authority = "[::1]:\(portText)"
        } else {
            throw EXOFillingError.invalidEndpoint
        }
        guard !portText.isEmpty,
              portText.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              let port = UInt16(portText),
              port != 0,
              String(port) == portText,
              let url = URL(string: rawValue),
              url.absoluteString == rawValue
        else {
            throw EXOFillingError.invalidEndpoint
        }
        self.rawValue = rawValue
        self.authority = authority
        self.baseURL = url
    }

    func url(path: String) -> URL {
        // Construction follows exact validation; neither input can contain a
        // slash that Foundation can normalize into a different authority.
        URL(string: rawValue + path)!
    }
}

enum EXORequestEncoder {
    static func encode(_ request: WireGenerationRequest, modelID: String) throws -> Data {
        guard request.tools.isEmpty else {
            throw EXOFillingError.unsupportedRequest("offered tools")
        }
        guard request.schema == nil else {
            throw EXOFillingError.unsupportedRequest("response schema")
        }
        guard request.context.includeSchemaInPrompt != true else {
            throw EXOFillingError.unsupportedRequest("schema-in-prompt")
        }
        guard request.context.reasoning == nil else {
            throw EXOFillingError.unsupportedRequest("reasoning level")
        }
        guard request.options.toolCalling != .required else {
            throw EXOFillingError.unsupportedRequest("required tool calling without tools")
        }

        let entries = Array(request.transcript)
        guard entries.count <= EXOLimits.transcriptMessages else {
            throw EXOFillingError.requestLimit("transcript message count")
        }
        var messages: [[String: Any]] = []
        messages.reserveCapacity(entries.count)
        for entry in entries {
            let role: String
            let segments: [Transcript.Segment]
            switch entry {
            case .instructions(let value):
                guard value.toolDefinitions.isEmpty else {
                    throw EXOFillingError.unsupportedRequest("instruction tool definitions")
                }
                role = "system"
                segments = value.segments
            case .prompt(let value):
                role = "user"
                segments = value.segments
            case .response(let value):
                guard value.assetIDs.isEmpty else {
                    throw EXOFillingError.unsupportedRequest("response assets")
                }
                role = "assistant"
                segments = value.segments
            case .reasoning:
                throw EXOFillingError.unsupportedRequest("reasoning transcript")
            case .toolCalls, .toolOutput:
                throw EXOFillingError.unsupportedRequest("tool-bearing transcript")
            @unknown default:
                throw EXOFillingError.unsupportedRequest("unknown transcript entry")
            }
            var text = ""
            for segment in segments {
                guard case .text(let value) = segment else {
                    throw EXOFillingError.unsupportedRequest("non-text transcript segment")
                }
                text += value.content
                guard text.utf8.count <= EXOLimits.messageBytes else {
                    throw EXOFillingError.requestLimit("message UTF-8 bytes")
                }
            }
            messages.append(["content": text, "role": role])
        }

        let maximumTokens = request.options.maximumResponseTokens ?? 512
        guard (1 ... 16_384).contains(maximumTokens) else {
            throw EXOFillingError.invalidNumericOption("maximum response tokens")
        }
        if let temperature = request.options.temperature, !temperature.isFinite {
            throw EXOFillingError.invalidNumericOption("temperature")
        }

        var object: [String: Any] = [
            "enable_thinking": false,
            "max_tokens": maximumTokens,
            "messages": messages,
            "model": modelID,
            "n": 1,
            "stream": true,
            "stream_options": ["include_usage": true],
        ]
        if let temperature = request.options.temperature {
            object["temperature"] = temperature
        }
        switch request.options.sampling {
        case .greedy:
            if let temperature = request.options.temperature, temperature != 0 {
                throw EXOFillingError.invalidNumericOption("greedy temperature")
            }
            object["temperature"] = 0.0
        case .topK(let value, let seed):
            guard (1 ... 100_000).contains(value) else {
                throw EXOFillingError.invalidNumericOption("top-k")
            }
            object["top_k"] = value
            if let seed { object["seed"] = seed }
        case .topP(let value, let seed):
            guard value.isFinite, value > 0, value <= 1 else {
                throw EXOFillingError.invalidNumericOption("top-p")
            }
            object["top_p"] = value
            if let seed { object["seed"] = seed }
        case nil:
            break
        }
        do {
            return try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
        } catch {
            throw EXOFillingError.unsupportedRequest("request JSON encoding")
        }
    }
}

enum EXOLimits {
    static let transcriptMessages = 256
    static let messageBytes = 256 * 1024
    static let requestBodyBytes = 1024 * 1024
    static let catalogBytes = 1024 * 1024
    static let errorBodyBytes = 64 * 1024
    static let lineBytes = 256 * 1024
    static let eventBytes = 512 * 1024
    static let eventCount = 65_536
    static let generationBytes = 32 * 1024 * 1024
    static let handoffFragmentBytes = 64 * 1024
    static let transportControlEvents = 16
    static let transportBufferedEvents = generationBytes / handoffFragmentBytes
        + transportControlEvents
    static let parserBufferedFragments = 16

    static let second: Int64 = 1_000_000_000
    static let catalogDeadline = 10 * second
    static let headerDeadline = 15 * second
    static let idleDeadline = 60 * second
    static let generationDeadline = 30 * 60 * second
}

// MARK: - HTTP loading boundary

struct EXOHTTPResponseHead: Sendable, Equatable {
    var statusCode: Int
    var headers: [String: String]

    func header(_ name: String) -> String? {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

enum EXOHTTPEvent: Sendable, Equatable {
    case response(EXOHTTPResponseHead)
    case bytes(Data)
    case redirect(Int)
    case authenticationChallenge
    case complete
}

protocol EXOHTTPTasking: Sendable {
    func nextEvent() async throws -> EXOHTTPEvent?
    func cancel()
    func waitForTermination() async
}

protocol EXOHTTPLoading: Sendable {
    var startCount: Int { get }
    func start(_ request: URLRequest) -> any EXOHTTPTasking
}

struct EXOTransportBufferSnapshot: Sendable, Equatable {
    var peakBufferedEvents: Int
    var peakBufferedBytes: Int
    var enqueuedEvents: Int
    var overflowRefusals: Int
    var cancellationSignals: Int
    var streamFinished: Bool
    var taskTerminated: Bool
}

final class EXOURLSessionOperation: EXOHTTPTasking, @unchecked Sendable {
    private let bufferedEvents: Int
    private let maximumBufferedBytes: Int
    private let fragmentBytes: Int
    private let lock = NSLock()
    private var task: URLSessionDataTask?
    private var queue: [EXOHTTPEvent] = []
    private var bufferedBytes = 0
    private var streamFinished = false
    private var streamError: (any Error)?
    private var taskTerminated = false
    private var eventWaiter: CheckedContinuation<EXOHTTPEvent?, any Error>?
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var peakBufferedEvents = 0
    private var peakBufferedBytes = 0
    private var enqueuedEvents = 0
    private var overflowRefusals = 0
    private var cancellationSignals = 0
    private var didSignalCancellation = false

    init(
        bufferedEvents: Int = EXOLimits.transportBufferedEvents,
        maximumBufferedBytes: Int = EXOLimits.generationBytes,
        fragmentBytes: Int = EXOLimits.handoffFragmentBytes
    ) {
        precondition(bufferedEvents > 0)
        precondition(maximumBufferedBytes > 0)
        precondition(fragmentBytes > 0)
        self.bufferedEvents = bufferedEvents
        self.maximumBufferedBytes = maximumBufferedBytes
        self.fragmentBytes = fragmentBytes
    }

    func attach(_ task: URLSessionDataTask) {
        lock.lock()
        self.task = task
        lock.unlock()
    }

    @discardableResult
    func send(_ event: EXOHTTPEvent) -> Bool {
        if case .bytes(let data) = event, data.isEmpty { return true }
        let receiver: CheckedContinuation<EXOHTTPEvent?, any Error>?
        let directEvent: EXOHTTPEvent?
        let overflowError: EXOFillingError?
        lock.lock()
        guard !streamFinished else {
            lock.unlock()
            return false
        }

        switch event {
        case .bytes(let data):
            let directCount = eventWaiter != nil && queue.isEmpty
                ? min(data.count, fragmentBytes)
                : 0
            let remainingCount = data.count - directCount
            let tailCapacity: Int = if case .bytes(let tail)? = queue.last {
                max(0, fragmentBytes - tail.count)
            } else {
                0
            }
            let afterTail = max(0, remainingCount - tailCapacity)
            let newFragments = afterTail / fragmentBytes
                + (afterTail % fragmentBytes == 0 ? 0 : 1)
            let byteOverflow = remainingCount > maximumBufferedBytes - bufferedBytes
            let eventOverflow = newFragments > bufferedEvents - queue.count
            if byteOverflow || eventOverflow {
                overflowRefusals += 1
                streamFinished = true
                let error = EXOFillingError.responseLimit("transport event buffer")
                streamError = error
                receiver = eventWaiter
                eventWaiter = nil
                directEvent = nil
                overflowError = error
            } else {
                receiver = eventWaiter
                eventWaiter = nil
                if directCount > 0 {
                    directEvent = .bytes(Data(data.prefix(directCount)))
                    enqueuedEvents += 1
                } else {
                    directEvent = nil
                }
                appendBytesLocked(data, from: directCount)
                overflowError = nil
            }
        default:
            if let eventWaiter, queue.isEmpty {
                receiver = eventWaiter
                self.eventWaiter = nil
                directEvent = event
                enqueuedEvents += 1
                overflowError = nil
            } else if queue.count < bufferedEvents {
                queue.append(event)
                enqueuedEvents += 1
                peakBufferedEvents = max(peakBufferedEvents, queue.count)
                receiver = nil
                directEvent = nil
                overflowError = nil
            } else {
                overflowRefusals += 1
                streamFinished = true
                let error = EXOFillingError.responseLimit("transport event buffer")
                streamError = error
                receiver = eventWaiter
                eventWaiter = nil
                directEvent = nil
                overflowError = error
            }
        }
        lock.unlock()

        if let overflowError {
            receiver?.resume(throwing: overflowError)
            signalCancellation()
            return false
        }
        if let directEvent { receiver?.resume(returning: directEvent) }
        return true
    }

    private func appendBytesLocked(_ data: Data, from initialOffset: Int) {
        var offset = initialOffset
        if offset < data.count,
           !queue.isEmpty,
           case .bytes(var tail) = queue[queue.count - 1],
           tail.count < fragmentBytes
        {
            let end = min(offset + fragmentBytes - tail.count, data.count)
            tail.append(contentsOf: data[offset ..< end])
            queue[queue.count - 1] = .bytes(tail)
            bufferedBytes += end - offset
            offset = end
        }
        while offset < data.count {
            let end = min(offset + fragmentBytes, data.count)
            queue.append(.bytes(Data(data[offset ..< end])))
            enqueuedEvents += 1
            bufferedBytes += end - offset
            offset = end
        }
        peakBufferedEvents = max(peakBufferedEvents, queue.count)
        peakBufferedBytes = max(peakBufferedBytes, bufferedBytes)
    }

    func refuse(_ error: any Error) {
        let receiver: CheckedContinuation<EXOHTTPEvent?, any Error>?
        lock.lock()
        guard !streamFinished else {
            lock.unlock()
            signalCancellation()
            return
        }
        streamFinished = true
        streamError = error
        receiver = queue.isEmpty ? eventWaiter : nil
        if receiver != nil { eventWaiter = nil }
        lock.unlock()
        receiver?.resume(throwing: error)
        signalCancellation()
    }

    func taskDidComplete(_ error: (any Error)? = nil) {
        let receiver: CheckedContinuation<EXOHTTPEvent?, any Error>?
        let terminalError: (any Error)?
        let resumed: [CheckedContinuation<Void, Never>]
        lock.lock()
        guard !taskTerminated else {
            lock.unlock()
            return
        }
        taskTerminated = true
        if !streamFinished {
            streamFinished = true
            streamError = error
        }
        terminalError = streamError
        receiver = queue.isEmpty ? eventWaiter : nil
        if receiver != nil { eventWaiter = nil }
        resumed = waiters
        waiters.removeAll()
        lock.unlock()
        if let terminalError { receiver?.resume(throwing: terminalError) }
        else { receiver?.resume(returning: nil) }
        resumed.forEach { $0.resume() }
    }

    func nextEvent() async throws -> EXOHTTPEvent? {
        try await withCheckedThrowingContinuation { continuation in
            let event: EXOHTTPEvent?
            let error: (any Error)?
            let isFinished: Bool
            lock.lock()
            if !queue.isEmpty {
                event = queue.removeFirst()
                if case .bytes(let data)? = event { bufferedBytes -= data.count }
                error = nil
                isFinished = false
            } else if streamFinished {
                event = nil
                error = streamError
                isFinished = true
            } else {
                precondition(eventWaiter == nil)
                eventWaiter = continuation
                lock.unlock()
                return
            }
            lock.unlock()
            if let event { continuation.resume(returning: event) }
            else if let error { continuation.resume(throwing: error) }
            else if isFinished { continuation.resume(returning: nil) }
        }
    }

    func cancel() {
        signalCancellation()
    }

    private func signalCancellation() {
        lock.lock()
        guard !didSignalCancellation else {
            lock.unlock()
            return
        }
        didSignalCancellation = true
        let task = self.task
        cancellationSignals += 1
        lock.unlock()
        task?.cancel()
    }

    var bufferSnapshot: EXOTransportBufferSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return .init(
            peakBufferedEvents: peakBufferedEvents,
            peakBufferedBytes: peakBufferedBytes,
            enqueuedEvents: enqueuedEvents,
            overflowRefusals: overflowRefusals,
            cancellationSignals: cancellationSignals,
            streamFinished: streamFinished,
            taskTerminated: taskTerminated
        )
    }

    func waitForTermination() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if taskTerminated {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }
}

struct EXOBodyPipeSnapshot: Sendable, Equatable {
    var bufferedFragments: Int
    var bufferedBytes: Int
    var peakBufferedFragments: Int
    var peakBufferedBytes: Int
    var acceptedFragments: Int
    var sendWaits: Int
}

actor EXOBoundedBodyPipe {
    private let bufferedFragments: Int
    private let fragmentBytes: Int
    private var queue: [Data] = []
    private var finished = false
    private var peakBufferedFragments = 0
    private var peakBufferedBytes = 0
    private var acceptedFragments = 0
    private var sendWaits = 0
    private var receiver: CheckedContinuation<Data?, Never>?
    private var senderWaiter: CheckedContinuation<Void, Never>?

    init(
        bufferedFragments: Int = EXOLimits.parserBufferedFragments,
        fragmentBytes: Int = EXOLimits.handoffFragmentBytes
    ) {
        precondition(bufferedFragments > 0)
        precondition(fragmentBytes > 0)
        self.bufferedFragments = bufferedFragments
        self.fragmentBytes = fragmentBytes
    }

    @discardableResult
    func send(_ data: Data) async -> Bool {
        guard !data.isEmpty else { return true }
        var offset = 0
        while offset < data.count {
            guard !finished else { return false }

            if let receiver {
                let end = min(offset + fragmentBytes, data.count)
                self.receiver = nil
                acceptedFragments += 1
                receiver.resume(returning: Data(data[offset ..< end]))
                offset = end
                continue
            }

            if !queue.isEmpty, queue[queue.count - 1].count < fragmentBytes {
                let available = fragmentBytes - queue[queue.count - 1].count
                let end = min(offset + available, data.count)
                queue[queue.count - 1].append(contentsOf: data[offset ..< end])
                peakBufferedBytes = max(
                    peakBufferedBytes,
                    queue.reduce(0) { $0 + $1.count }
                )
                offset = end
                continue
            }

            if queue.count < bufferedFragments {
                let end = min(offset + fragmentBytes, data.count)
                queue.append(Data(data[offset ..< end]))
                acceptedFragments += 1
                peakBufferedFragments = max(peakBufferedFragments, queue.count)
                peakBufferedBytes = max(
                    peakBufferedBytes,
                    queue.reduce(0) { $0 + $1.count }
                )
                offset = end
                continue
            }

            sendWaits += 1
            await withCheckedContinuation { continuation in
                precondition(senderWaiter == nil)
                senderWaiter = continuation
            }
        }
        return true
    }

    func next() async -> Data? {
        if !queue.isEmpty {
            let fragment = queue.removeFirst()
            let sender = senderWaiter
            senderWaiter = nil
            sender?.resume()
            return fragment
        }
        if finished { return nil }
        return await withCheckedContinuation { continuation in
            precondition(receiver == nil)
            receiver = continuation
        }
    }

    func finish() {
        guard !finished else { return }
        finished = true
        if queue.isEmpty {
            let receiver = self.receiver
            self.receiver = nil
            receiver?.resume(returning: nil)
        }
        let sender = senderWaiter
        senderWaiter = nil
        sender?.resume()
    }

    var snapshot: EXOBodyPipeSnapshot {
        return .init(
            bufferedFragments: queue.count,
            bufferedBytes: queue.reduce(0) { $0 + $1.count },
            peakBufferedFragments: peakBufferedFragments,
            peakBufferedBytes: peakBufferedBytes,
            acceptedFragments: acceptedFragments,
            sendWaits: sendWaits
        )
    }
}

final class EXOSessionDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var operations: [Int: EXOURLSessionOperation] = [:]

    func register(_ operation: EXOURLSessionOperation, for task: URLSessionTask) {
        lock.lock()
        operations[task.taskIdentifier] = operation
        lock.unlock()
    }

    private func operation(for task: URLSessionTask) -> EXOURLSessionOperation? {
        lock.lock()
        defer { lock.unlock() }
        return operations[task.taskIdentifier]
    }

    private func removeOperation(for task: URLSessionTask) -> EXOURLSessionOperation? {
        lock.lock()
        defer { lock.unlock() }
        return operations.removeValue(forKey: task.taskIdentifier)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let response = response as? HTTPURLResponse else {
            operation(for: dataTask)?.refuse(EXOFillingError.transport("response was not HTTP"))
            completionHandler(.cancel)
            return
        }
        let headers = response.allHeaderFields.reduce(into: [String: String]()) { result, entry in
            result[String(describing: entry.key)] = String(describing: entry.value)
        }
        guard operation(for: dataTask)?.send(.response(.init(
            statusCode: response.statusCode,
            headers: headers
        ))) == true else {
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        operation(for: dataTask)?.send(.bytes(data))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        operation(for: task)?.send(.redirect(response.statusCode))
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        operation(for: task)?.send(.authenticationChallenge)
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: (any Error)?
    ) {
        guard let operation = removeOperation(for: task) else { return }
        if error == nil {
            operation.send(.complete)
        }
        operation.taskDidComplete(error)
    }
}

final class EXOURLSessionLoader: EXOHTTPLoading, @unchecked Sendable {
    let configuration: URLSessionConfiguration
    let delegate: EXOSessionDelegate
    private let session: URLSession
    private let lock = NSLock()
    private var starts = 0

    init(configuration: URLSessionConfiguration, delegate: EXOSessionDelegate) {
        self.configuration = configuration
        self.delegate = delegate
        self.session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    var startCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return starts
    }

    func start(_ request: URLRequest) -> any EXOHTTPTasking {
        let operation = EXOURLSessionOperation()
        let task = session.dataTask(with: request)
        operation.attach(task)
        delegate.register(operation, for: task)
        lock.lock()
        starts += 1
        lock.unlock()
        task.resume()
        return operation
    }
}

// MARK: - Clock, cancellation, and quiescence

protocol EXOClock: Sendable {
    func now() async -> Int64
    func sleep(until deadline: Int64) async throws
}

struct EXOContinuousClock: EXOClock, Sendable {
    private let clock = ContinuousClock()
    private let origin: ContinuousClock.Instant

    init() {
        origin = clock.now
    }

    func now() async -> Int64 {
        let components = origin.duration(to: clock.now).components
        let (seconds, secondsOverflow) = components.seconds.multipliedReportingOverflow(by: EXOLimits.second)
        if secondsOverflow { return Int64.max }
        let nanoseconds = components.attoseconds / 1_000_000_000
        let (value, overflow) = seconds.addingReportingOverflow(nanoseconds)
        return overflow ? Int64.max : value
    }

    func sleep(until deadline: Int64) async throws {
        let current = await now()
        if current < deadline {
            try await Task.sleep(for: .nanoseconds(deadline - current))
        }
    }
}

enum EXOChildKind: String, Sendable, Hashable {
    case settlement
    case urlTask
    case reader
    case parser
    case catalogTimer
    case headerTimer
    case idleTimer
    case totalTimer
}

struct EXOOperationSnapshot: Sendable, Equatable {
    var started: [EXOChildKind: Int]
    var terminated: [EXOChildKind: Int]
    var cancelled: [EXOChildKind: Int]
    var idleDeadlineResets: Int
    var idleDeadlineChecks: Int
    var outcome: String?
    var outcomes: Int
    var terminalEmissions: Int
    var postSettlementCandidates: Int

    var survivorCount: Int {
        started.values.reduce(0, +) - terminated.values.reduce(0, +)
    }
}

final class EXOOperationTestProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var startedCounts: [EXOChildKind: Int] = [:]
    private var terminatedCounts: [EXOChildKind: Int] = [:]
    private var cancelledCounts: [EXOChildKind: Int] = [:]
    private var idleResetCount = 0
    private var idleCheckCount = 0
    private var outcomeValue: String?
    private var outcomeCount = 0
    private var terminalCount = 0
    private var postCount = 0
    private var isSettled = false
    private var waiters: [CheckedContinuation<EXOOperationSnapshot, Never>] = []

    func started(_ kind: EXOChildKind) {
        lock.lock()
        startedCounts[kind, default: 0] += 1
        lock.unlock()
    }

    func terminated(_ kind: EXOChildKind) {
        lock.lock()
        terminatedCounts[kind, default: 0] += 1
        lock.unlock()
    }

    func cancelled(_ kind: EXOChildKind) {
        lock.lock()
        cancelledCounts[kind, default: 0] += 1
        lock.unlock()
    }

    func idleDeadlineReset() {
        lock.lock()
        idleResetCount += 1
        lock.unlock()
    }

    func idleDeadlineChecked() {
        lock.lock()
        idleCheckCount += 1
        lock.unlock()
    }

    func record(outcome: String) {
        lock.lock()
        outcomeValue = outcome
        outcomeCount += 1
        lock.unlock()
    }

    func terminalEmitted() {
        lock.lock()
        terminalCount += 1
        lock.unlock()
    }

    func postSettlementCandidate() {
        lock.lock()
        postCount += 1
        lock.unlock()
    }

    func settled() {
        let resumed: [(CheckedContinuation<EXOOperationSnapshot, Never>, EXOOperationSnapshot)]
        lock.lock()
        isSettled = true
        let snapshot = snapshotLocked()
        resumed = waiters.map { ($0, snapshot) }
        waiters.removeAll()
        lock.unlock()
        resumed.forEach { $0.0.resume(returning: $0.1) }
    }

    func snapshot() -> EXOOperationSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshotLocked()
    }

    func waitForQuiescence() async -> EXOOperationSnapshot {
        await withCheckedContinuation { continuation in
            lock.lock()
            if isSettled {
                let snapshot = snapshotLocked()
                lock.unlock()
                continuation.resume(returning: snapshot)
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    private func snapshotLocked() -> EXOOperationSnapshot {
        .init(
            started: startedCounts,
            terminated: terminatedCounts,
            cancelled: cancelledCounts,
            idleDeadlineResets: idleResetCount,
            idleDeadlineChecks: idleCheckCount,
            outcome: outcomeValue,
            outcomes: outcomeCount,
            terminalEmissions: terminalCount,
            postSettlementCandidates: postCount
        )
    }
}

final class EXOCancelOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var didCancel = false
    private let kind: EXOChildKind
    private let probe: EXOOperationTestProbe?
    private let action: @Sendable () -> Void

    init(kind: EXOChildKind, probe: EXOOperationTestProbe?, action: @escaping @Sendable () -> Void) {
        self.kind = kind
        self.probe = probe
        self.action = action
    }

    func cancel() {
        lock.lock()
        guard !didCancel else {
            lock.unlock()
            return
        }
        didCancel = true
        lock.unlock()
        probe?.cancelled(kind)
        action()
    }

    func matches(_ kind: EXOChildKind) -> Bool {
        self.kind == kind
    }
}

final class EXOCancellationRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded = false
    private var callbacks: [@Sendable () -> Void] = []
    private var wake: (@Sendable () -> Void)?

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    var callbackCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return callbacks.count
    }

    func install(_ callback: @escaping @Sendable () -> Void) {
        lock.lock()
        if recorded {
            lock.unlock()
            callback()
        } else {
            callbacks.append(callback)
            lock.unlock()
        }
    }

    func setWake(_ callback: @escaping @Sendable () -> Void) {
        lock.lock()
        if recorded {
            lock.unlock()
            callback()
        } else {
            wake = callback
            lock.unlock()
        }
    }

    func cancel() {
        let callbacks: [@Sendable () -> Void]
        let wake: (@Sendable () -> Void)?
        lock.lock()
        guard !recorded else {
            lock.unlock()
            return
        }
        recorded = true
        callbacks = self.callbacks
        self.callbacks.removeAll()
        wake = self.wake
        lock.unlock()
        callbacks.forEach { $0() }
        wake?()
    }

    func releaseCallbacks() {
        lock.lock()
        callbacks.removeAll()
        wake = nil
        lock.unlock()
    }
}

final class EXOSettlementRetention: @unchecked Sendable {
    var task: Task<Void, Never>?
}

// MARK: - Operation coordinator

enum EXOOperationMode: Sendable {
    case catalog(modelID: String)
    case generation(modelID: String)
}

struct EXOTerminalResult: Sendable, Equatable {
    var usage: EXOUsage?
}

enum EXOOperationOutcome: Sendable {
    case success(EXOTerminalResult)
    case failure(EXOFillingError)
    case cancelled

    var label: String {
        switch self {
        case .success: "success"
        case .failure: "failure"
        case .cancelled: "cancelled"
        }
    }
}

private enum EXOBodyKind: Sendable {
    case catalog(modelID: String)
    case generation(modelID: String)
    case error(status: Int)
}

struct EXOCoordinatorOwnershipSnapshot: Sendable, Equatable {
    var timerTasks: Int
    var childCancels: Int
    var cancellationCallbacks: Int
    var bodyPeakBufferedFragments: Int
    var bodyPeakBufferedBytes: Int
    var bodySendWaits: Int
    var outcome: String?
}

actor EXOOperationCoordinator {
    private let mode: EXOOperationMode
    private let loader: any EXOHTTPLoading
    private let clock: any EXOClock
    private let cancellation: EXOCancellationRegistry
    private let probe: EXOOperationTestProbe?
    private let emit: (@Sendable (WireEvent) -> Bool)?

    private var operation: (any EXOHTTPTasking)?
    private var operationCancel: EXOCancelOnce?
    private var readerTask: Task<Void, Never>?
    private var parserTask: Task<Void, Never>?
    private var idleTimerTask: Task<Void, Never>?
    private var timerTasks: [Task<Void, Never>] = []
    private var childCancels: [EXOCancelOnce] = []
    private var bodyPipe: EXOBoundedBodyPipe?
    private var responseSeen = false
    private var responseStatus: Int?
    private var successfulGenerationResponse = false
    private var loaderCompleted = false
    private var bodyBytes = 0
    private var startTime: Int64 = 0
    private var headerDeadline: Int64?
    private var totalDeadline: Int64 = 0
    private var idleDeadline: Int64?
    private var outcome: EXOOperationOutcome?
    private var outcomeWaiter: CheckedContinuation<EXOOperationOutcome, Never>?

    init(
        mode: EXOOperationMode,
        loader: any EXOHTTPLoading,
        clock: any EXOClock,
        cancellation: EXOCancellationRegistry,
        probe: EXOOperationTestProbe?,
        emit: (@Sendable (WireEvent) -> Bool)?
    ) {
        self.mode = mode
        self.loader = loader
        self.clock = clock
        self.cancellation = cancellation
        self.probe = probe
        self.emit = emit
    }

    func run(request: URLRequest) async -> EXOOperationOutcome {
        startTime = await clock.now()
        switch mode {
        case .catalog:
            totalDeadline = startTime + EXOLimits.catalogDeadline
        case .generation:
            headerDeadline = startTime + EXOLimits.headerDeadline
            totalDeadline = startTime + EXOLimits.generationDeadline
        }
        if cancellation.isCancelled {
            commit(.cancelled)
        } else {
            startLoader(request)
            switch mode {
            case .catalog:
                startTimer(kind: .catalogTimer, deadline: totalDeadline)
            case .generation:
                if let headerDeadline { startTimer(kind: .headerTimer, deadline: headerDeadline) }
                startTimer(kind: .totalTimer, deadline: totalDeadline)
            }
        }
        let outcome = await waitForOutcome()
        await cleanUp(for: outcome)
        return outcome
    }

    func consumerCancelled() {
        guard outcome == nil else {
            probe?.postSettlementCandidate()
            return
        }
        commit(.cancelled)
    }

    func ownershipSnapshot() async -> EXOCoordinatorOwnershipSnapshot {
        let bodySnapshot: EXOBodyPipeSnapshot?
        if let bodyPipe { bodySnapshot = await bodyPipe.snapshot }
        else { bodySnapshot = nil }
        return .init(
            timerTasks: timerTasks.count,
            childCancels: childCancels.count,
            cancellationCallbacks: cancellation.callbackCount,
            bodyPeakBufferedFragments: bodySnapshot?.peakBufferedFragments ?? 0,
            bodyPeakBufferedBytes: bodySnapshot?.peakBufferedBytes ?? 0,
            bodySendWaits: bodySnapshot?.sendWaits ?? 0,
            outcome: outcome?.label
        )
    }

    private func startLoader(_ request: URLRequest) {
        let operation = loader.start(request)
        self.operation = operation
        probe?.started(.urlTask)
        let operationCancel = EXOCancelOnce(kind: .urlTask, probe: probe) {
            operation.cancel()
        }
        self.operationCancel = operationCancel
        cancellation.install { operationCancel.cancel() }

        probe?.started(.reader)
        let task = Task { [operation, probe] in
            defer { probe?.terminated(.reader) }
            do {
                while let event = try await operation.nextEvent() {
                    if Task.isCancelled { break }
                    await self.receive(event)
                }
                await self.readerEnded()
            } catch {
                await self.readerFailed(error)
            }
        }
        readerTask = task
        let cancel = EXOCancelOnce(kind: .reader, probe: probe) { task.cancel() }
        childCancels.append(cancel)
        cancellation.install { cancel.cancel() }
    }

    private func startTimer(kind: EXOChildKind, deadline: Int64) {
        probe?.started(kind)
        let task = Task { [clock, probe] in
            defer { probe?.terminated(kind) }
            do {
                try await clock.sleep(until: deadline)
            } catch {
                return
            }
            await self.deadlineFired()
        }
        timerTasks.append(task)
        let cancel = EXOCancelOnce(kind: kind, probe: probe) { task.cancel() }
        childCancels.append(cancel)
        cancellation.install { cancel.cancel() }
    }

    private func startIdleWatchdog() {
        guard idleTimerTask == nil else { return }
        probe?.started(.idleTimer)
        let task = Task { [clock, probe] in
            defer { probe?.terminated(.idleTimer) }
            while !Task.isCancelled {
                guard let deadline = self.currentIdleDeadline() else { return }
                do {
                    try await clock.sleep(until: deadline)
                } catch {
                    return
                }
                if await self.idleWatchdogFired() { return }
            }
        }
        idleTimerTask = task
        timerTasks.append(task)
        let cancel = EXOCancelOnce(kind: .idleTimer, probe: probe) { task.cancel() }
        childCancels.append(cancel)
        cancellation.install { cancel.cancel() }
    }

    private func currentIdleDeadline() -> Int64? {
        guard outcome == nil else { return nil }
        return idleDeadline
    }

    private func idleWatchdogFired() async -> Bool {
        probe?.idleDeadlineChecked()
        let now = await clock.now()
        _ = acceptCandidate(at: now)
        return outcome != nil
    }

    private func startBodyParser(_ kind: EXOBodyKind) {
        let pipe = EXOBoundedBodyPipe()
        bodyPipe = pipe
        probe?.started(.parser)
        let task = Task { [probe] in
            defer { probe?.terminated(.parser) }
            do {
                switch kind {
                case .catalog(let modelID):
                    var data = Data()
                    while let chunk = await pipe.next() {
                        if Task.isCancelled { return }
                        data.append(chunk)
                    }
                    try EXOCatalogParser.validate(data, modelID: modelID)
                    await self.parserFinished(.init(usage: nil))
                case .error(let status):
                    var data = Data()
                    while let chunk = await pipe.next() {
                        if Task.isCancelled { return }
                        data.append(chunk)
                    }
                    await self.parserFailed(.httpStatus(status, EXOText.sanitized(data)))
                case .generation(let modelID):
                    var parser = EXOSSEParser(modelID: modelID)
                    while let chunk = await pipe.next() {
                        if Task.isCancelled { return }
                        let batch = parser.consume(chunk)
                        for event in batch.events {
                            await self.parserEmitted(event)
                        }
                        if let error = batch.error { throw error }
                    }
                    await self.parserFinished(try parser.finish())
                }
            } catch let error as EXOFillingError {
                await self.parserFailed(error)
            } catch {
                await self.parserFailed(.transport(EXOText.sanitized(String(describing: error))))
            }
        }
        parserTask = task
        let cancel = EXOCancelOnce(kind: .parser, probe: probe) {
            task.cancel()
        }
        childCancels.append(cancel)
        cancellation.install { cancel.cancel() }
    }

    private func receive(_ event: EXOHTTPEvent) async {
        let now = await clock.now()
        guard acceptCandidate(at: now) else { return }
        switch event {
        case .response(let head):
            guard !responseSeen else {
                commit(.failure(.protocolContradiction("duplicate HTTP response headers")))
                return
            }
            responseSeen = true
            responseStatus = head.statusCode
            cancelChildren(kind: .headerTimer)
            if head.statusCode != 200 {
                startBodyParser(.error(status: head.statusCode))
                return
            }
            switch mode {
            case .catalog(let modelID):
                guard EXOMediaType.matches(head.header("Content-Type"), expected: "application/json") else {
                    commit(.failure(.contentType(
                        expected: "application/json",
                        actual: head.header("Content-Type")
                    )))
                    return
                }
                startBodyParser(.catalog(modelID: modelID))
            case .generation(let modelID):
                guard EXOMediaType.matches(head.header("Content-Type"), expected: "text/event-stream") else {
                    commit(.failure(.contentType(
                        expected: "text/event-stream",
                        actual: head.header("Content-Type")
                    )))
                    return
                }
                successfulGenerationResponse = true
                startBodyParser(.generation(modelID: modelID))
                resetIdleDeadline(from: now)
            }
        case .bytes(let data):
            guard responseSeen, let bodyPipe else {
                commit(.failure(.protocolContradiction("body bytes arrived before accepted headers")))
                return
            }
            guard !data.isEmpty else { return }
            let maximum: Int
            if responseStatus != 200 {
                maximum = EXOLimits.errorBodyBytes
            } else {
                switch mode {
                case .catalog:
                    maximum = EXOLimits.catalogBytes
                case .generation:
                    maximum = EXOLimits.generationBytes
                }
            }
            let (next, overflow) = bodyBytes.addingReportingOverflow(data.count)
            if overflow || next > maximum {
                commit(.failure(.responseLimit(
                    maximum == EXOLimits.errorBodyBytes
                        ? "non-200 error body bytes"
                        : maximum == EXOLimits.catalogBytes
                            ? "model catalog bytes"
                            : "generation bytes"
                )))
                return
            }
            bodyBytes = next
            if successfulGenerationResponse { resetIdleDeadline(from: now) }
            if !(await bodyPipe.send(data)) {
                commit(.failure(.protocolContradiction("body parser handoff closed early")))
            }
        case .redirect(let status):
            commit(.failure(.redirect(status)))
        case .authenticationChallenge:
            commit(.failure(.authenticationChallenge))
        case .complete:
            loaderCompleted = true
            guard responseSeen else {
                commit(.failure(.transport("request ended before HTTP response headers")))
                return
            }
            await bodyPipe?.finish()
        }
    }

    private func resetIdleDeadline(from now: Int64) {
        idleDeadline = now + EXOLimits.idleDeadline
        probe?.idleDeadlineReset()
        startIdleWatchdog()
    }

    private func cancelChildren(kind: EXOChildKind) {
        // Cancelling an already-finished child is harmless and the one-shot
        // wrapper keeps every cleanup signal exact.
        for cancel in childCancels where cancel.matches(kind) {
            cancel.cancel()
        }
    }

    private func parserEmitted(_ event: WireEvent) async {
        let now = await clock.now()
        guard acceptCandidate(at: now) else { return }
        guard emit?(event) ?? false else {
            cancellation.cancel()
            commit(.cancelled)
            return
        }
    }

    private func parserFinished(_ terminal: EXOTerminalResult) async {
        let now = await clock.now()
        guard acceptCandidate(at: now) else { return }
        guard loaderCompleted else {
            commit(.failure(.protocolContradiction("parser settled before loader completion")))
            return
        }
        commit(.success(terminal))
    }

    private func parserFailed(_ error: EXOFillingError) async {
        let now = await clock.now()
        guard acceptCandidate(at: now) else { return }
        commit(.failure(error))
    }

    private func readerFailed(_ error: any Error) async {
        let now = await clock.now()
        guard acceptCandidate(at: now) else { return }
        if let error = error as? EXOFillingError {
            commit(.failure(error))
        } else if error is CancellationError || (error as? URLError)?.code == .cancelled {
            if cancellation.isCancelled { commit(.cancelled) }
            else { commit(.failure(.transport("URL task was cancelled"))) }
        } else {
            commit(.failure(.transport(EXOText.sanitized(String(describing: error)))))
        }
    }

    private func readerEnded() async {
        let now = await clock.now()
        guard acceptCandidate(at: now) else { return }
        if !loaderCompleted {
            commit(.failure(.transport("loader ended without completion")))
        }
    }

    private func deadlineFired() async {
        let now = await clock.now()
        _ = acceptCandidate(at: now)
    }

    private func acceptCandidate(at now: Int64) -> Bool {
        if outcome != nil {
            probe?.postSettlementCandidate()
            return false
        }
        if cancellation.isCancelled {
            commit(.cancelled)
            return false
        }
        if now >= totalDeadline {
            let name = switch mode {
            case .catalog: "catalog total"
            case .generation: "generation total"
            }
            commit(.failure(.timeout(name)))
            return false
        }
        if let headerDeadline, !responseSeen, now >= headerDeadline {
            commit(.failure(.timeout("generation response headers")))
            return false
        }
        if let idleDeadline, now >= idleDeadline {
            commit(.failure(.timeout("generation idle")))
            return false
        }
        return true
    }

    private func commit(_ result: EXOOperationOutcome) {
        guard outcome == nil else {
            probe?.postSettlementCandidate()
            return
        }
        outcome = result
        outcomeWaiter?.resume(returning: result)
        outcomeWaiter = nil
    }

    private func waitForOutcome() async -> EXOOperationOutcome {
        if let outcome { return outcome }
        return await withCheckedContinuation { continuation in
            if let outcome {
                continuation.resume(returning: outcome)
            } else {
                outcomeWaiter = continuation
            }
        }
    }

    private func cleanUp(for outcome: EXOOperationOutcome) async {
        await bodyPipe?.finish()
        let shouldCancelURL: Bool = switch outcome {
        case .success: false
        case .failure, .cancelled: !loaderCompleted
        }
        if shouldCancelURL { operationCancel?.cancel() }
        childCancels.forEach { $0.cancel() }
        if let readerTask { await readerTask.value }
        if let parserTask { await parserTask.value }
        for timer in timerTasks { await timer.value }
        if let operation {
            await operation.waitForTermination()
            probe?.terminated(.urlTask)
        }
        cancellation.releaseCallbacks()
        operation = nil
        operationCancel = nil
        readerTask = nil
        parserTask = nil
        idleTimerTask = nil
        timerTasks.removeAll()
        childCancels.removeAll()
        bodyPipe = nil
    }
}

// MARK: - Catalog and stream parsing

enum EXOMediaType {
    static func matches(_ value: String?, expected: String) -> Bool {
        guard let value else { return false }
        let parts = value.split(separator: ";", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 1 || parts.count == 2,
              parts[0].caseInsensitiveCompare(expected) == .orderedSame
        else { return false }
        if parts.count == 2 {
            let parameter = parts[1]
            guard parameter.lowercased().hasPrefix("charset="),
                  !parameter.dropFirst("charset=".count).isEmpty
            else { return false }
        }
        return true
    }
}

enum EXOCatalogParser {
    static func validate(_ data: Data, modelID: String) throws {
        guard data.count <= EXOLimits.catalogBytes else {
            throw EXOFillingError.responseLimit("model catalog bytes")
        }
        guard String(data: data, encoding: .utf8) != nil else {
            throw EXOFillingError.malformedCatalog("body is not UTF-8")
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw EXOFillingError.malformedCatalog("body is not one JSON object")
        }
        guard let root = object as? [String: Any], root["object"] as? String == "list" else {
            throw EXOFillingError.malformedCatalog("top-level object marker is not list")
        }
        guard let records = root["data"] as? [Any] else {
            throw EXOFillingError.malformedCatalog("data is not an array")
        }
        var seen: Set<String> = []
        var matches = 0
        for value in records {
            guard let record = value as? [String: Any],
                  let id = record["id"] as? String,
                  !id.isEmpty
            else {
                throw EXOFillingError.malformedCatalog("model record has no nonempty string id")
            }
            guard seen.insert(id).inserted else {
                throw EXOFillingError.protocolContradiction("duplicate model id in catalog")
            }
            if id == modelID { matches += 1 }
        }
        guard matches == 1 else { throw EXOFillingError.modelUnavailable(modelID) }
    }
}

struct EXOUsage: Sendable, Equatable {
    var inputTokens: Int
    var outputTokens: Int
}

struct EXOSSEFeedResult: Sendable {
    var events: [WireEvent]
    var error: EXOFillingError?
}

struct EXOSSEParser: Sendable {
    private enum State: Sendable { case open, streaming, terminal, done, settled }

    private let modelID: String
    private var state: State = .open
    private var lineBuffer = Data()
    private var eventData: Data?
    private var eventHasLine = false
    private var eventByteCount = 0
    private var events = 0
    private var commandID: String?
    private var terminalUsage: EXOUsage?

    init(modelID: String) {
        self.modelID = modelID
    }

    /// Preserves complete events that precede a malformed event in the same
    /// transport chunk. The coordinator emits this prefix before committing
    /// the error, so packet coalescing cannot alter stream behavior.
    mutating func consume(_ data: Data) -> EXOSSEFeedResult {
        var emitted: [WireEvent] = []
        do {
            try process(data, emitted: &emitted)
            return .init(events: emitted, error: nil)
        } catch let error as EXOFillingError {
            return .init(events: emitted, error: error)
        } catch {
            return .init(
                events: emitted,
                error: .malformedStream("unexpected parser failure")
            )
        }
    }

    mutating func feed(_ data: Data) throws -> [WireEvent] {
        let result = consume(data)
        if let error = result.error { throw error }
        return result.events
    }

    private mutating func process(_ data: Data, emitted: inout [WireEvent]) throws {
        guard state != .done, state != .settled else {
            if data.isEmpty { return }
            throw EXOFillingError.malformedStream("bytes followed [DONE]")
        }
        lineBuffer.append(data)
        while let newline = lineBuffer.firstIndex(of: 0x0A) {
            var line = Data(lineBuffer[..<newline])
            lineBuffer.removeSubrange(...newline)
            if line.last == 0x0D { line.removeLast() }
            guard !line.contains(0x0D) else {
                throw EXOFillingError.malformedStream("bare carriage return")
            }
            guard line.count <= EXOLimits.lineBytes else {
                throw EXOFillingError.responseLimit("SSE line bytes")
            }
            if line.isEmpty {
                if eventHasLine {
                    if eventData != nil {
                        events += 1
                        guard events <= EXOLimits.eventCount else {
                            throw EXOFillingError.responseLimit("SSE event count")
                        }
                    }
                    emitted.append(contentsOf: try finishEvent())
                }
                resetEvent()
                if state == .done, !lineBuffer.isEmpty {
                    throw EXOFillingError.malformedStream("bytes followed [DONE]")
                }
                continue
            }
            eventHasLine = true
            eventByteCount += line.count + 1
            guard eventByteCount <= EXOLimits.eventBytes else {
                throw EXOFillingError.responseLimit("SSE event bytes")
            }
            guard String(data: line, encoding: .utf8) != nil else {
                throw EXOFillingError.malformedStream("line is not UTF-8")
            }
            if line.first == 0x3A { continue }
            let prefix = Data("data:".utf8)
            guard line.starts(with: prefix) else {
                throw EXOFillingError.malformedStream("unknown SSE field")
            }
            guard eventData == nil else {
                throw EXOFillingError.malformedStream("multiple data lines in one SSE event")
            }
            var payload = Data(line.dropFirst(prefix.count))
            if payload.first == 0x20 { payload.removeFirst() }
            eventData = payload
        }
        if lineBuffer.count > EXOLimits.lineBytes {
            let exactLineFollowedByCR = lineBuffer.count == EXOLimits.lineBytes + 1
                && lineBuffer.last == 0x0D
            guard exactLineFollowedByCR else {
                throw EXOFillingError.responseLimit("SSE line bytes")
            }
        }
    }

    mutating func finish() throws -> EXOTerminalResult {
        guard lineBuffer.isEmpty, !eventHasLine else {
            throw EXOFillingError.malformedStream("EOF split an SSE event")
        }
        guard state == .done else {
            throw EXOFillingError.malformedStream("EOF arrived before terminal [DONE]")
        }
        state = .settled
        return .init(usage: terminalUsage)
    }

    private mutating func resetEvent() {
        eventData = nil
        eventHasLine = false
        eventByteCount = 0
    }

    private mutating func finishEvent() throws -> [WireEvent] {
        guard let eventData else { return [] }
        if eventData == Data("[DONE]".utf8) {
            guard state == .terminal else {
                throw EXOFillingError.malformedStream("[DONE] arrived before one terminal object")
            }
            state = .done
            return []
        }
        guard state != .terminal else {
            throw EXOFillingError.malformedStream("JSON followed the terminal object")
        }
        guard let text = String(data: eventData, encoding: .utf8) else {
            throw EXOFillingError.malformedStream("data object is not UTF-8")
        }
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: Data(text.utf8))
        } catch {
            throw EXOFillingError.malformedStream("data line is not JSON")
        }
        guard let root = object as? [String: Any] else {
            throw EXOFillingError.malformedStream("data JSON is not an object")
        }
        if let upstream = root["error"] {
            throw EXOFillingError.upstreamError(EXOText.upstreamMessage(upstream))
        }
        guard let id = root["id"] as? String, !id.isEmpty else {
            throw EXOFillingError.protocolContradiction("empty or missing command id")
        }
        if let commandID, commandID != id {
            throw EXOFillingError.protocolContradiction("command id changed during stream")
        }
        commandID = id
        guard root["model"] as? String == modelID else {
            throw EXOFillingError.protocolContradiction("response model differs from configured model")
        }
        guard let choices = root["choices"] as? [Any], choices.count == 1,
              let choice = choices[0] as? [String: Any]
        else {
            throw EXOFillingError.protocolContradiction("response must contain exactly one choice")
        }
        guard EXONumber.integer(choice["index"]) == 0 else {
            throw EXOFillingError.protocolContradiction("choice index is not zero")
        }
        guard choice["usage"] == nil else {
            throw EXOFillingError.protocolContradiction("choice-level usage is forbidden")
        }
        guard let delta = choice["delta"] as? [String: Any] else {
            throw EXOFillingError.protocolContradiction("choice delta is missing")
        }
        try rejectNonempty(delta["reasoning"], name: "reasoning")
        try rejectNonempty(delta["reasoning_content"], name: "reasoning")
        try rejectNonempty(choice["reasoning"], name: "reasoning")
        try rejectNonempty(delta["tool_calls"], name: "tool calls")
        try rejectNonempty(delta["function_call"], name: "function call")
        try rejectNonempty(choice["tool_calls"], name: "tool calls")
        try rejectNonempty(choice["function_call"], name: "function call")

        let content: String
        if let value = delta["content"] {
            if value is NSNull { content = "" }
            else if let value = value as? String { content = value }
            else { throw EXOFillingError.protocolContradiction("delta content is not text") }
        } else {
            content = ""
        }
        var emitted: [WireEvent] = []
        if !content.isEmpty {
            emitted.append(.responseAppend(
                entryID: nil,
                text: content,
                segmentID: nil,
                tokenCount: 1
            ))
        }

        let finishValue = choice["finish_reason"]
        if finishValue == nil || finishValue is NSNull {
            guard root["usage"] == nil else {
                throw EXOFillingError.protocolContradiction("usage appeared before terminal choice")
            }
            state = .streaming
            return emitted
        }
        guard let finish = finishValue as? String else {
            throw EXOFillingError.protocolContradiction("finish reason is not text")
        }
        switch finish {
        case "stop", "length":
            break
        case "content_filter", "error", "tool_calls", "function_call":
            throw EXOFillingError.upstreamError("generation ended with \(finish)")
        default:
            throw EXOFillingError.protocolContradiction("unknown finish reason")
        }
        if let usage = root["usage"] {
            terminalUsage = try EXONumber.usage(usage)
        }
        state = .terminal
        return emitted
    }

    private func rejectNonempty(_ value: Any?, name: String) throws {
        guard let value, !(value is NSNull) else { return }
        let empty: Bool
        switch value {
        case let string as String: empty = string.isEmpty
        case let array as [Any]: empty = array.isEmpty
        case let dictionary as [String: Any]: empty = dictionary.isEmpty
        default: empty = false
        }
        if !empty {
            throw EXOFillingError.protocolContradiction("nonempty \(name) is unsupported")
        }
    }
}

enum EXONumber {
    static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(number),
              number.int64Value >= 0,
              number.uint64Value <= UInt64(Int.max)
        else { return nil }
        return Int(number.uint64Value)
    }

    static func usage(_ value: Any) throws -> EXOUsage {
        guard let object = value as? [String: Any],
              let input = integer(object["prompt_tokens"]),
              let output = integer(object["completion_tokens"]),
              let total = integer(object["total_tokens"])
        else {
            throw EXOFillingError.protocolContradiction("terminal usage is malformed")
        }
        let (sum, overflow) = input.addingReportingOverflow(output)
        guard !overflow, sum == total else {
            throw EXOFillingError.protocolContradiction("terminal usage total is inconsistent")
        }
        return .init(inputTokens: input, outputTokens: output)
    }
}

enum EXOText {
    static func sanitized(_ data: Data) -> String? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let value = sanitized(text)
        return value.isEmpty ? nil : value
    }

    static func sanitized(_ text: String) -> String {
        let scalars = text.unicodeScalars.map { scalar -> Character in
            if scalar.properties.isWhitespace { return " " }
            if scalar.value < 0x20 || scalar.value == 0x7F { return "�" }
            return Character(String(scalar))
        }
        let collapsed = String(scalars).split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
        return String(collapsed.prefix(512))
    }

    static func upstreamMessage(_ value: Any) -> String {
        if let string = value as? String { return sanitized(string) }
        if let object = value as? [String: Any], let message = object["message"] as? String {
            return sanitized(message)
        }
        return "upstream error object"
    }
}
