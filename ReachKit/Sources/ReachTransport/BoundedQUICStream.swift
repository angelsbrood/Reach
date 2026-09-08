import Foundation
import Network
import ReachWire
import Security

public enum BoundedTransportError: Error, Sendable, Equatable { case authentication, closed, concurrentOperation, malformed, overflow, timeout }

/// Decodes the existing envelope header before allocating any body. Receive is
/// demand driven: one requested frame, no complete-frame queue, <=64 KiB/read.
struct BoundedFrameHeader: Sendable {
    let type: FrameType
    let bodyLength: Int
    init(_ bytes: Data) throws {
        guard bytes.count == 5 else { throw BoundedTransportError.malformed }
        let length = bytes.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length >= 1, let type = FrameType(rawValue: bytes[bytes.startIndex + 4]) else { throw BoundedTransportError.malformed }
        guard length <= FrameCodec.maxFrameLength, Int(length - 1) <= DurableWire.bodyLimit(type) else { throw BoundedTransportError.overflow }
        self.type = type; bodyLength = Int(length - 1)
    }
}

public struct BoundedStreamMetrics: Sendable {
    public let receiveCalls: Int, maximumReceive: Int, maximumBody: Int
}

/// Opt-in transport only. No read is armed until the caller has checked peer DER
/// and asks for a frame. One consumer and one serialized send; no internal task
/// or frame/send queue. Cancelling settles active waiters and cancels the socket.
public final class BoundedQUICStream: @unchecked Sendable {
    private struct Chunk: Sendable { let data: Data, end: Bool }
    private let connection: NWConnection
    private let ready = Latch<Void>(), ended = Latch<Void>()
    private let lock = NSLock()
    private var closed = false, reading = false, sending = false, eof = false
    private var receiveWaiter: ResumeOnce<Chunk>?, sendWaiter: ResumeOnce<Void>?
    private var receiveCalls = 0, maximumReceive = 0, maximumBody = 0
    private let onEnd: @Sendable () -> Void
    private var notified = false

    init(connection: NWConnection, onEnd: @escaping @Sendable () -> Void = {}) {
        self.connection = connection; self.onEnd = onEnd
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.ready.settle(.success(()))
            case .failed(let error):
                self.stop(error: { if case .tls = error { return .authentication }; return .closed }())
                self.connection.cancel()
                self.ended.settle(.success(()))
                self.notifyEnd()
            case .cancelled:
                self.stop()
                self.ended.settle(.success(()))
                self.notifyEnd()
            default: break
            }
        }
        connection.start(queue: transportQueue)
    }
    public static func open(endpoint: NWEndpoint, parameters: NWParameters, timeout: Duration = .seconds(10)) async throws -> BoundedQUICStream {
        let stream = BoundedQUICStream(connection: NWConnection(to: endpoint, using: parameters))
        do { try await stream.waitUntilReady(timeout: timeout); return stream }
        catch { await stream.cancelAndWait(); throw error }
    }
    public func waitUntilReady(timeout: Duration = .seconds(10)) async throws {
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                defer { group.cancelAll() }
                group.addTask { try await self.ready.value() }
                group.addTask { try await Task.sleep(for: timeout); throw BoundedTransportError.timeout }
                try await group.next()
            }
        } catch { cancel(); throw error }
    }
    public var isClosed: Bool { lock.withLock { closed } }
    public var metrics: BoundedStreamMetrics { lock.withLock { .init(receiveCalls: receiveCalls, maximumReceive: maximumReceive, maximumBody: maximumBody) } }
    private func notifyEnd() {
        let notify = lock.withLock { if notified { return false }; notified = true; return true }
        if notify { onEnd() }
    }
    private func stop(error: BoundedTransportError = .closed) {
        let pending = lock.withLock { () -> (ResumeOnce<Chunk>?, ResumeOnce<Void>?) in
            closed = true
            defer { receiveWaiter = nil; sendWaiter = nil }
            return (receiveWaiter, sendWaiter)
        }
        pending.0?.resume(.failure(error)); pending.1?.resume(.failure(error))
        ready.settle(.failure(error))
    }
    public func cancel() { stop(); connection.cancel() }
    public func cancelAndWait() async { cancel(); await Self.drain(ended) }
    static func drain(_ latch: Latch<Void>) async { await Task.detached { _ = try? await latch.value() }.value }
    private func receive(maximum: Int) async throws -> Chunk {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                let box = ResumeOnce(continuation)
                let permitted = lock.withLock { () -> Bool in
                    guard !closed else { return false }
                    receiveWaiter = box; receiveCalls += 1; maximumReceive = max(maximumReceive, maximum); return true
                }
                guard permitted else { box.resume(.failure(BoundedTransportError.closed)); return }
                connection.receive(minimumIncompleteLength: 1, maximumLength: maximum) { [weak self] bytes, _, complete, error in
                    self?.lock.withLock { self?.receiveWaiter = nil }
                    if error != nil { box.resume(.failure(BoundedTransportError.closed)) }
                    else { box.resume(.success(.init(data: bytes ?? Data(), end: complete))) }
                }
            }
        } onCancel: { self.cancel() }
    }
    private func exact(_ count: Int, allowEOF: Bool = false) async throws -> Data? {
        var bytes = Data(); bytes.reserveCapacity(count)
        while bytes.count < count {
            if lock.withLock({ eof }) {
                if allowEOF && bytes.isEmpty { return nil }
                throw BoundedTransportError.malformed
            }
            let chunk = try await receive(maximum: min(65536, count - bytes.count))
            guard chunk.data.count <= min(65536, count - bytes.count), !chunk.data.isEmpty || chunk.end else { throw BoundedTransportError.malformed }
            bytes.append(chunk.data)
            if chunk.end { lock.withLock { eof = true } }
        }
        return bytes
    }
    public func next() async throws -> RawFrame? {
        try lock.withLock { guard !reading else { throw BoundedTransportError.concurrentOperation }; reading = true }
        defer { lock.withLock { reading = false } }
        do {
            guard let bytes = try await exact(5, allowEOF: true) else { return nil }
            let header = try BoundedFrameHeader(bytes)
            lock.withLock { maximumBody = max(maximumBody, header.bodyLength) }
            guard let body = try await exact(header.bodyLength) else { throw BoundedTransportError.malformed }
            return RawFrame(type: header.type, body: body)
        } catch { cancel(); throw error }
    }
    public func send(_ bytes: Data) async throws {
        guard bytes.count <= (32 << 20) else { throw BoundedTransportError.overflow }
        try lock.withLock {
            guard !closed else { throw BoundedTransportError.closed }
            guard !sending else { throw BoundedTransportError.concurrentOperation }; sending = true
        }
        defer { lock.withLock { sending = false } }
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let box = ResumeOnce(continuation)
                let permitted = lock.withLock { () -> Bool in guard !closed else { return false }; sendWaiter = box; return true }
                guard permitted else { box.resume(.failure(BoundedTransportError.closed)); return }
                connection.send(content: bytes, completion: .contentProcessed { [weak self] error in
                    self?.lock.withLock { self?.sendWaiter = nil }
                    box.resume(error == nil ? .success(()) : .failure(BoundedTransportError.closed))
                })
            }
        } onCancel: { self.cancel() }
    }
    public func peerCertificateDER() -> Data? {
        guard let metadata = connection.metadata(definition: NWProtocolQUIC.definition) as? NWProtocolQUIC.Metadata else { return nil }
        var der: Data?
        sec_protocol_metadata_access_peer_certificate_chain(metadata.securityProtocolMetadata) { certificate in
            if der == nil { der = SecCertificateCopyData(sec_certificate_copy_ref(certificate).takeRetainedValue()) as Data }
        }
        return der
    }
    public func localEndpointDescription() -> String? { connection.currentPath?.localEndpoint.map { "\($0)" } }
}

/// One accepted group/stream, zero queued peer connections. Excess groups and
/// streams are explicitly cancelled. The bounded stream does not start a pump.
public final class BoundedQUICListener: @unchecked Sendable {
    private final class Lease: @unchecked Sendable {
        let id = UUID(), group: NWConnectionGroup, ended = Latch<Void>()
        var stream: BoundedQUICStream?
        var deadline: DispatchSourceTimer?
        init(_ group: NWConnectionGroup) { self.group = group }
    }
    private let listener: NWListener
    private let ready = Latch<Void>(), ended = Latch<Void>()
    private let lock = NSLock()
    private var active: Lease?, stopped = false, rejected = 0
    private let continuation: AsyncThrowingStream<BoundedQUICStream, Error>.Continuation
    public let streams: AsyncThrowingStream<BoundedQUICStream, Error>
    public let port: UInt16
    public init(port: UInt16, parameters: NWParameters) throws {
        guard (49152...65535).contains(port) else { throw BoundedTransportError.malformed }
        self.port = port
        let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .init(rawValue: port)!)
        parameters.requiredLocalEndpoint = endpoint
        // requiredLocalEndpoint owns both address and port. Supplying on:
        // as well makes Network.framework reject the parameters with EINVAL.
        listener = try NWListener(using: parameters)
        (streams, continuation) = AsyncThrowingStream.makeStream(bufferingPolicy: .bufferingOldest(1))
        listener.newConnectionGroupHandler = { [weak self] group in self?.accept(group) ?? group.cancel() }
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.ready.settle(.success(()))
            case .failed, .cancelled:
                self.ready.settle(.failure(BoundedTransportError.closed)); self.ended.settle(.success(())); self.continuation.finish()
            default: break
            }
        }
        listener.start(queue: transportQueue)
    }
    private func accept(_ group: NWConnectionGroup) {
        let lease = Lease(group)
        let permitted = lock.withLock { () -> Bool in
            guard !stopped, active == nil else { rejected += 1; return false }; active = lease; return true
        }
        guard permitted else { group.cancel(); return }
        let deadline = DispatchSource.makeTimerSource(queue: transportQueue)
        deadline.schedule(deadline: .now() + 10)
        deadline.setEventHandler { [weak lease] in lease?.group.cancel() }
        lease.deadline = deadline; deadline.resume()
        group.newConnectionHandler = { [weak self, weak lease] connection in
            guard let self, let lease else { connection.cancel(); return }
            let stream: BoundedQUICStream? = self.lock.withLock {
                guard !self.stopped, self.active?.id == lease.id, lease.stream == nil else { self.rejected += 1; return nil }
                let stream = BoundedQUICStream(connection: connection, onEnd: { [weak lease] in lease?.group.cancel() })
                lease.deadline?.cancel(); lease.deadline = nil
                lease.stream = stream; return stream
            }
            guard let stream else { connection.cancel(); return }
            if case .enqueued = self.continuation.yield(stream) {} else { stream.cancel(); group.cancel() }
        }
        group.stateUpdateHandler = { [weak self, weak lease] state in
            guard let lease else { return }
            switch state {
            case .failed, .cancelled:
                lease.deadline?.cancel(); lease.deadline = nil
                lease.stream?.cancel(); lease.ended.settle(.success(()))
                self?.lock.withLock { if self?.active?.id == lease.id { self?.active = nil } }
            default: break
            }
        }
        group.start(queue: transportQueue)
    }
    public var rejectedConnectionsOrStreams: Int { lock.withLock { rejected } }
    public func waitUntilReady(timeout: Duration = .seconds(10)) async throws {
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                defer { group.cancelAll() }
                group.addTask { try await self.ready.value() }
                group.addTask { try await Task.sleep(for: timeout); throw BoundedTransportError.timeout }
                try await group.next()
            }
        } catch { await cancelAndWait(); throw error }
    }
    public func cancelAndWait() async {
        let lease = lock.withLock { stopped = true; return active }
        listener.cancel(); continuation.finish()
        if let lease { await lease.stream?.cancelAndWait(); lease.group.cancel(); await BoundedQUICStream.drain(lease.ended) }
        await BoundedQUICStream.drain(ended)
    }
}
