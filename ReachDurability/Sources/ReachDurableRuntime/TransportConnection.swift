import Foundation
import ReachWire
import ReachTransport

/// One call, one frame. Timeout cancellation closes and drains the active read;
/// there are no detached readers surviving a failed exchange.
enum TransportConnection {
    static func bytes(_ raw: RawFrame) throws -> Data {
        guard raw.body.count <= DurableWire.bodyLimit(raw.type), raw.body.count + 1 <= FrameCodec.maxFrameLength else { throw TransportRuntimeError.protocolRefused }
        var length = UInt32(raw.body.count + 1).bigEndian
        var bytes = withUnsafeBytes(of: &length) { Data($0) }
        bytes.append(raw.type.rawValue); bytes.append(raw.body); return bytes
    }
    static func message(_ bytes: Data) throws -> DurableMessage {
        var frames = FrameReassembler(); let values = try frames.feed(bytes)
        guard values.count == 1 else { throw TransportRuntimeError.protocolRefused }
        return try DurableMessage.decode(values[0], version: 2)
    }
    static func deadline<T>(_ duration: Duration, _ body: @escaping () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            defer { group.cancelAll() }
            group.addTask { try await body() }
            group.addTask { try await Task.sleep(for: duration); throw BoundedTransportError.timeout }
            guard let value = try await group.next() else { throw CancellationError() }; return value
        }
    }
    static func read(_ stream: BoundedQUICStream, timeout: Duration = .seconds(10)) async throws -> RawFrame {
        try await deadline(timeout) {
            guard let raw = try await stream.next() else { throw BoundedTransportError.closed }; return raw
        }
    }
    static func send(_ bytes: Data, on stream: BoundedQUICStream) async throws {
        try await deadline(.seconds(10)) { try await stream.send(bytes) }
    }
    static func progress(_ value: TransportProgress, enabled: Bool) throws {
        if enabled { try TransportContract.write(value, to: nil) }
    }
}

/// The only executor allowed to load/advance the host model. Each submitted
/// operation is awaited to its returned boundary, even when its caller cancels.
final class TransportHostWorker {
    private let queue = DispatchQueue(label: "reach.durable-transport.native")
    private var runtime: TransportHostRuntime?
    func open(root: String) async throws {
        try await perform { self.runtime = try TransportHostRuntime(root: root) }
    }
    private func perform<T>(_ body: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try LocalDurableRuntime.withCPU(body) }) }
        }
    }
    func call<T>(_ body: @escaping (TransportHostRuntime) throws -> T) async throws -> T {
        try await perform { guard let runtime = self.runtime else { throw TransportRuntimeError.unavailable }; return try body(runtime) }
    }
    func close() async { _ = try? await perform { self.runtime?.close(); self.runtime = nil } }
}
