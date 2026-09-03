import CReachLinuxMsQuic
import Dispatch
import Foundation
import ReachHost
import ReachWire

private let reachStatusOK = Int32(REACH_MSQUIC_OK)
private let reachStatusRefused = Int32(REACH_MSQUIC_REFUSED)
private let reachStatusTimeout = Int32(REACH_MSQUIC_TIMEOUT)
private let reachStatusClosed = Int32(REACH_MSQUIC_CLOSED)

public struct LinuxShutdownDeadline: Sendable, Equatable {
    public static let budgetNanoseconds: UInt64 = 15_000_000_000

    public let monotonicNanoseconds: UInt64

    public init(monotonicNanoseconds: UInt64) {
        self.monotonicNanoseconds = monotonicNanoseconds
    }

    public static func startingNow() -> Self {
        let now = reach_msquic_monotonic_now_nanoseconds()
        let addition = now.addingReportingOverflow(budgetNanoseconds)
        return Self(monotonicNanoseconds: addition.overflow ? .max : addition.partialValue)
    }

    public func hasExpired(now: UInt64 = reach_msquic_monotonic_now_nanoseconds()) -> Bool {
        now >= monotonicNanoseconds
    }
}

public enum LinuxTransportError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case startup(String)
    case streamClosed
    case receive(String)
    case send(String)
    case shutdownTimedOut

    public var description: String {
        switch self {
        case .startup(let detail):
            "Linux QUIC listener startup refused: \(detail)"
        case .streamClosed:
            "the Linux QUIC stream closed before the exchange finished"
        case .receive(let detail):
            "the Linux QUIC stream could not receive a frame: \(detail)"
        case .send(let detail):
            "the Linux QUIC stream could not send a frame: \(detail)"
        case .shutdownTimedOut:
            "the Linux QUIC listener did not settle within 15 seconds"
        }
    }

    public var errorDescription: String? { description }
}

public struct LinuxListenerConfiguration: Sendable, Equatable {
    public var address: String
    public var port: UInt16
    public var clusterCACertificatePath: String
    public var serverCertificateChainPath: String
    public var serverPrivateKeyPath: String

    public init(
        address: String,
        port: UInt16,
        clusterCACertificatePath: String,
        serverCertificateChainPath: String,
        serverPrivateKeyPath: String
    ) {
        self.address = address
        self.port = port
        self.clusterCACertificatePath = clusterCACertificatePath
        self.serverCertificateChainPath = serverCertificateChainPath
        self.serverPrivateKeyPath = serverPrivateKeyPath
    }
}

public struct LinuxTransportMetrics: Sendable, Equatable, Codable {
    public var rawConnections: UInt32
    public var acceptedConnections: UInt32
    public var activeConnections: UInt32
    public var refusedConnections: UInt32
    public var acceptedStreams: UInt32
    public var activeStreams: UInt32
    public var refusedStreams: UInt32
    public var peakConnections: UInt32
    public var peakStreams: UInt32
    public var retainedReceiveBytes: UInt64
    public var peakRetainedReceiveBytes: UInt64
    public var suspendedReceiveStreams: UInt32

    public init(
        rawConnections: UInt32,
        acceptedConnections: UInt32,
        activeConnections: UInt32,
        refusedConnections: UInt32,
        acceptedStreams: UInt32,
        activeStreams: UInt32,
        refusedStreams: UInt32,
        peakConnections: UInt32,
        peakStreams: UInt32,
        retainedReceiveBytes: UInt64 = 0,
        peakRetainedReceiveBytes: UInt64 = 0,
        suspendedReceiveStreams: UInt32 = 0
    ) {
        self.rawConnections = rawConnections
        self.acceptedConnections = acceptedConnections
        self.activeConnections = activeConnections
        self.refusedConnections = refusedConnections
        self.acceptedStreams = acceptedStreams
        self.activeStreams = activeStreams
        self.refusedStreams = refusedStreams
        self.peakConnections = peakConnections
        self.peakStreams = peakStreams
        self.retainedReceiveBytes = retainedReceiveBytes
        self.peakRetainedReceiveBytes = peakRetainedReceiveBytes
        self.suspendedReceiveStreams = suspendedReceiveStreams
    }
}

public enum LinuxSystemdNotifier {
    /// Absence of NOTIFY_SOCKET is legitimate for foreground/tests. A present
    /// but unusable inherited socket is a service-start failure.
    public static func notify(_ message: String) throws {
        let status = message.withCString { reach_linux_systemd_notify($0) }
        switch status {
        case reachStatusOK, reachStatusRefused:
            return
        default:
            throw LinuxTransportError.startup("systemd notification failed")
        }
    }
}

private final class ListenerHandle: @unchecked Sendable {
    let pointer: OpaquePointer
    private let lock = NSLock()
    private var stopped = false

    init(configuration: LinuxListenerConfiguration) throws {
        var resultPointer: OpaquePointer?
        var error = [CChar](repeating: 0, count: 512)
        let result = configuration.address.withCString { address in
            configuration.serverCertificateChainPath.withCString { certificate in
                configuration.serverPrivateKeyPath.withCString { key in
                    configuration.clusterCACertificatePath.withCString { ca in
                        var raw = reach_msquic_listener_configuration(
                            listen_address: address,
                            listen_port: configuration.port,
                            certificate_chain_path: certificate,
                            private_key_path: key,
                            cluster_ca_path: ca
                        )
                        return error.withUnsafeMutableBufferPointer { errorBuffer in
                            reach_msquic_listener_start(
                                &raw,
                                &resultPointer,
                                errorBuffer.baseAddress,
                                errorBuffer.count
                            )
                        }
                    }
                }
            }
        }
        guard result == reachStatusOK, let resultPointer else {
            let detail = String(
                decoding: error.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )
            throw LinuxTransportError.startup(detail)
        }
        pointer = resultPointer
    }

    deinit {
        _ = reach_msquic_listener_destroy(pointer)
    }

    func accept() -> ListenerAcceptResult {
        var stream: OpaquePointer?
        let status = reach_msquic_listener_accept(pointer, 250, &stream)
        return ListenerAcceptResult(status: status, stream: stream)
    }

    func snapshot() -> LinuxTransportMetrics {
        var raw = reach_msquic_metrics()
        reach_msquic_listener_snapshot(pointer, &raw)
        return LinuxTransportMetrics(
            rawConnections: raw.raw_connections,
            acceptedConnections: raw.accepted_connections,
            activeConnections: raw.active_connections,
            refusedConnections: raw.refused_connections,
            acceptedStreams: raw.accepted_streams,
            activeStreams: raw.active_streams,
            refusedStreams: raw.refused_streams,
            peakConnections: raw.peak_connections,
            peakStreams: raw.peak_streams,
            retainedReceiveBytes: raw.retained_receive_bytes,
            peakRetainedReceiveBytes: raw.peak_retained_receive_bytes,
            suspendedReceiveStreams: raw.suspended_receive_streams
        )
    }

    func stop(until deadline: LinuxShutdownDeadline) -> Int32 {
        lock.lock()
        if stopped {
            lock.unlock()
            return reachStatusOK
        }
        lock.unlock()
        let status = reach_msquic_listener_stop_until(
            pointer,
            deadline.monotonicNanoseconds
        )
        if status == reachStatusOK {
            lock.lock()
            stopped = true
            lock.unlock()
        }
        return status
    }
}

private struct ListenerAcceptResult: @unchecked Sendable {
    var status: Int32
    var stream: OpaquePointer?
}

private final class StreamHandle: @unchecked Sendable {
    let pointer: OpaquePointer

    init(transferring pointer: OpaquePointer) {
        self.pointer = pointer
    }

    deinit {
        reach_msquic_stream_release(pointer)
    }

    func peerCertificate() -> Data? {
        let length = reach_msquic_stream_peer_certificate_length(pointer)
        guard length > 0, length <= REACH_MSQUIC_MAX_PEER_CERTIFICATE else { return nil }
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { bytes in
            reach_msquic_stream_copy_peer_certificate(
                pointer,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                length
            )
        }
        return status == reachStatusOK ? data : nil
    }

    func blockingRead(into allocation: FrameAllocation, offset: Int, count: Int) -> BlockingRead {
        var readCount = 0
        var fin: Int32 = 0
        let status = reach_msquic_stream_read(
            pointer,
            allocation.pointer.advanced(by: offset).assumingMemoryBound(to: UInt8.self),
            count,
            1_000,
            &readCount,
            &fin
        )
        return BlockingRead(status: status, count: readCount, fin: fin != 0)
    }

    func releaseReceiveBytes(_ count: Int) {
        guard count > 0 else { return }
        precondition(reach_msquic_stream_release_receive_bytes(pointer, count) == reachStatusOK)
    }

    func blockingSend(_ data: Data) -> Int32 {
        data.withUnsafeBytes { bytes in
            reach_msquic_stream_send(
                pointer,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                bytes.count,
                0,
                30_000
            )
        }
    }

    func finish() {
        reach_msquic_stream_finish(pointer)
    }

    func cancel() {
        reach_msquic_stream_cancel(pointer, 0x52450004)
    }
}

struct BlockingRead: Sendable {
    var status: Int32
    var count: Int
    var fin: Bool
}

final class FrameAllocation: @unchecked Sendable {
    private(set) var pointer: UnsafeMutableRawPointer
    let count: Int
    private var transferred = false

    init(count: Int) {
        self.count = count
        pointer = UnsafeMutableRawPointer.allocate(
            byteCount: max(count, 1),
            alignment: MemoryLayout<UInt64>.alignment
        )
    }

    deinit {
        if !transferred {
            pointer.deallocate()
        }
    }

    func byte(at index: Int) -> UInt8 {
        pointer.load(fromByteOffset: index, as: UInt8.self)
    }

    func transferToData() -> Data {
        precondition(!transferred)
        transferred = true
        return Data(
            bytesNoCopy: pointer,
            count: count,
            deallocator: .custom { pointer, _ in pointer.deallocate() }
        )
    }
}

protocol LinuxFrameByteSource: Sendable {
    func read(into allocation: FrameAllocation, offset: Int, count: Int) async -> BlockingRead
    func releaseRetainedBytes(_ count: Int)
    func cancel()
}

extension LinuxFrameByteSource {
    func releaseRetainedBytes(_: Int) {}
}

private final class CFrameByteSource: LinuxFrameByteSource, @unchecked Sendable {
    private let handle: StreamHandle

    init(handle: StreamHandle) {
        self.handle = handle
    }

    func read(into allocation: FrameAllocation, offset: Int, count: Int) async -> BlockingRead {
        await Task.detached(priority: .userInitiated) { [handle] in
            handle.blockingRead(into: allocation, offset: offset, count: count)
        }.value
    }

    func releaseRetainedBytes(_ count: Int) {
        handle.releaseReceiveBytes(count)
    }

    func cancel() {
        handle.cancel()
    }
}

final class LinuxFrameReader: @unchecked Sendable {
    private let source: any LinuxFrameByteSource
    private let lock = NSLock()
    private var inputFinished = false
    private var outstandingFrameBytes = 0

    init(source: any LinuxFrameByteSource) {
        self.source = source
    }

    deinit {
        releaseOutstandingFrame()
    }

    private func hasFinishedInput() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return inputFinished
    }

    private func markInputFinished() {
        lock.lock()
        inputFinished = true
        lock.unlock()
    }

    private func releaseOutstandingFrame() {
        let count: Int
        lock.lock()
        count = outstandingFrameBytes
        outstandingFrameBytes = 0
        lock.unlock()
        source.releaseRetainedBytes(count)
    }

    private func retainFrameForHandoff(_ count: Int) {
        lock.lock()
        precondition(outstandingFrameBytes == 0)
        outstandingFrameBytes = count
        lock.unlock()
    }

    func nextFrame() async throws -> RawFrame? {
        releaseOutstandingFrame()
        if hasFinishedInput() { return nil }

        let header = FrameAllocation(count: 4)
        let headerRead = try await readExactly(into: header, count: 4)
        defer { source.releaseRetainedBytes(headerRead.retainedBytes) }
        guard let headerFin = headerRead.fin else {
            markInputFinished()
            return nil
        }
        if headerFin {
            throw LinuxTransportError.receive("the peer finished inside a frame header")
        }
        var length: UInt32 = 0
        for index in 0 ..< 4 {
            length = (length << 8) | UInt32(header.byte(at: index))
        }
        guard length >= 1 else {
            throw WireError.malformedFrame("zero-length frame")
        }
        guard length <= FrameCodec.maxFrameLength else {
            throw WireError.frameTooLarge(length)
        }

        let typeStorage = FrameAllocation(count: 1)
        let typeRead = try await readExactly(into: typeStorage, count: 1)
        defer { source.releaseRetainedBytes(typeRead.retainedBytes) }
        guard let typeFin = typeRead.fin else {
            throw LinuxTransportError.streamClosed
        }
        guard let type = FrameType(rawValue: typeStorage.byte(at: 0)) else {
            throw WireError.unknownFrameType(typeStorage.byte(at: 0))
        }
        let bodyCount = Int(length) - 1
        var body = Data()
        var retainedBodyBytes = 0
        let bodyFin: Bool
        if bodyCount == 0 {
            bodyFin = typeFin
        } else {
            if typeFin {
                throw LinuxTransportError.receive("the peer finished before the frame body")
            }
            var remaining = bodyCount
            var finished = false
            do {
                while remaining > 0 {
                    let amount = min(remaining, 64 * 1024)
                    let chunk = FrameAllocation(count: amount)
                    let read = try await readExactly(into: chunk, count: amount)
                    retainedBodyBytes += read.retainedBytes
                    guard let chunkFin = read.fin else {
                        throw LinuxTransportError.streamClosed
                    }
                    body.append(
                        chunk.pointer.assumingMemoryBound(to: UInt8.self),
                        count: amount
                    )
                    remaining -= amount
                    finished = chunkFin
                    if finished && remaining > 0 {
                        throw LinuxTransportError.receive("the peer finished inside a frame")
                    }
                }
            } catch {
                source.releaseRetainedBytes(retainedBodyBytes)
                throw error
            }
            bodyFin = finished
        }
        if bodyFin {
            markInputFinished()
        }
        retainFrameForHandoff(retainedBodyBytes)
        return RawFrame(type: type, body: body)
    }

    private func readExactly(
        into allocation: FrameAllocation,
        count: Int
    ) async throws -> (fin: Bool?, retainedBytes: Int) {
        var offset = 0
        var sawFin = false
        do {
            while offset < count {
                try Task.checkCancellation()
                let result = await source.read(into: allocation, offset: offset, count: count - offset)
                switch result.status {
                case reachStatusOK:
                    guard result.count > 0 else {
                        throw LinuxTransportError.receive("the transport returned an empty receive")
                    }
                    offset += result.count
                    sawFin = result.fin
                    if sawFin && offset < count {
                        throw LinuxTransportError.receive("the peer finished inside a frame")
                    }
                case reachStatusTimeout:
                    continue
                case reachStatusClosed:
                    if offset == 0 && result.fin { return (nil, 0) }
                    throw LinuxTransportError.streamClosed
                default:
                    throw LinuxTransportError.receive("MsQuic receive status \(result.status)")
                }
            }
            return (sawFin, offset)
        } catch {
            source.releaseRetainedBytes(offset)
            throw error
        }
    }

    func cancel() {
        releaseOutstandingFrame()
        source.cancel()
    }
}

public final class LinuxSessionStream: SessionHostStream, @unchecked Sendable {
    private let handle: StreamHandle
    private let reader: LinuxFrameReader
    private let incoming: AsyncThrowingStream<RawFrame, any Error>
    private let peerDER: Data?

    fileprivate init(transferring pointer: OpaquePointer) {
        let handle = StreamHandle(transferring: pointer)
        self.handle = handle
        let reader = LinuxFrameReader(source: CFrameByteSource(handle: handle))
        self.reader = reader
        peerDER = handle.peerCertificate()

        incoming = AsyncThrowingStream<RawFrame, any Error>(
            unfolding: { [reader] in
                try await withTaskCancellationHandler(
                    operation: { try await reader.nextFrame() },
                    onCancel: { reader.cancel() }
                )
            }
        )
    }

    public var frames: AsyncThrowingStream<RawFrame, any Error> { incoming }

    public func send(_ frame: some WireFrame, for negotiatedVersion: UInt8) async throws {
        let encoded = try FrameCodec.encode(frame, for: negotiatedVersion)
        let status = await Task.detached(priority: .userInitiated) { [handle] in
            handle.blockingSend(encoded)
        }.value
        guard status == reachStatusOK else {
            throw LinuxTransportError.send("MsQuic send status \(status)")
        }
    }

    public func finishSending() {
        handle.finish()
    }

    public func cancel() {
        reader.cancel()
    }

    public func remoteEndpointDescription() -> String? { nil }

    public func peerCertificateDER() -> Data? { peerDER }
}

public final class ReachLinuxListener: @unchecked Sendable {
    private let handle: ListenerHandle

    public init(configuration: LinuxListenerConfiguration) throws {
        handle = try ListenerHandle(configuration: configuration)
    }

    public func nextStream() async throws -> LinuxSessionStream? {
        while !Task.isCancelled {
            let result = await Task.detached(priority: .userInitiated) { [handle] in
                handle.accept()
            }.value
            switch result.status {
            case reachStatusOK:
                guard let pointer = result.stream else {
                    throw LinuxTransportError.receive("accepted stream was missing")
                }
                return LinuxSessionStream(transferring: pointer)
            case reachStatusTimeout:
                continue
            case reachStatusClosed:
                return nil
            default:
                throw LinuxTransportError.receive("MsQuic accept status \(result.status)")
            }
        }
        return nil
    }

    public func metrics() -> LinuxTransportMetrics {
        handle.snapshot()
    }

    public func stop(until deadline: LinuxShutdownDeadline) async throws {
        let status = await Task.detached(priority: .high) { [handle] in
            handle.stop(until: deadline)
        }.value
        guard status == reachStatusOK else {
            throw LinuxTransportError.shutdownTimedOut
        }
    }
}
