import CReachLinuxMsQuic
import Dispatch
import Foundation
import Glibc
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
    public var physicalOwnedReceiveBytes: UInt64
    public var physicalBorrowedReceiveBytes: UInt64
    public var physicalReceiveBytes: UInt64
    public var peakPhysicalReceiveBytes: UInt64
    public var virtualReceiveBytes: UInt64
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
        physicalOwnedReceiveBytes: UInt64 = 0,
        physicalBorrowedReceiveBytes: UInt64 = 0,
        physicalReceiveBytes: UInt64 = 0,
        peakPhysicalReceiveBytes: UInt64 = 0,
        virtualReceiveBytes: UInt64 = 0,
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
        self.physicalOwnedReceiveBytes = physicalOwnedReceiveBytes
        self.physicalBorrowedReceiveBytes = physicalBorrowedReceiveBytes
        self.physicalReceiveBytes = physicalReceiveBytes
        self.peakPhysicalReceiveBytes = peakPhysicalReceiveBytes
        self.virtualReceiveBytes = virtualReceiveBytes
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
            physicalOwnedReceiveBytes: raw.physical_owned_receive_bytes,
            physicalBorrowedReceiveBytes: raw.physical_borrowed_receive_bytes,
            physicalReceiveBytes: raw.physical_receive_bytes,
            peakPhysicalReceiveBytes: raw.peak_physical_receive_bytes,
            virtualReceiveBytes: raw.virtual_receive_bytes,
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

    func registerReceiveMapping(_ allocation: FrameAllocation) -> Bool {
        reach_msquic_stream_register_receive_mapping(
            pointer,
            allocation.mappingBase!,
            allocation.bodyOffset,
            allocation.count,
            allocation.mappedLength,
            allocation.pageSize
        ) == reachStatusOK
    }

    func releaseReceiveMapping(_ allocation: FrameMappingIdentity) -> Bool {
        reach_msquic_stream_release_receive_mapping(
            pointer,
            allocation.mappingBase,
            allocation.bodyOffset,
            allocation.logicalLength,
            allocation.mappedLength,
            allocation.pageSize
        ) == reachStatusOK
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

struct FrameMappingIdentity: @unchecked Sendable {
    let mappingBase: UnsafeMutableRawPointer
    let pointer: UnsafeMutableRawPointer
    let bodyOffset: Int
    let logicalLength: Int
    let mappedLength: Int
    let pageSize: Int
}

final class FrameStorageLease: @unchecked Sendable {
    typealias Releaser = @Sendable (FrameMappingIdentity, Int) -> Bool

    let identity: FrameMappingIdentity
    private let releaser: Releaser
    private let lock = NSLock()
    private var transferredBytes = 0
    private var releaseStarted = false
    private var released = false
    private var cancellationRequested = false
    private var waiter: CheckedContinuation<Void, any Error>?

    init(identity: FrameMappingIdentity, releaser: @escaping Releaser) {
        self.identity = identity
        self.releaser = releaser
    }

    func recordTransfer(_ count: Int) {
        lock.lock()
        precondition(!releaseStarted && count >= 0)
        transferredBytes += count
        precondition(transferredBytes <= identity.logicalLength)
        lock.unlock()
    }

    func release() {
        let transferred: Int
        lock.lock()
        guard !releaseStarted else {
            lock.unlock()
            return
        }
        releaseStarted = true
        transferred = transferredBytes
        lock.unlock()

        precondition(releaser(identity, transferred), "mapped frame storage release failed")

        let continuation: CheckedContinuation<Void, any Error>?
        lock.lock()
        released = true
        continuation = waiter
        waiter = nil
        lock.unlock()
        continuation?.resume()
    }

    func waitForRelease() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if released {
                    lock.unlock()
                    continuation.resume()
                } else if cancellationRequested || Task.isCancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                } else {
                    precondition(waiter == nil)
                    waiter = continuation
                    lock.unlock()
                }
            }
        } onCancel: {
            self.cancelWaiter()
        }
    }

    func cancelWaiter() {
        let continuation: CheckedContinuation<Void, any Error>?
        lock.lock()
        cancellationRequested = true
        continuation = waiter
        waiter = nil
        lock.unlock()
        continuation?.resume(throwing: CancellationError())
    }
}

final class FrameAllocation: @unchecked Sendable {
    enum Storage {
        case heap
        case mapped(pageSize: Int, mappedLength: Int)
    }

    private(set) var pointer: UnsafeMutableRawPointer
    let count: Int
    let storage: Storage
    let mappingBase: UnsafeMutableRawPointer?
    let bodyOffset: Int
    private var transferred = false
    private var lease: FrameStorageLease?

    init(count: Int) {
        self.count = count
        storage = .heap
        pointer = UnsafeMutableRawPointer.allocate(
            byteCount: max(count, 1),
            alignment: MemoryLayout<UInt64>.alignment
        )
        mappingBase = nil
        bodyOffset = 0
    }

    private init(
        count: Int,
        mappingBase: UnsafeMutableRawPointer,
        bodyOffset: Int,
        pageSize: Int,
        mappedLength: Int
    ) {
        self.count = count
        self.mappingBase = mappingBase
        self.bodyOffset = bodyOffset
        pointer = mappingBase.advanced(by: bodyOffset)
        storage = .mapped(pageSize: pageSize, mappedLength: mappedLength)
    }

    static func mapped(count: Int) throws -> FrameAllocation {
        let pageSize = Int(sysconf(Int32(_SC_PAGESIZE)))
        guard count > 0,
              pageSize > 0,
              pageSize <= Int(REACH_MSQUIC_MAX_RECEIVE_PAGE_SIZE),
              pageSize.nonzeroBitCount == 1,
              Int(REACH_MSQUIC_RECEIVE_COPY_QUANTUM).isMultiple(of: pageSize),
              Int(REACH_MSQUIC_MAX_FRAME_LENGTH).isMultiple(of: pageSize) else {
            throw LinuxTransportError.receive("unsupported receive page geometry")
        }
        let remainder = count % pageSize
        let mappedLength = count + (remainder == 0 ? 0 : pageSize - remainder)
        let bodyOffset = count < pageSize ? pageSize - count : 0
        guard mappedLength <= Int(REACH_MSQUIC_MAX_FRAME_LENGTH),
              let mappingBase = mmap(
                nil,
                mappedLength,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0
              ), mappingBase != MAP_FAILED else {
            throw LinuxTransportError.receive("could not reserve frame body mapping")
        }
        return FrameAllocation(
            count: count,
            mappingBase: mappingBase,
            bodyOffset: bodyOffset,
            pageSize: pageSize,
            mappedLength: mappedLength
        )
    }

    var pageSize: Int {
        guard case .mapped(let pageSize, _) = storage else { return 0 }
        return pageSize
    }

    var mappedLength: Int {
        guard case .mapped(_, let mappedLength) = storage else { return 0 }
        return mappedLength
    }

    var mappingIdentity: FrameMappingIdentity {
        precondition(mappedLength > 0)
        return FrameMappingIdentity(
            mappingBase: mappingBase!,
            pointer: pointer,
            bodyOffset: bodyOffset,
            logicalLength: count,
            mappedLength: mappedLength,
            pageSize: pageSize
        )
    }

    func bindLease(_ lease: FrameStorageLease) {
        precondition(self.lease == nil && lease.identity.pointer == pointer)
        self.lease = lease
    }

    deinit {
        if !transferred {
            if let lease {
                lease.release()
            } else {
                releaseUnboundStorage()
            }
        }
    }

    func byte(at index: Int) -> UInt8 {
        pointer.load(fromByteOffset: index, as: UInt8.self)
    }

    func transferToData() -> (Data, FrameStorageLease) {
        precondition(!transferred && count > 0)
        let lease = self.lease!
        transferred = true
        // Linux Foundation copies custom NSData subclasses and inlines short
        // Data values. A sub-page body therefore occupies the tail of its
        // already-charged page: the full-page owner stays external, while the
        // nonzero-offset slice exposes only the logical bytes and retains the
        // same custom-deallocator lease.
        let backing = Data(
            bytesNoCopy: mappingBase!,
            count: bodyOffset + count,
            deallocator: .custom { [lease] _, _ in lease.release() }
        )
        let data = bodyOffset == 0 ? backing : backing.dropFirst(bodyOffset)
        precondition(data.count == count)
        precondition(data.withUnsafeBytes { $0.baseAddress } == UnsafeRawPointer(pointer))
        return (data, lease)
    }

    private func releaseUnboundStorage() {
        switch storage {
        case .heap:
            pointer.deallocate()
        case .mapped(_, let mappedLength):
            precondition(munmap(mappingBase!, mappedLength) == 0)
        }
    }
}

protocol LinuxFrameByteSource: Sendable {
    func read(into allocation: FrameAllocation, offset: Int, count: Int) async -> BlockingRead
    func releaseRetainedBytes(_ count: Int)
    func registerBodyMapping(_ allocation: FrameAllocation) -> Bool
    func releaseBodyMapping(_ identity: FrameMappingIdentity, transferredBytes: Int) -> Bool
    func cancel()
}

extension LinuxFrameByteSource {
    func releaseRetainedBytes(_: Int) {}

    func registerBodyMapping(_: FrameAllocation) -> Bool { true }

    func releaseBodyMapping(
        _ identity: FrameMappingIdentity,
        transferredBytes: Int
    ) -> Bool {
        guard munmap(identity.mappingBase, identity.mappedLength) == 0 else { return false }
        releaseRetainedBytes(transferredBytes)
        return true
    }
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

    func registerBodyMapping(_ allocation: FrameAllocation) -> Bool {
        handle.registerReceiveMapping(allocation)
    }

    func releaseBodyMapping(
        _ identity: FrameMappingIdentity,
        transferredBytes _: Int
    ) -> Bool {
        handle.releaseReceiveMapping(identity)
    }

    func cancel() {
        handle.cancel()
    }
}

final class LinuxFrameReader: @unchecked Sendable {
    private let source: any LinuxFrameByteSource
    private let lock = NSLock()
    private var inputFinished = false
    private var outstandingLease: FrameStorageLease?

    init(source: any LinuxFrameByteSource) {
        self.source = source
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

    private func waitForOutstandingFrame() async throws {
        let lease = lock.withLock { outstandingLease }
        guard let lease else { return }
        try await lease.waitForRelease()
        lock.withLock {
            if outstandingLease === lease {
                outstandingLease = nil
            }
        }
    }

    private func retainFrameForHandoff(_ lease: FrameStorageLease) {
        lock.lock()
        precondition(outstandingLease == nil)
        outstandingLease = lease
        lock.unlock()
    }

    func nextFrame() async throws -> RawFrame? {
        try await waitForOutstandingFrame()
        if hasFinishedInput() { return nil }

        let (length, headerFin) = try await readLength()
        guard let headerFin else {
            markInputFinished()
            return nil
        }
        if headerFin {
            throw LinuxTransportError.receive("the peer finished inside a frame header")
        }
        guard length >= 1 else {
            throw WireError.malformedFrame("zero-length frame")
        }
        guard length <= FrameCodec.maxFrameLength else {
            throw WireError.frameTooLarge(length)
        }

        let (rawType, typeFin) = try await readType()
        guard let typeFin else {
            throw LinuxTransportError.streamClosed
        }
        guard let type = FrameType(rawValue: rawType) else {
            throw WireError.unknownFrameType(rawType)
        }
        let bodyCount = Int(length) - 1
        let body: Data
        let bodyFin: Bool
        if bodyCount == 0 {
            body = Data()
            bodyFin = typeFin
        } else {
            if typeFin {
                throw LinuxTransportError.receive("the peer finished before the frame body")
            }
            let allocation = try FrameAllocation.mapped(count: bodyCount)
            guard source.registerBodyMapping(allocation) else {
                throw LinuxTransportError.receive("transport refused frame body mapping")
            }
            let lease = FrameStorageLease(identity: allocation.mappingIdentity) { [source] identity, transferred in
                source.releaseBodyMapping(identity, transferredBytes: transferred)
            }
            allocation.bindLease(lease)
            var offset = 0
            var finished = false
            while offset < bodyCount {
                let amount = min(bodyCount - offset, Int(REACH_MSQUIC_RECEIVE_COPY_QUANTUM))
                let read = try await readExactly(
                    into: allocation,
                    offset: offset,
                    count: amount,
                    releaseOnFailure: false,
                    onTransfer: lease.recordTransfer
                )
                guard let chunkFin = read.fin else {
                    throw LinuxTransportError.streamClosed
                }
                offset += amount
                finished = chunkFin
                if finished && offset < bodyCount {
                    throw LinuxTransportError.receive("the peer finished inside a frame")
                }
            }
            let transferred = allocation.transferToData()
            body = transferred.0
            retainFrameForHandoff(lease)
            bodyFin = finished
        }
        if bodyFin {
            markInputFinished()
        }
        return RawFrame(type: type, body: body)
    }

    private func readLength() async throws -> (UInt32, Bool?) {
        let allocation = FrameAllocation(count: 4)
        let read = try await readExactly(into: allocation, count: 4)
        defer { source.releaseRetainedBytes(read.retainedBytes) }
        guard read.fin != nil else { return (0, nil) }
        var length: UInt32 = 0
        for index in 0 ..< 4 {
            length = (length << 8) | UInt32(allocation.byte(at: index))
        }
        return (length, read.fin)
    }

    private func readType() async throws -> (UInt8, Bool?) {
        let allocation = FrameAllocation(count: 1)
        let read = try await readExactly(into: allocation, count: 1)
        defer { source.releaseRetainedBytes(read.retainedBytes) }
        guard read.fin != nil else { return (0, nil) }
        return (allocation.byte(at: 0), read.fin)
    }

    private func readExactly(
        into allocation: FrameAllocation,
        offset initialOffset: Int = 0,
        count: Int,
        releaseOnFailure: Bool = true,
        onTransfer: ((Int) -> Void)? = nil
    ) async throws -> (fin: Bool?, retainedBytes: Int) {
        var offset = initialOffset
        let end = initialOffset + count
        var sawFin = false
        do {
            while offset < end {
                try Task.checkCancellation()
                let result = await source.read(into: allocation, offset: offset, count: end - offset)
                switch result.status {
                case reachStatusOK:
                    guard result.count > 0 else {
                        throw LinuxTransportError.receive("the transport returned an empty receive")
                    }
                    offset += result.count
                    onTransfer?(result.count)
                    sawFin = result.fin
                    if sawFin && offset < end {
                        throw LinuxTransportError.receive("the peer finished inside a frame")
                    }
                case reachStatusTimeout:
                    continue
                case reachStatusClosed:
                    if offset == initialOffset && result.fin { return (nil, 0) }
                    throw LinuxTransportError.streamClosed
                default:
                    throw LinuxTransportError.receive("MsQuic receive status \(result.status)")
                }
            }
            return (sawFin, offset - initialOffset)
        } catch {
            if releaseOnFailure {
                source.releaseRetainedBytes(offset - initialOffset)
            }
            throw error
        }
    }

    func cancel() {
        lock.lock()
        let lease = outstandingLease
        lock.unlock()
        lease?.cancelWaiter()
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
