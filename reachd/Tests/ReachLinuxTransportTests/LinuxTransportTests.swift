import CReachLinuxMsQuic
import Foundation
import Glibc
import ReachWire
import Testing
@testable import ReachLinuxTransport

private final class ScriptedByteSource: LinuxFrameByteSource, @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: Data
    private let fragmentSize: Int
    private var cancelled = false
    private var retainedBytes = 0
    private var peakRetainedBytes = 0
    private var readRequests = 0
    private var bodyDestinations: [UInt] = []
    private var mappingReleaseCount = 0
    private let failAfterReadRequests: Int?
    private let refuseMapping: Bool
    private let lifetimeAnchor: AnyObject?
    private let mappingReleaseObserver: @Sendable () -> Void

    init(
        _ bytes: Data,
        fragmentSize: Int,
        failAfterReadRequests: Int? = nil,
        refuseMapping: Bool = false,
        lifetimeAnchor: AnyObject? = nil,
        mappingReleaseObserver: @escaping @Sendable () -> Void = {}
    ) {
        self.bytes = bytes
        self.fragmentSize = max(fragmentSize, 1)
        self.failAfterReadRequests = failAfterReadRequests
        self.refuseMapping = refuseMapping
        self.lifetimeAnchor = lifetimeAnchor
        self.mappingReleaseObserver = mappingReleaseObserver
    }

    func read(into allocation: FrameAllocation, offset: Int, count: Int) async -> BlockingRead {
        readLocked(into: allocation, offset: offset, count: count)
    }

    private func readLocked(
        into allocation: FrameAllocation,
        offset: Int,
        count: Int
    ) -> BlockingRead {
        lock.lock()
        defer { lock.unlock() }
        readRequests += 1
        if let failAfterReadRequests, readRequests > failAfterReadRequests {
            return BlockingRead(status: Int32(REACH_MSQUIC_REFUSED), count: 0, fin: false)
        }
        if cancelled {
            return BlockingRead(status: Int32(REACH_MSQUIC_ERROR), count: 0, fin: false)
        }
        if bytes.isEmpty {
            return BlockingRead(status: Int32(REACH_MSQUIC_CLOSED), count: 0, fin: true)
        }
        let amount = min(count, fragmentSize, bytes.count)
        let prefix = bytes.prefix(amount)
        prefix.withUnsafeBytes { source in
            allocation.pointer.advanced(by: offset).copyMemory(
                from: source.baseAddress!,
                byteCount: amount
            )
        }
        if allocation.mappedLength > 0 {
            bodyDestinations.append(UInt(bitPattern: allocation.pointer))
        }
        bytes.removeFirst(amount)
        retainedBytes += amount
        peakRetainedBytes = max(peakRetainedBytes, retainedBytes)
        return BlockingRead(
            status: Int32(REACH_MSQUIC_OK),
            count: amount,
            fin: bytes.isEmpty
        )
    }

    func releaseRetainedBytes(_ count: Int) {
        lock.lock()
        precondition(count >= 0 && count <= retainedBytes)
        retainedBytes -= count
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    func registerBodyMapping(_: FrameAllocation) -> Bool { !refuseMapping }

    func releaseBodyMapping(
        _ identity: FrameMappingIdentity,
        transferredBytes: Int
    ) -> Bool {
        guard munmap(identity.mappingBase, identity.mappedLength) == 0 else { return false }
        lock.lock()
        precondition(transferredBytes >= 0 && transferredBytes <= retainedBytes)
        retainedBytes -= transferredBytes
        mappingReleaseCount += 1
        lock.unlock()
        mappingReleaseObserver()
        return true
    }

    var retained: Int {
        lock.lock()
        defer { lock.unlock() }
        return retainedBytes
    }

    var peakRetained: Int {
        lock.lock()
        defer { lock.unlock() }
        return peakRetainedBytes
    }


    var snapshot: (reads: Int, destinations: [UInt], releases: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (readRequests, bodyDestinations, mappingReleaseCount)
    }
}

private final class WaitingByteSource: LinuxFrameByteSource, @unchecked Sendable {
    private let lock = NSLock()
    private var waiter: CheckedContinuation<BlockingRead, Never>?
    private var cancelled = false
    private var completionCount = 0

    func read(into: FrameAllocation, offset: Int, count: Int) async -> BlockingRead {
        await withCheckedContinuation { continuation in
            lock.lock()
            if cancelled {
                completionCount += 1
                lock.unlock()
                continuation.resume(returning: BlockingRead(
                    status: Int32(REACH_MSQUIC_ERROR),
                    count: 0,
                    fin: false
                ))
            } else {
                precondition(waiter == nil)
                waiter = continuation
                lock.unlock()
            }
        }
    }

    func cancel() {
        let continuation: CheckedContinuation<BlockingRead, Never>?
        lock.lock()
        cancelled = true
        continuation = waiter
        waiter = nil
        if continuation != nil { completionCount += 1 }
        lock.unlock()
        continuation?.resume(returning: BlockingRead(
            status: Int32(REACH_MSQUIC_ERROR),
            count: 0,
            fin: false
        ))
    }

    var isWaiting: Bool {
        lock.lock()
        defer { lock.unlock() }
        return waiter != nil
    }

    var completions: Int {
        lock.lock()
        defer { lock.unlock() }
        return completionCount
    }
}

private final class MappingReleaseProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var releaseCount = 0

    func release(_ identity: FrameMappingIdentity, transferredBytes: Int) -> Bool {
        guard transferredBytes == identity.logicalLength,
              munmap(identity.mappingBase, identity.mappedLength) == 0 else { return false }
        lock.withLock { releaseCount += 1 }
        return true
    }

    var releases: Int {
        lock.withLock { releaseCount }
    }
}

private final class DataOwnerBox: @unchecked Sendable {
    private var value: Data?

    init(_ value: Data) {
        self.value = value
    }

    func makeCopyOwner() -> DataOwnerBox {
        guard let value else { preconditionFailure("data owner was already cleared") }
        return DataOwnerBox(value)
    }

    func observe<Result>(_ body: (Data) throws -> Result) rethrows -> Result {
        guard let value else { preconditionFailure("data owner was already cleared") }
        return try body(value)
    }

    func clearWithoutReading() {
        value = nil
    }
}

private func nextBodyOwner(from reader: LinuxFrameReader) async throws -> DataOwnerBox {
    guard let frame = try await reader.nextFrame() else {
        throw LinuxTransportError.streamClosed
    }
    return DataOwnerBox(frame.body)
}

private func encodedHello() throws -> Data {
    try FrameCodec.encode(Hello(versions: [1, 0], client: "linux-transport-test"))
}

private struct FocusedDiagnosticTimeout: Error {}

private let focusedDiagnosticNanoseconds: UInt64 = 10_000_000_000

private func withFocusedDiagnosticDeadline<Value: Sendable>(
    onTimeout: @escaping @Sendable () -> Void,
    operation: @escaping @Sendable () async throws -> Value
) async throws -> Value {
    try await withThrowingTaskGroup(of: Value.self) { group in
        group.addTask {
            try await withTaskCancellationHandler(
                operation: operation,
                onCancel: onTimeout
            )
        }
        group.addTask {
            try await Task.sleep(nanoseconds: focusedDiagnosticNanoseconds)
            throw FocusedDiagnosticTimeout()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
            throw FocusedDiagnosticTimeout()
        }
        return result
    }
}

private final class WaiterInstalledProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var installed = false
    private var cancelled = false
    private var waiter: CheckedContinuation<Void, any Error>?

    func signal() {
        let continuation: CheckedContinuation<Void, any Error>?
        lock.lock()
        installed = true
        continuation = waiter
        waiter = nil
        lock.unlock()
        continuation?.resume()
    }

    func wait() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if installed {
                    lock.unlock()
                    continuation.resume()
                } else if cancelled || Task.isCancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                } else {
                    precondition(waiter == nil)
                    waiter = continuation
                    lock.unlock()
                }
            }
        } onCancel: {
            self.cancel()
        }
    }

    func cancel() {
        let continuation: CheckedContinuation<Void, any Error>?
        lock.lock()
        cancelled = true
        continuation = waiter
        waiter = nil
        lock.unlock()
        continuation?.resume(throwing: CancellationError())
    }
}

private final class LifetimeOrderProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [String] = []

    func record(_ event: String) {
        lock.withLock { recorded.append(event) }
    }

    var events: [String] {
        lock.withLock { recorded }
    }
}

private final class NextFrameTaskBox: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<RawFrame?, any Error>?

    init(reader: LinuxFrameReader) {
        task = Task { try await reader.nextFrame() }
    }

    func pingNonce() async throws -> UInt64 {
        let task = lock.withLock { self.task }
        guard let task else { throw LinuxTransportError.streamClosed }
        guard let frame = try await task.value else {
            throw LinuxTransportError.streamClosed
        }
        return try frame.decode(Ping.self).nonce
    }

    func cancel() {
        lock.withLock { task }?.cancel()
    }

    func clearWithoutReading() {
        lock.withLock { task = nil }
    }
}

private func syntheticPointer(_ value: UInt) -> OpaquePointer {
    OpaquePointer(bitPattern: value)!
}

private func mappedBodyOwner(
    retaining stream: StreamHandle,
    order: LifetimeOrderProbe
) async throws -> DataOwnerBox {
    let source = ScriptedByteSource(
        try FrameCodec.encode(Ping(nonce: 11)),
        fragmentSize: 17,
        lifetimeAnchor: stream,
        mappingReleaseObserver: { order.record("mapping") }
    )
    let reader = LinuxFrameReader(source: source)
    let owner = try await withFocusedDiagnosticDeadline(
        onTimeout: reader.cancel,
        operation: { try await nextBodyOwner(from: reader) }
    )
    reader.cancel()
    return owner
}

private func proveZeroBodyDoesNotLeak(retaining stream: StreamHandle) async throws {
    let source = ScriptedByteSource(
        Data([0, 0, 0, 1, FrameType.ping.rawValue]),
        fragmentSize: 5,
        lifetimeAnchor: stream
    )
    let reader = LinuxFrameReader(source: source)
    let frame = try await withFocusedDiagnosticDeadline(
        onTimeout: reader.cancel,
        operation: reader.nextFrame
    )
    #expect(frame?.type == .ping)
    #expect(frame?.body.isEmpty == true)
}

private func provePretransferRefusalDoesNotLeak(retaining stream: StreamHandle) async throws {
    let source = ScriptedByteSource(
        try FrameCodec.encode(Ping(nonce: 12)),
        fragmentSize: 17,
        refuseMapping: true,
        lifetimeAnchor: stream
    )
    let reader = LinuxFrameReader(source: source)
    do {
        _ = try await withFocusedDiagnosticDeadline(
            onTimeout: reader.cancel,
            operation: reader.nextFrame
        )
        Issue.record("mapping refusal unexpectedly produced a frame")
    } catch is FocusedDiagnosticTimeout {
        throw FocusedDiagnosticTimeout()
    } catch {
        #expect(source.retained == 0)
        #expect(source.snapshot.releases == 0)
    }
}

@Suite(.serialized) struct LinuxTransportTests {
    @Test func exactMsQuicPreviewLayoutAndFiniteCeilings() {
        var size = 0
        var alignment = 0
        var offsets = [Int](repeating: 0, count: 6)
        let status = offsets.withUnsafeMutableBufferPointer { buffer in
            reach_msquic_version_settings_layout(&size, &alignment, buffer.baseAddress)
        }
        #expect(status == Int32(REACH_MSQUIC_OK))
        #expect(size == 40)
        #expect(alignment == 8)
        #expect(offsets == [0, 8, 16, 24, 28, 32])
        #expect(REACH_MSQUIC_MAX_CONNECTIONS == 16)
        #expect(REACH_MSQUIC_MAX_STREAMS_PER_CONNECTION == 8)
        #expect(REACH_MSQUIC_MAX_STREAMS_PROCESS == 16)
        #expect(REACH_MSQUIC_MAX_FRAME_LENGTH == 16 * 1024 * 1024)
        #expect(REACH_MSQUIC_STREAM_RECEIVE_LIMIT == 16 * 1024 * 1024 + 4)
        #expect(REACH_MSQUIC_PROCESS_RECEIVE_LIMIT == 256 * 1024 * 1024)
        #expect(REACH_MSQUIC_RECEIVE_COPY_QUANTUM == 64 * 1024)
        #expect(REACH_MSQUIC_STREAM_PHYSICAL_RECEIVE_LIMIT ==
            16 * 1024 * 1024 + 4 + 64 * 1024)
        #expect(REACH_MSQUIC_PROCESS_PHYSICAL_RECEIVE_LIMIT == 257 * 1024 * 1024)
    }

    @Test func callbackScopedDescriptorsAreCopiedBeforeDeferredMultiBufferRead() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_DEFERRED_MULTI_BUFFER),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func pendingReceiveCompletesExactlyOnceAcrossRepeatedLocalCancellation() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_LOCAL_CANCELLATION),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func pendingReceiveCompletesExactlyOnceBeforePeerAbortSettlement() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_PEER_ABORT),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func readAndShutdownCloseRaceHasOneReceiveCompletionAndNoSurvivor() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_CLOSE_RACE),
            512
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func zeroBufferZeroDataFinIsValidAndEmptyWithoutFinRefuses() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_EMPTY_FIN),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func sixteenStreamCombinedRetentionSuspendsAndResumesAtExactCeilings() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_RETENTION_BUDGET),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func mappedMaximumFramePrechargesBeforeCopyAndTracksKernelResidency() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_MAPPED_PRECHARGE),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func mappedTailBodyPrechargesItsPageAndValidatesTheCanonicalOffset() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_MAPPED_TAIL_BODY),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func sixteenMappedMaximumFramesStayWithinPhysicalProcessCeiling() {
        #expect(reach_msquic_receive_contract_test(
            UInt32(REACH_MSQUIC_RECEIVE_TEST_MAPPED_SIXTEEN_STREAMS),
            1
        ) == Int32(REACH_MSQUIC_OK))
    }

    @Test func listenerStopAndDestructorReuseOneAbsoluteMonotonicDeadline() {
        for scenario in [
            REACH_MSQUIC_SHUTDOWN_TEST_SUCCESS,
            REACH_MSQUIC_SHUTDOWN_TEST_TIMEOUT_REUSE,
            REACH_MSQUIC_SHUTDOWN_TEST_DESTRUCTOR_REUSE,
        ] {
            #expect(reach_msquic_shutdown_contract_test(UInt32(scenario)) ==
                Int32(REACH_MSQUIC_OK))
        }
        let now = reach_msquic_monotonic_now_nanoseconds()
        let deadline = LinuxShutdownDeadline(
            monotonicNanoseconds: now + LinuxShutdownDeadline.budgetNanoseconds
        )
        #expect(!deadline.hasExpired(now: now))
        #expect(deadline.hasExpired(now: deadline.monotonicNanoseconds))
    }

    @Test func connectionConfigurationStopLatchAndLifetimeAreExactAcrossReentrantSettlement() {
        var result = reach_msquic_configuration_contract_result()
        #expect(reach_msquic_configuration_contract_test(10_000, &result) ==
            Int32(REACH_MSQUIC_OK))
        #expect(result.attempts == 60_000)
        #expect(result.succeeded == 30_000)
        #expect(result.failed == 30_000)
        #expect(result.connection_closes == 30_000)
        #expect(result.registration_removals == 60_000)
        #expect(result.context_releases == 60_000)
        #expect(result.refused_connections == 30_000)
        #expect(result.active_connections == 0)
        #expect(result.shutdown_calls == 10_000)
        #expect(result.shutdown_completions == 40_000)
        #expect(result.stop_latches == 20_000)
        #expect(result.stop_deadline_settlements == 20_000)
        #expect(result.callback_dispatches == 40_000)
        #expect(result.context_release_events == 60_000)
        #expect(result.late_dispatch_attempts == 60_000)
        #expect(result.late_dispatch_refusals == 60_000)
        #expect(result.post_release_callback_accesses == 0)
    }

    @Test func packetizationDoesNotChangeFrameDecoding() async throws {
        let encoded = try encodedHello()
        for fragment in [1, 2, 3, 5, 127, encoded.count, encoded.count * 2] {
            let source = ScriptedByteSource(encoded, fragmentSize: fragment)
            let reader = LinuxFrameReader(source: source)
            do {
                let frame = try #require(await reader.nextFrame())
                #expect(try frame.decode(Hello.self) == Hello(
                    versions: [1, 0],
                    client: "linux-transport-test"
                ))
            }
            #expect(try await reader.nextFrame() == nil)
        }
    }

    @Test func manyTinyFragmentsRetainOneFiniteFrame() async throws {
        let text = String(repeating: "x", count: 64 * 1024)
        let encoded = try FrameCodec.encode(ErrorFrame(code: "fixed", message: text))
        let source = ScriptedByteSource(encoded, fragmentSize: 1)
        let reader = LinuxFrameReader(source: source)
        do {
            let frame = try #require(await reader.nextFrame())
            let decoded = try frame.decode(ErrorFrame.self)
            #expect(decoded.code == "fixed")
            #expect(decoded.message.utf8.count == 64 * 1024)
        }
        #expect(try await reader.nextFrame() == nil)
        #expect(source.retained == 0)
        #expect(source.peakRetained <= encoded.count)
    }

    @Test func referenceBackedDataKeepsSmallAndMaximumMappingIdentity() throws {
        for count in [1, Int(REACH_MSQUIC_MAX_FRAME_LENGTH) - 1] {
            let allocation = try FrameAllocation.mapped(count: count)
            allocation.pointer.storeBytes(of: UInt8(0x5a), as: UInt8.self)
            if count > 1 {
                allocation.pointer.advanced(by: count - 1).storeBytes(
                    of: UInt8(0xa5),
                    as: UInt8.self
                )
            }
            let identity = allocation.mappingIdentity
            #expect(identity.mappingBase.advanced(by: identity.bodyOffset) == identity.pointer)
            #expect(identity.bodyOffset == (count < identity.pageSize ? identity.pageSize - count : 0))
            let probe = MappingReleaseProbe()
            let lease = FrameStorageLease(identity: identity, releaser: probe.release)
            lease.recordTransfer(count)
            allocation.bindLease(lease)

            var body: Data? = allocation.transferToData().0
            #expect(body?.count == count)
            #expect(body?.first == 0x5a)
            #expect(body?.last == (count == 1 ? 0x5a : 0xa5))
            #expect(body?.withUnsafeBytes { $0.baseAddress } == UnsafeRawPointer(identity.pointer))
            var copy: Data? = body
            body = nil
            #expect(probe.releases == 0)
            #expect(copy?.withUnsafeBytes { $0.baseAddress } == UnsafeRawPointer(identity.pointer))
            copy = nil
            #expect(probe.releases == 1)
        }
    }

    @Test func mutatingAReferenceBackedCopyDetachesWithoutCorruptingTheMapping() throws {
        let allocation = try FrameAllocation.mapped(count: 2)
        allocation.pointer.storeBytes(of: UInt8(0x11), as: UInt8.self)
        allocation.pointer.advanced(by: 1).storeBytes(of: UInt8(0x22), as: UInt8.self)
        let identity = allocation.mappingIdentity
        let probe = MappingReleaseProbe()
        let lease = FrameStorageLease(identity: identity, releaser: probe.release)
        lease.recordTransfer(2)
        allocation.bindLease(lease)

        var original: Data? = allocation.transferToData().0
        var mutated = original!
        mutated[mutated.startIndex] = 0x33
        #expect(original == Data([0x11, 0x22]))
        #expect(mutated == Data([0x33, 0x22]))
        #expect(original?.withUnsafeBytes { $0.baseAddress } == UnsafeRawPointer(identity.pointer))
        #expect(mutated.withUnsafeBytes { $0.baseAddress } != UnsafeRawPointer(identity.pointer))
        #expect(probe.releases == 0)
        original = nil
        #expect(probe.releases == 1)
    }

    @Test func sharedDataLeaseBackpressuresNextFrameUntilFinalCopyReleases() async throws {
        let first = try FrameCodec.encode(Ping(nonce: 7))
        let second = try FrameCodec.encode(Ping(nonce: 8))
        let source = ScriptedByteSource(first + second, fragmentSize: 17)
        let waiterInstalled = WaiterInstalledProbe()
        let reader = LinuxFrameReader(
            source: source,
            outstandingWaiterInstalledObserver: waiterInstalled.signal
        )
        let held = try await withFocusedDiagnosticDeadline(
            onTimeout: reader.cancel,
            operation: { try await nextBodyOwner(from: reader) }
        )
        let copy = held.makeCopyOwner()
        let pointer = held.observe { value in
            value.withUnsafeBytes { UInt(bitPattern: $0.baseAddress!) }
        }
        #expect(source.snapshot.destinations.allSatisfy { $0 == pointer })
        copy.observe { value in
            #expect(value.withUnsafeBytes { UInt(bitPattern: $0.baseAddress!) } == pointer)
        }

        let readsBeforeWait = source.snapshot.reads
        let retainedBeforeWait = source.retained
        #expect(retainedBeforeWait > 0)
        let next = NextFrameTaskBox(reader: reader)
        do {
            try await withFocusedDiagnosticDeadline(
                onTimeout: waiterInstalled.cancel,
                operation: waiterInstalled.wait
            )
            #expect(source.snapshot.reads == readsBeforeWait)
            #expect(source.snapshot.releases == 0)
            #expect(source.retained == retainedBeforeWait)

            held.clearWithoutReading()
            #expect(source.snapshot.reads == readsBeforeWait)
            #expect(source.snapshot.releases == 0)
            #expect(source.retained == retainedBeforeWait)

            copy.clearWithoutReading()
            let nonce = try await withFocusedDiagnosticDeadline(
                onTimeout: {
                    next.cancel()
                    reader.cancel()
                },
                operation: next.pingNonce
            )
            #expect(nonce == 8)
            #expect(source.snapshot.releases == 1)
            next.clearWithoutReading()
            let terminal = try await withFocusedDiagnosticDeadline(
                onTimeout: reader.cancel,
                operation: reader.nextFrame
            )
            #expect(terminal == nil)
            #expect(source.snapshot.releases == 2)
        } catch {
            next.cancel()
            reader.cancel()
            next.clearWithoutReading()
            throw error
        }
    }

    @Test func cancelDoesNotReleaseRetainedMappedBodyEarly() async throws {
        let encoded = try FrameCodec.encode(Ping(nonce: 9))
        let source = ScriptedByteSource(encoded, fragmentSize: encoded.count)
        let reader = LinuxFrameReader(source: source)
        let held = try await withFocusedDiagnosticDeadline(
            onTimeout: reader.cancel,
            operation: { try await nextBodyOwner(from: reader) }
        )
        let expected = held.makeCopyOwner()
        reader.cancel()
        #expect(source.retained > 0)
        #expect(source.snapshot.releases == 0)
        held.observe { heldValue in
            expected.observe { expectedValue in
                #expect(heldValue == expectedValue)
            }
        }
        held.clearWithoutReading()
        #expect(source.snapshot.releases == 0)
        expected.clearWithoutReading()
        #expect(source.snapshot.releases == 1)
    }

    @Test func mappedBodyRetainsListenerUntilStreamReleaseCompletes() async throws {
        let order = LifetimeOrderProbe()
        var listener: ListenerHandle? = ListenerHandle(
            testing: syntheticPointer(0x1000),
            destroyer: { _ in order.record("listener") }
        )
        weak var listenerReference = listener
        var stream: StreamHandle? = StreamHandle(
            transferring: syntheticPointer(0x2000),
            listenerOwner: listener!,
            releaser: { _ in order.record("stream") }
        )
        #expect(stream?.retainsListener(listener!) == true)
        weak var streamReference = stream
        let bodyOwner = try await mappedBodyOwner(retaining: stream!, order: order)

        listener = nil
        stream = nil
        #expect(listenerReference != nil)
        #expect(streamReference != nil)
        #expect(order.events.isEmpty)

        bodyOwner.clearWithoutReading()
        #expect(streamReference == nil)
        #expect(listenerReference == nil)
        #expect(order.events == ["mapping", "stream", "listener"])
    }

    @Test func listenerOwnerIsSharedAcrossAcceptedStreamsAndDestroyedLast() {
        let order = LifetimeOrderProbe()
        var listener: ListenerHandle? = ListenerHandle(
            testing: syntheticPointer(0x3000),
            destroyer: { _ in order.record("listener") }
        )
        weak var listenerReference = listener
        var first: StreamHandle? = StreamHandle(
            transferring: syntheticPointer(0x4000),
            listenerOwner: listener!,
            releaser: { _ in order.record("stream-1") }
        )
        var second: StreamHandle? = StreamHandle(
            transferring: syntheticPointer(0x5000),
            listenerOwner: listener!,
            releaser: { _ in order.record("stream-2") }
        )
        #expect(first?.retainsListener(listener!) == true)
        #expect(second?.retainsListener(listener!) == true)

        listener = nil
        first = nil
        #expect(listenerReference != nil)
        #expect(order.events == ["stream-1"])
        second = nil
        #expect(listenerReference == nil)
        #expect(order.events == ["stream-1", "stream-2", "listener"])
    }

    @Test func zeroBodyAndPretransferRefusalDoNotLeakOrDestroyListenerEarly() async throws {
        for scenario in ["zero-body", "pretransfer-refusal"] {
            let order = LifetimeOrderProbe()
            var listener: ListenerHandle? = ListenerHandle(
                testing: syntheticPointer(0x6000),
                destroyer: { _ in order.record("listener") }
            )
            weak var listenerReference = listener
            var stream: StreamHandle? = StreamHandle(
                transferring: syntheticPointer(0x7000),
                listenerOwner: listener!,
                releaser: { _ in order.record("stream") }
            )
            listener = nil
            #expect(listenerReference != nil)
            if scenario == "zero-body" {
                try await proveZeroBodyDoesNotLeak(retaining: stream!)
            } else {
                try await provePretransferRefusalDoesNotLeak(retaining: stream!)
            }
            #expect(order.events.isEmpty)
            stream = nil
            #expect(listenerReference == nil)
            #expect(order.events == ["stream", "listener"])
        }
    }

    @Test func productionAcceptEdgeRequiresAndForwardsTheExactListenerOwner() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let sourceFile = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/ReachLinuxTransport/LinuxTransport.swift")
        let source = try String(contentsOf: sourceFile, encoding: .utf8)
        #expect(source.contains(
            "fileprivate init(transferring pointer: OpaquePointer, listenerOwner: ListenerHandle)"
        ))
        #expect(source.contains(
            "let handle = StreamHandle(transferring: pointer, listenerOwner: listenerOwner)"
        ))
        #expect(source.contains(
            "return LinuxSessionStream(transferring: pointer, listenerOwner: handle)"
        ))
        #expect(!source.contains("return LinuxSessionStream(transferring: pointer)"))
    }

    @Test func mappingRefusalAndPartialBodyFailureReleaseExactlyOnceWithoutHandoff() async throws {
        let encoded = try FrameCodec.encode(Ping(nonce: 10))
        let refused = ScriptedByteSource(
            encoded,
            fragmentSize: encoded.count,
            refuseMapping: true
        )
        await #expect(throws: (any Error).self) {
            _ = try await LinuxFrameReader(source: refused).nextFrame()
        }
        #expect(refused.retained == 0)
        #expect(refused.snapshot.releases == 0)
        #expect(refused.snapshot.destinations.isEmpty)

        let partial = ScriptedByteSource(
            encoded,
            fragmentSize: 4,
            failAfterReadRequests: 3
        )
        await #expect(throws: (any Error).self) {
            _ = try await LinuxFrameReader(source: partial).nextFrame()
        }
        #expect(partial.retained == 0)
        #expect(partial.snapshot.releases == 1)
        #expect(Set(partial.snapshot.destinations).count == 1)
    }

    @Test func malformedLengthTypeAndTruncationRefuse() async {
        let zero = Data([0, 0, 0, 0])
        await #expect(throws: (any Error).self) {
            _ = try await LinuxFrameReader(
                source: ScriptedByteSource(zero, fragmentSize: 4)
            ).nextFrame()
        }

        let oversized = UInt32(FrameCodec.maxFrameLength + 1)
        let oversizedHeader = Data([
            UInt8((oversized >> 24) & 0xff), UInt8((oversized >> 16) & 0xff),
            UInt8((oversized >> 8) & 0xff), UInt8(oversized & 0xff),
        ])
        await #expect(throws: (any Error).self) {
            _ = try await LinuxFrameReader(
                source: ScriptedByteSource(oversizedHeader, fragmentSize: 4)
            ).nextFrame()
        }

        let unknown = Data([0, 0, 0, 1, 0xff])
        await #expect(throws: (any Error).self) {
            _ = try await LinuxFrameReader(
                source: ScriptedByteSource(unknown, fragmentSize: 5)
            ).nextFrame()
        }

        let truncated = Data([0, 0, 0, 4, FrameType.hello.rawValue, 0x7b])
        await #expect(throws: (any Error).self) {
            _ = try await LinuxFrameReader(
                source: ScriptedByteSource(truncated, fragmentSize: 2)
            ).nextFrame()
        }
    }

    @Test func cancellationSettlesAWaitingReaderOnce() async {
        let source = WaitingByteSource()
        let reader = LinuxFrameReader(source: source)
        let task = Task { try await reader.nextFrame() }
        while !source.isWaiting { await Task.yield() }
        reader.cancel()
        reader.cancel()
        await #expect(throws: (any Error).self) {
            _ = try await task.value
        }
        #expect(source.completions == 1)
    }

    @Test func credentialFailureOccursBeforeAnyListenerIsReturned() {
        #expect(throws: (any Error).self) {
            _ = try ReachLinuxListener(configuration: LinuxListenerConfiguration(
                address: "127.0.0.1",
                port: 54_431,
                clusterCACertificatePath: "/nonexistent/reach-ca.pem",
                serverCertificateChainPath: "/nonexistent/reach-server.pem",
                serverPrivateKeyPath: "/nonexistent/reach-server-key.pem"
            ))
        }
    }
}
