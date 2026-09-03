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

    init(_ bytes: Data, fragmentSize: Int) {
        self.bytes = bytes
        self.fragmentSize = max(fragmentSize, 1)
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

private func encodedHello() throws -> Data {
    try FrameCodec.encode(Hello(versions: [1, 0], client: "linux-transport-test"))
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

    @Test func packetizationDoesNotChangeFrameDecoding() async throws {
        let encoded = try encodedHello()
        for fragment in [1, 2, 3, 5, 127, encoded.count, encoded.count * 2] {
            let source = ScriptedByteSource(encoded, fragmentSize: fragment)
            let reader = LinuxFrameReader(source: source)
            let frame = try #require(await reader.nextFrame())
            #expect(try frame.decode(Hello.self) == Hello(
                versions: [1, 0],
                client: "linux-transport-test"
            ))
            #expect(try await reader.nextFrame() == nil)
        }
    }

    @Test func manyTinyFragmentsRetainOneFiniteFrame() async throws {
        let text = String(repeating: "x", count: 64 * 1024)
        let encoded = try FrameCodec.encode(ErrorFrame(code: "fixed", message: text))
        let source = ScriptedByteSource(encoded, fragmentSize: 1)
        let reader = LinuxFrameReader(source: source)
        let frame = try #require(await reader.nextFrame())
        let decoded = try frame.decode(ErrorFrame.self)
        #expect(decoded.code == "fixed")
        #expect(decoded.message.utf8.count == 64 * 1024)
        #expect(try await reader.nextFrame() == nil)
        #expect(source.retained == 0)
        #expect(source.peakRetained <= encoded.count)
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
