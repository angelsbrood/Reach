import Foundation
import Darwin
import DurableRootKeys
import DurableClientReceipts
import DurableSessionLifecycle

/// Each role persists a different raw origin and epoch. No clock conversion.
public final class RoleMonotonicClock: ClientClock, LifecycleClock {
    public let origin: UInt64, epoch: String, boot: String
    public var policy: String { "role-monotonic-ns-v1:"+epoch }
    private let rawNow: () throws -> UInt64, currentBoot: () throws -> String
    private let lock=NSLock()
    private var last: UInt64
    public init(origin: UInt64, epoch: String, boot: String,
        rawNow: @escaping () throws -> UInt64 = { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) },
        currentBoot: @escaping () throws -> String = { try RootKeyCodec.boot() }) throws {
        guard origin>0, RootKeyCodec.uuid(epoch), RootKeyCodec.uuid(boot) else { throw TransportRuntimeError.invalid }
        self.origin=origin; self.epoch=epoch; self.boot=boot; self.rawNow=rawNow; self.currentBoot=currentBoot; last=origin
        _=try now()
    }
    public func now() throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        let raw=try rawNow()
        guard try currentBoot()==boot, raw>=origin, raw>=last else { throw TransportRuntimeError.expired }
        let time=(raw-origin).addingReportingOverflow(1)
        guard !time.overflow, time.partialValue>0 else { throw TransportRuntimeError.invalid }
        last=raw; return time.partialValue
    }
}
