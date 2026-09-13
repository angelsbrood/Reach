import Foundation
import Darwin

public struct Sample: Codable, Equatable, Sendable {
    public let boot: String
    public let incarnation: String
    public let nanoseconds: UInt64
    public init(boot: String, incarnation: String, nanoseconds: UInt64) {
        self.boot = boot; self.incarnation = incarnation; self.nanoseconds = nanoseconds
    }
}

/// Injection is for explicit test fixtures. The qualification executable uses only SystemClock.
public protocol PolicyClock: AnyObject {
    func sample() throws -> Sample
}

public final class SystemClock: PolicyClock {
    private static let processIncarnation = UUID().uuidString.lowercased()
    public init() {}
    public func sample() throws -> Sample {
        var bytes = [CChar](repeating: 0, count: 128)
        var size = bytes.count
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0,
              size > 1, size <= bytes.count else { throw Refusal.clock }
        let boot = String(decoding: bytes.prefix(size - 1).map { UInt8(bitPattern: $0) }, as: UTF8.self).lowercased()
        guard validUUID(boot) else { throw Refusal.clock }
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom > 0
        else { throw Refusal.clock }
        let ticks = mach_continuous_time()
        let d = UInt64(timebase.denom), n = UInt64(timebase.numer)
        // Quotient/remainder conversion avoids overflowing ticks * numer.
        let whole = try multiply(ticks / d, n)
        let fraction = try multiply(ticks % d, n) / d
        return Sample(boot: boot, incarnation: Self.processIncarnation,
                      nanoseconds: try add(whole, fraction))
    }
}

/// Each serial owner latches epoch faults and observed regressions for its whole incarnation.
final class ClockTracker {
    let clock: any PolicyClock
    private(set) var last: Sample
    private(set) var invalid = false
    init(_ clock: any PolicyClock) throws {
        self.clock = clock; last = try clock.sample()
        guard validUUID(last.boot), validUUID(last.incarnation) else { throw Refusal.clock }
    }
    func invalidate() { invalid = true }
    func read() throws -> Sample {
        guard !invalid else { throw Refusal.invalidated }
        do {
            let now = try clock.sample()
            guard now.boot == last.boot, now.incarnation == last.incarnation,
                  now.nanoseconds >= last.nanoseconds else { throw Refusal.clock }
            last = now
            return now
        } catch { invalid = true; throw error }
    }
}
