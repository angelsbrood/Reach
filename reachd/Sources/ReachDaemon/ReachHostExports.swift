@_exported import ReachHost

// Existing ReachDaemon tests construct expected admission snapshots through
// the former same-module memberwise initializer. Keep that test seam in the
// Apple composition without adding it to the portable host's API.
extension SlotAdmission.Counters {
    package init(
        active: Int = 0,
        waiting: Int = 0,
        admitted: UInt64 = 0,
        refused: UInt64 = 0,
        cancelled: UInt64 = 0,
        timedOut: UInt64 = 0
    ) {
        self = .expectedValue(
            active: active,
            waiting: waiting,
            admitted: admitted,
            refused: refused,
            cancelled: cancelled,
            timedOut: timedOut
        )
    }
}
