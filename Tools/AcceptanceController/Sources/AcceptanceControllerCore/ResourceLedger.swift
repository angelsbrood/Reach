import Foundation

public enum ConstraintKind: String, Codable, Sendable { case maximum, zero, exact }
public enum MeasurementKind: String, Codable, Sendable { case counter, physicalBytes, logicalBytes, durationNanoseconds, observedPeak }

public enum RunDimension: String, Codable, CaseIterable, Sendable {
    case frozenActions
    case actionProcessLaunches
    case simultaneouslyLiveActions
    case actionWorkWindowNanoseconds
    case actionSettlementReserveNanoseconds
    case runWallNanoseconds
    case stdoutPhysicalBytes
    case stderrPhysicalBytes
    case combinedOutputPhysicalBytes
    case canonicalResultBytes
    case journalFiles
    case journalLogicalBytes
    case observedPeakPhysicalBytes
    case observedPeakLogicalBytes
    case termSignals
    case killSignals
    case notStartedRows
    case workloadLaunchesAfterStop
    case publicationAttempts
    case packetWriters
    case unsettledProcessGroups
}

public struct ResourceEntry: Codable, Equatable, Sendable {
    public var limit: Int64
    public var used: Int64?
    public var remaining: Int64?
    public var constraintKind: ConstraintKind
    public var measurementKind: MeasurementKind

    public init(limit: Int64, used: Int64, constraintKind: ConstraintKind, measurementKind: MeasurementKind) {
        self.limit = limit
        self.used = used
        self.remaining = constraintKind == .maximum ? limit - used : (used == limit ? 0 : nil)
        self.constraintKind = constraintKind
        self.measurementKind = measurementKind
    }
}

public struct RunResourceVector: Codable, Equatable, Sendable {
    public private(set) var entries: [String: ResourceEntry]

    public init(frozenActions: Int) {
        entries = [:]
        func entry(_ dimension: RunDimension, _ limit: Int64, _ used: Int64 = 0, _ kind: ConstraintKind = .maximum, _ measurement: MeasurementKind = .counter) -> (String, ResourceEntry) {
            (dimension.rawValue, ResourceEntry(limit: limit, used: used, constraintKind: kind, measurementKind: measurement))
        }
        entries = Dictionary(uniqueKeysWithValues: [
            entry(.frozenActions, 32, Int64(frozenActions)),
            entry(.actionProcessLaunches, 32),
            entry(.simultaneouslyLiveActions, 1),
            entry(.actionWorkWindowNanoseconds, 60_000_000_000, 0, .maximum, .durationNanoseconds),
            entry(.actionSettlementReserveNanoseconds, 6_000_000_000, 0, .maximum, .durationNanoseconds),
            entry(.runWallNanoseconds, 1_200_000_000_000, 0, .maximum, .durationNanoseconds),
            entry(.stdoutPhysicalBytes, 1_048_576, 0, .maximum, .physicalBytes),
            entry(.stderrPhysicalBytes, 1_048_576, 0, .maximum, .physicalBytes),
            entry(.combinedOutputPhysicalBytes, 4_194_304, 0, .maximum, .physicalBytes),
            entry(.canonicalResultBytes, 1_048_576, 0, .maximum, .logicalBytes),
            entry(.journalFiles, 96),
            entry(.journalLogicalBytes, 8_388_608, 0, .maximum, .logicalBytes),
            entry(.observedPeakPhysicalBytes, 268_435_456, 0, .maximum, .observedPeak),
            entry(.observedPeakLogicalBytes, 268_435_456, 0, .maximum, .observedPeak),
            entry(.termSignals, 32),
            entry(.killSignals, 32),
            entry(.notStartedRows, 32),
            entry(.workloadLaunchesAfterStop, 0, 0, .zero),
            entry(.publicationAttempts, 1, 0, .exact),
            entry(.packetWriters, 1, 1, .exact),
            entry(.unsettledProcessGroups, 0, 0, .zero),
        ])
    }

    public func entry(_ dimension: RunDimension) throws -> ResourceEntry {
        guard let entry = entries[dimension.rawValue] else { throw ControllerError.evidence("missing-dimension-\(dimension.rawValue)") }
        return entry
    }

    public mutating func charge(_ dimension: RunDimension, by amount: Int64 = 1) throws {
        guard amount >= 0, let entry = entries[dimension.rawValue], let used = entry.used else {
            throw ControllerError.evidence("invalid-charge-\(dimension.rawValue)")
        }
        let (next, overflow) = used.addingReportingOverflow(amount)
        guard !overflow else { throw ControllerError.evidence("arithmetic-overflow-\(dimension.rawValue)") }
        try assign(dimension, value: next)
    }

    public mutating func assign(_ dimension: RunDimension, value: Int64) throws {
        guard value >= 0, var entry = entries[dimension.rawValue] else {
            throw ControllerError.evidence("invalid-value-\(dimension.rawValue)")
        }
        switch entry.constraintKind {
        case .maximum:
            guard value <= entry.limit else { throw ControllerError.evidence("resource-limit-\(dimension.rawValue)") }
            entry.remaining = entry.limit - value
        case .zero:
            guard value == 0 else { throw ControllerError.evidence("zero-constraint-\(dimension.rawValue)") }
            entry.remaining = 0
        case .exact:
            guard value <= entry.limit else { throw ControllerError.evidence("exact-overrun-\(dimension.rawValue)") }
            entry.remaining = value == entry.limit ? 0 : nil
        }
        entry.used = value
        entries[dimension.rawValue] = entry
    }

    public mutating func markUnknown(_ dimension: RunDimension) throws {
        guard var entry = entries[dimension.rawValue] else { throw ControllerError.evidence("missing-dimension") }
        entry.used = nil
        entry.remaining = nil
        entries[dimension.rawValue] = entry
    }

    /// An observed crossing belongs in a STOP record, even though admission rejects it.
    public mutating func observeMaximum(_ dimension: RunDimension, value: Int64) throws {
        guard value >= 0, var entry = entries[dimension.rawValue], entry.constraintKind == .maximum else {
            throw ControllerError.evidence("invalid-observation")
        }
        entry.used = value; entry.remaining = entry.limit - value
        entries[dimension.rawValue] = entry
    }

    public func validateComplete(requireExact: Bool, allowExceededMaximum: Bool = false) throws {
        guard entries.count == RunDimension.allCases.count else { throw ControllerError.evidence("incomplete-vector") }
        for dimension in RunDimension.allCases {
            let value = try entry(dimension)
            guard let used = value.used, used >= 0 else { throw ControllerError.evidence("unknown-\(dimension.rawValue)") }
            switch value.constraintKind {
            case .maximum: guard (allowExceededMaximum || used <= value.limit), value.remaining == value.limit - used else { throw ControllerError.evidence("maximum-invalid-\(dimension.rawValue)") }
            case .zero: guard used == 0, value.remaining == 0 else { throw ControllerError.evidence("zero-invalid-\(dimension.rawValue)") }
            case .exact:
                guard used <= value.limit else { throw ControllerError.evidence("exact-invalid-\(dimension.rawValue)") }
                if requireExact { guard used == value.limit, value.remaining == 0 else { throw ControllerError.evidence("exact-incomplete-\(dimension.rawValue)") } }
            }
        }
    }
}

public struct StorageSample: Codable, Equatable, Sendable {
    public let at: UInt64
    public let physicalBytes: Int64
    public let logicalBytes: Int64
}

public struct StorageSummary: Codable, Equatable, Sendable {
    public let samples: [StorageSample]
    public let observedPeakPhysicalBytes: Int64
    public let observedPeakLogicalBytes: Int64
    public let maximumGapNanoseconds: UInt64
    public let scanFailure: String?
}

public final class TreeStorageMonitor: @unchecked Sendable {
    private let root: URL
    private let intervalNanoseconds: UInt64
    private let lock = NSLock()
    private var samples: [StorageSample] = []
    private var failure: String?
    private var timer: DispatchSourceTimer?

    public init(root: URL, intervalNanoseconds: UInt64) {
        self.root = root
        self.intervalNanoseconds = intervalNanoseconds
    }

    public func start() {
        sampleNow()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "reach.acceptance.storage"))
        timer.schedule(deadline: .now() + .nanoseconds(Int(intervalNanoseconds)), repeating: .nanoseconds(Int(intervalNanoseconds)))
        timer.setEventHandler { [weak self] in self?.sampleNow() }
        self.timer = timer
        timer.resume()
    }

    public func sampleNow() {
        lock.lock(); defer { lock.unlock() }
        do {
            let usage = try Self.measure(root: root)
            let sample = StorageSample(at: RawClock.now(), physicalBytes: usage.physical, logicalBytes: usage.logical)
            samples.append(sample)
        } catch {
            if failure == nil { failure = String(describing: error) }
        }
    }

    deinit { timer?.cancel() }

    public func stop() -> StorageSummary {
        timer?.cancel()
        timer = nil
        sampleNow()
        lock.lock(); defer { lock.unlock() }
        let physical = samples.map(\.physicalBytes).max() ?? 0
        let logical = samples.map(\.logicalBytes).max() ?? 0
        let gaps = zip(samples, samples.dropFirst()).map { $1.at >= $0.at ? $1.at - $0.at : UInt64.max }
        return StorageSummary(
            samples: samples,
            observedPeakPhysicalBytes: physical,
            observedPeakLogicalBytes: logical,
            maximumGapNanoseconds: gaps.max() ?? 0,
            scanFailure: failure
        )
    }

    private static func measure(root: URL) throws -> (physical: Int64, logical: Int64) {
        var pending = [root.path]
        var seen = Set<String>()
        var physical: Int64 = 0
        var logical: Int64 = 0
        while let path = pending.popLast() {
            var info = stat()
            guard lstat(path, &info) == 0 else { throw ControllerError.evidence("lstat") }
            let identity = "\(UInt64(info.st_dev)):\(UInt64(info.st_ino))"
            guard seen.insert(identity).inserted else { continue }
            let (nextPhysical, pOverflow) = physical.addingReportingOverflow(Int64(info.st_blocks) * 512)
            let (nextLogical, lOverflow) = logical.addingReportingOverflow(max(0, Int64(info.st_size)))
            guard !pOverflow, !lOverflow else { throw ControllerError.evidence("storage-arithmetic") }
            physical = nextPhysical; logical = nextLogical
            if (info.st_mode & S_IFMT) == S_IFDIR {
                for child in try FileManager.default.contentsOfDirectory(atPath: path) {
                    pending.append((path as NSString).appendingPathComponent(child))
                }
            }
        }
        return (physical, logical)
    }
}
