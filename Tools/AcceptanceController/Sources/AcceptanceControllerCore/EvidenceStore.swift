import Foundation
import Darwin

public enum SHA256 {
    private static let constants: [UInt32] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ]

    public static func hex(_ data: Data) -> String {
        var message = Array(data)
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 { message.append(0) }
        message.append(contentsOf: withUnsafeBytes(of: bitLength.bigEndian, Array.init))
        var state: [UInt32] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
        for offset in stride(from: 0, to: message.count, by: 64) {
            var words = [UInt32](repeating: 0, count: 64)
            for index in 0..<16 {
                let base = offset + index * 4
                words[index] = UInt32(message[base]) << 24 | UInt32(message[base + 1]) << 16 | UInt32(message[base + 2]) << 8 | UInt32(message[base + 3])
            }
            for index in 16..<64 {
                let a = words[index - 15]
                let b = words[index - 2]
                let s0 = rotate(a, 7) ^ rotate(a, 18) ^ (a >> 3)
                let s1 = rotate(b, 17) ^ rotate(b, 19) ^ (b >> 10)
                words[index] = words[index - 16] &+ s0 &+ words[index - 7] &+ s1
            }
            var a = state[0], b = state[1], c = state[2], d = state[3]
            var e = state[4], f = state[5], g = state[6], h = state[7]
            for index in 0..<64 {
                let s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
                let ch = (e & f) ^ ((~e) & g)
                let t1 = h &+ s1 &+ ch &+ constants[index] &+ words[index]
                let s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let t2 = s0 &+ maj
                h = g; g = f; f = e; e = d &+ t1
                d = c; c = b; b = a; a = t1 &+ t2
            }
            state[0] &+= a; state[1] &+= b; state[2] &+= c; state[3] &+= d
            state[4] &+= e; state[5] &+= f; state[6] &+= g; state[7] &+= h
        }
        return state.map { String(format: "%08x", $0) }.joined()
    }

    public static func file(_ url: URL) throws -> String { hex(try Data(contentsOf: url, options: .mappedIfSafe)) }
    private static func rotate(_ value: UInt32, _ count: UInt32) -> UInt32 { (value >> count) | (value << (32 - count)) }
}

public enum DurableFile {
    public static func createDirectory(_ url: URL, mode: mode_t = 0o700) throws {
        if mkdir(url.path, mode) != 0, errno != EEXIST { throw ControllerError.evidence("mkdir-\(errno)") }
        var info = stat()
        guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == getuid(), info.st_nlink >= 2 else {
            throw ControllerError.ownership("directory")
        }
        guard chmod(url.path, mode) == 0 else { throw ControllerError.ownership("chmod-directory") }
    }

    public static func write(_ data: Data, to url: URL, exclusive: Bool = true) throws {
        let flags = O_WRONLY | O_CREAT | (exclusive ? O_EXCL : O_TRUNC) | O_NOFOLLOW | O_CLOEXEC
        let descriptor = open(url.path, flags, 0o600)
        guard descriptor >= 0 else { throw ControllerError.evidence("open-\(url.lastPathComponent)-\(errno)") }
        defer { close(descriptor) }
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var written = 0
            while written < raw.count {
                let count = Darwin.write(descriptor, base.advanced(by: written), raw.count - written)
                guard count > 0 else { throw ControllerError.evidence("write-\(errno)") }
                written += count
            }
        }
        guard fsync(descriptor) == 0 else { throw ControllerError.evidence("fsync-file") }
    }

    public static func fsyncDirectory(_ url: URL) throws {
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw ControllerError.evidence("open-directory") }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw ControllerError.evidence("fsync-directory") }
    }
}

public struct ControllerRunResult: Sendable {
    public let outcome: WorkloadOutcome
    public let exitCode: Int32
    public let receipt: Data
    public let packetRootDigest: String
}

public final class AcceptanceController: @unchecked Sendable {
    public init() {}

    public func run(specURL: URL, scratchURL: URL, packetURL: URL, executableURL: URL) throws -> ControllerRunResult {
        let specData = try Data(contentsOf: specURL, options: .mappedIfSafe)
        let specKeys: Set<String> = ["actions", "executableDigest", "launchSnapshotDigest", "launchSnapshotPath", "packetPath", "runID", "scratchRoot", "sourceManifestDigest", "sourceManifestPath", "version"]
        let spec = try CanonicalJSON.decode(RunSpec.self, from: specData, allowedTopLevelKeys: specKeys)
        try validate(spec: spec, specURL: specURL, scratchURL: scratchURL, packetURL: packetURL, executableURL: executableURL)

        try DurableFile.createDirectory(scratchURL)
        let ownerURL = scratchURL.appendingPathComponent("owner.json")
        let owner = try CanonicalJSON.encode(["pid": .integer(Int(getpid())), "runID": .string(spec.runID), "version": .integer(1)] as [String: AnyCodable])
        try DurableFile.write(owner, to: ownerURL)
        let journalURL = scratchURL.appendingPathComponent("journal")
        try DurableFile.createDirectory(journalURL)
        let monitor = TreeStorageMonitor(root: scratchURL, intervalNanoseconds: 5_000_000)
        monitor.start()
        let runT0 = RawClock.now()
        var vector = RunResourceVector(frozenActions: spec.actions.count)
        var records: [ActionRecord] = []
        var publicResults: [String: [String: TypedValue]] = [:]
        var stopOrdinal: Int?
        var stopReason: String?
        var controllerFailed = false
        var runResultBytes: Int64 = 0

        for action in spec.actions {
            if let stopOrdinal {
                try vector.charge(.notStartedRows)
                let record = ActionRecord(
                    ordinal: action.ordinal, actionID: action.id, state: .notStarted,
                    rawT0: nil, rawT1: nil, workDeadline: nil, settlementDeadline: nil,
                    termination: nil, exitCode: nil, signal: nil, processID: nil, timeoutDetectedAt: nil,
                    termSentAt: nil, killSentAt: nil, groupAbsentAt: nil,
                    stdoutDigest: nil, stderrDigest: nil, stdoutBytes: nil, stderrBytes: nil,
                    result: nil, reason: "caused-by-\(stopOrdinal)", preVector: vector, postVector: vector
                )
                records.append(record)
                try writeRow(record, prefix: "not-started", at: journalURL, vector: &vector)
                continue
            }

            let pre = vector
            let admittedAt = RawClock.now()
            let window = action.workDeadlineNanoseconds > admittedAt ? action.workDeadlineNanoseconds - admittedAt : 0
            try vector.assign(.actionWorkWindowNanoseconds, value: max(try vector.entry(.actionWorkWindowNanoseconds).used ?? 0, Int64(clamping: window)))
            try vector.assign(.actionSettlementReserveNanoseconds, value: max(try vector.entry(.actionSettlementReserveNanoseconds).used ?? 0, Int64(clamping: action.settlementDeadlineNanoseconds - action.workDeadlineNanoseconds)))
            try vector.charge(.actionProcessLaunches)
            try vector.assign(.simultaneouslyLiveActions, value: 1)
            let started = ActionRecord(
                ordinal: action.ordinal, actionID: action.id, state: .started,
                rawT0: nil, rawT1: nil, workDeadline: action.workDeadlineNanoseconds,
                settlementDeadline: action.settlementDeadlineNanoseconds, termination: nil,
                exitCode: nil, signal: nil, processID: nil, timeoutDetectedAt: nil, termSentAt: nil,
                killSentAt: nil, groupAbsentAt: nil, stdoutDigest: nil, stderrDigest: nil,
                stdoutBytes: nil, stderrBytes: nil, result: nil, reason: nil,
                preVector: pre, postVector: vector
            )
            try writeRow(started, prefix: "started", at: journalURL, vector: &vector)
            let process = try ProcessRunner.run(action)
            try vector.assign(.simultaneouslyLiveActions, value: 0)
            for (dimension, count) in [(RunDimension.stdoutPhysicalBytes, process.stdoutCount), (.stderrPhysicalBytes, process.stderrCount), (.combinedOutputPhysicalBytes, process.stdoutCount + process.stderrCount)] {
                try vector.observeMaximum(dimension, value: (try vector.entry(dimension).used ?? 0) + Int64(count))
            }
            if !process.cleanupComplete { try vector.markUnknown(.unsettledProcessGroups) }
            if process.termSentAt != nil { try vector.charge(.termSignals) }
            if process.killSentAt != nil { try vector.charge(.killSignals) }

            var envelope: ResultEnvelope?
            var reason: String?
            let outputLimit = try [RunDimension.stdoutPhysicalBytes, .stderrPhysicalBytes, .combinedOutputPhysicalBytes].contains {
                let entry = try vector.entry($0); return (entry.used ?? 0) > entry.limit
            }
            if let code = process.spawnError {
                reason = "spawn-failure-\(code)"; controllerFailed = true
            } else if !process.cleanupComplete || !process.groupAssigned || process.rawT1 > action.settlementDeadlineNanoseconds {
                reason = "containment"
            } else if process.overflowed || outputLimit {
                reason = "output-limit"
            } else if process.termination == "timeout" {
                reason = "timeout"
            } else if process.exitCode != 0 {
                reason = "nonzero"
            } else {
                do {
                    let parsed = try ResultDecoder.decode(process.stdout, action: action)
                    envelope = parsed
                    let canonical = try CanonicalJSON.encode(parsed)
                    runResultBytes += Int64(canonical.count)
                    try vector.assign(.canonicalResultBytes, value: runResultBytes)
                    if parsed.kind == .ok, action.expectedKind == .ok {
                        publicResults[action.id] = parsed.fields
                    } else {
                        reason = parsed.reasonCode ?? "unexpected-result-kind"
                    }
                } catch {
                    // Decoder diagnostics can contain rejected values and field names.
                    reason = "result-refusal"
                }
            }
            let stdoutDigest = SHA256.hex(process.stdout)
            let stderrDigest = SHA256.hex(process.stderr)
            let terminal = ActionRecord(
                ordinal: action.ordinal, actionID: action.id, state: .settled,
                rawT0: process.rawT0, rawT1: process.rawT1,
                workDeadline: action.workDeadlineNanoseconds, settlementDeadline: action.settlementDeadlineNanoseconds,
                termination: process.termination, exitCode: process.exitCode, signal: process.signal, processID: process.processID,
                timeoutDetectedAt: process.timeoutDetectedAt, termSentAt: process.termSentAt,
                killSentAt: process.killSentAt, groupAbsentAt: process.groupAbsentAt,
                stdoutDigest: stdoutDigest, stderrDigest: stderrDigest,
                stdoutBytes: process.stdoutCount, stderrBytes: process.stderrCount,
                result: envelope, reason: reason, preVector: pre, postVector: vector
            )
            records.append(terminal)
            try writeRow(terminal, prefix: "settled", at: journalURL, vector: &vector)
            if reason != nil { stopOrdinal = action.ordinal; stopReason = reason }
        }

        try vector.assign(.runWallNanoseconds, value: Int64(RawClock.now() - runT0))
        try vector.assign(.publicationAttempts, value: 1)
        monitor.sampleNow()
        let storage = monitor.stop()
        if let failure = storage.scanFailure { throw ControllerError.evidence("storage-scan-\(failure)") }
        try vector.assign(.observedPeakPhysicalBytes, value: storage.observedPeakPhysicalBytes)
        try vector.assign(.observedPeakLogicalBytes, value: storage.observedPeakLogicalBytes)
        try vector.validateComplete(requireExact: true, allowExceededMaximum: stopOrdinal != nil)

        let actionTableData = try CanonicalJSON.encode(records)
        let runLedgerData = try CanonicalJSON.encode(RunLedgerPayload(records: records, resourceVector: vector))
        let outcome = OutcomePayload(
            version: 1,
            outcome: controllerFailed ? .controllerFailure : (stopOrdinal == nil ? .pass : .stop),
            packetBasename: packetURL.lastPathComponent,
            actionTableDigest: SHA256.hex(actionTableData),
            runLedgerDigest: SHA256.hex(runLedgerData),
            sliceLaunchSnapshotDigest: spec.launchSnapshotDigest,
            earliestStopOrdinal: stopOrdinal,
            publicResults: publicResults,
            claimBoundaryDigest: SHA256.hex(Data("synthetic-controller-only;no-product-capability;reason=\(stopReason ?? "none")".utf8))
        )
        let outcomeData = try CanonicalJSON.encode(outcome)
        let sourceManifestData = try Data(contentsOf: URL(fileURLWithPath: spec.sourceManifestPath))
        let launchData = try Data(contentsOf: URL(fileURLWithPath: spec.launchSnapshotPath))
        let storageData = try CanonicalJSON.encode(storage)
        let payloads: [String: Data] = [
            "action-table.json": actionTableData,
            "executable.json": try CanonicalJSON.encode(["sha256": .string(spec.executableDigest), "version": .integer(1)] as [String: AnyCodable]),
            "launch-snapshot.json": launchData,
            "outcome.json": outcomeData,
            "raw-absence.json": try CanonicalJSON.encode(["rawFiles": .integer(0), "capturePolicy": .string("bounded in-memory capture; only counts and prefix digests retained"), "version": .integer(1)] as [String: AnyCodable]),
            "resource-vector.json": try CanonicalJSON.encode(vector),
            "run-ledger.json": runLedgerData,
            "source-manifest.json": sourceManifestData,
            "spec.json": specData,
            "storage.json": storageData,
        ]
        let published = try PacketPublisher.publish(payloads: payloads, finalURL: packetURL)
        let receipt = RunReceipt(
            version: 1, path: packetURL.path, packetRootDigest: published.rootDigest,
            outcomeDigest: SHA256.hex(outcomeData), outcome: outcome
        )
        let receiptData = try CanonicalJSON.encode(receipt)
        guard try CanonicalJSON.encode(receipt.outcome) == outcomeData else { throw ControllerError.evidence("receipt-projection") }
        return ControllerRunResult(
            outcome: outcome.outcome,
            exitCode: outcome.outcome == .pass ? 0 : (outcome.outcome == .stop ? 20 : 70),
            receipt: receiptData,
            packetRootDigest: published.rootDigest
        )
    }

    private func validate(spec: RunSpec, specURL: URL, scratchURL: URL, packetURL: URL, executableURL: URL) throws {
        guard spec.version == 1, spec.actions.count <= 32, spec.actions.indices.allSatisfy({ spec.actions[$0].ordinal == $0 }) else {
            throw ControllerError.input("spec-shape")
        }
        guard spec.scratchRoot == scratchURL.path, spec.packetPath == packetURL.path else { throw ControllerError.input("path-mismatch") }
        let roots = [specURL, packetURL, URL(fileURLWithPath: spec.launchSnapshotPath), URL(fileURLWithPath: spec.sourceManifestPath)]
        guard scratchURL.path.hasPrefix("/"), roots.allSatisfy({ $0.path.hasPrefix(scratchURL.path + "/") }) else {
            throw ControllerError.input("path-outside-scratch")
        }
        for url in [specURL, URL(fileURLWithPath: spec.launchSnapshotPath), URL(fileURLWithPath: spec.sourceManifestPath), executableURL] {
            var info = stat()
            guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else {
                throw ControllerError.ownership("authority-file")
            }
        }
        guard !FileManager.default.fileExists(atPath: packetURL.path) else { throw ControllerError.input("packet-present") }
        guard try SHA256.file(URL(fileURLWithPath: spec.launchSnapshotPath)) == spec.launchSnapshotDigest else { throw ControllerError.input("launch-digest") }
        guard try SHA256.file(URL(fileURLWithPath: spec.sourceManifestPath)) == spec.sourceManifestDigest else { throw ControllerError.input("source-manifest-digest") }
        guard try SHA256.file(executableURL) == spec.executableDigest else { throw ControllerError.input("executable-digest") }
        var identifiers = Set<String>()
        for action in spec.actions {
            guard action.id.utf8.count <= 128, identifiers.insert(action.id).inserted,
                  action.arguments.count <= 32, action.arguments.allSatisfy({ $0.utf8.count <= 4_096 }),
                  action.environment.count <= 64,
                  action.environment.allSatisfy({ $0.key.utf8.count <= 4_096 && $0.value.utf8.count <= 4_096 }),
                  action.workDeadlineNanoseconds < action.settlementDeadlineNanoseconds,
                  action.settlementDeadlineNanoseconds - action.workDeadlineNanoseconds <= 6_000_000_000 else {
                throw ControllerError.input("action-shape")
            }
        }
    }

    private func writeRow(_ row: ActionRecord, prefix: String, at journal: URL, vector: inout RunResourceVector) throws {
        let data = try CanonicalJSON.encode(row)
        let name = String(format: "%03d-%@.json", row.ordinal, prefix)
        try DurableFile.write(data, to: journal.appendingPathComponent(name))
        try DurableFile.fsyncDirectory(journal)
        try vector.charge(.journalFiles)
        try vector.charge(.journalLogicalBytes, by: Int64(data.count))
    }
}

public struct RunLedgerPayload: Codable, Equatable, Sendable {
    public let records: [ActionRecord]
    public let resourceVector: RunResourceVector
    public init(records: [ActionRecord], resourceVector: RunResourceVector) {
        self.records = records; self.resourceVector = resourceVector
    }
}

public enum AnyCodable: Codable, Equatable, Sendable {
    case string(String), integer(Int), boolean(Bool)

    public init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let bool = try? value.decode(Bool.self) { self = .boolean(bool) }
        else if let int = try? value.decode(Int.self) { self = .integer(int) }
        else { self = .string(try value.decode(String.self)) }
    }

    public func encode(to encoder: any Encoder) throws {
        var value = encoder.singleValueContainer()
        switch self {
        case .string(let item): try value.encode(item)
        case .integer(let item): try value.encode(item)
        case .boolean(let item): try value.encode(item)
        }
    }

    public init(_ value: String) { self = .string(value) }
    public init(_ value: Int) { self = .integer(value) }
    public init(_ value: Bool) { self = .boolean(value) }
}

public enum ReceiptWriter {
    public static func write(_ data: Data, descriptor: Int32, appendNewline: Bool = true) -> Bool {
        _ = fcntl(descriptor, F_SETNOSIGPIPE, 1)
        var bytes = data
        if appendNewline { bytes.append(0x0A) }
        return bytes.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return true }
            var written = 0
            while written < raw.count {
                let amount = Darwin.write(descriptor, base.advanced(by: written), raw.count - written)
                if amount <= 0 { return false }
                written += amount
            }
            return true
        }
    }
}
