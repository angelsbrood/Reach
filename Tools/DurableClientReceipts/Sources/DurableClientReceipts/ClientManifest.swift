import Foundation
import CryptoKit

struct SnapshotReference: Codable {
    var name: String, digest: String
    var revision: UInt64
    var length: Int
}
struct LiveClientRecord: Codable {
    var identity: String, namespace: String, anchor: String, contextDigest: String
    var issued: UInt64, expires: UInt64
    var key: Data
    var snapshot: SnapshotReference
    var calls: Int, futureBytes: Int
}
struct ClientRecord: Codable {
    var id: String
    var live: LiveClientRecord?
    var cleanup: SnapshotReference?
}
struct ClientManifest: Codable {
    var version = 1
    var root: String, boot: String, policy: String
    var revision: UInt64, ownerEpoch: UInt64, observed: UInt64
    var records: [ClientRecord] = []
    func validate(_ e: ClientEnvironment) throws {
        guard version == 1, crEqual(root, e.rootID), crEqual(boot, e.boot), crEqual(policy, e.policy),
              revision > 0, ownerEpoch > 0, observed > 0, records.count <= ClientLimits.records else { throw ClientError.unavailable }
        var ids = Set<String>(), identities = Set<String>(), roles = Set<String>(), calls = 0
        var anchors: [String: String] = [:]
        for r in records {
            guard crUUID(r.id), ids.insert(r.id).inserted, (r.live != nil) != (r.cleanup != nil) else { throw ClientError.unavailable }
            let ref: SnapshotReference
            if let live = r.live {
                guard [live.identity, live.namespace, live.anchor, live.contextDigest].allSatisfy(crDigest),
                      identities.insert(live.identity).inserted, live.key.count == 32,
                      live.issued > 0, live.expires > live.issued, live.expires <= (try crAdd(live.issued, ClientLimits.session)),
                      (0...32).contains(live.calls), (1...ClientLimits.snapshot).contains(live.futureBytes) else { throw ClientError.unavailable }
                if let anchor = anchors[live.namespace], anchor != live.anchor { throw ClientError.unavailable }
                anchors[live.namespace] = live.anchor; calls += live.calls; ref = live.snapshot
            } else { ref = r.cleanup! }
            guard ClientFileSystem.role(ref.name), ref.name.hasPrefix("s-"), roles.insert(ref.name).inserted,
                  crDigest(ref.digest), ref.revision > 0, ref.revision <= revision,
                  (ClientCrypto.overhead...ClientLimits.snapshot+ClientCrypto.overhead).contains(ref.length) else { throw ClientError.unavailable }
        }
        guard calls <= ClientLimits.calls else { throw ClientError.full }
    }
}
struct ClientSnapshot: Codable {
    var version = 1
    var context: Data
    var batches: [InboxBatch] = []
    var calls: [ClientCall] = []
    var high: UInt64 = 0
    var terminal = false
    var receiptRevision: UInt64 = 0
    func receipt() -> DurableReceipt {
        .init(contextDigest: crHash(context), revision: receiptRevision, high: high, terminal: terminal, registeredCalls: calls.count)
    }
    func maximumFutureBytes() throws -> Int {
        // Outcome's <=1 MiB canonical encoding is itself stored as Data (base64).
        // Space for absent->intent, revision widths and JSON field framing is also retained.
        let pending = calls.filter { $0.outcome == nil }.count
        let future = try crEncode(self).count + pending * (((ClientLimits.outcome+2)/3)*4+4096) + 8192
        guard future <= ClientLimits.snapshot else { throw ClientError.full }; return future
    }
    func validate(_ live: LiveClientRecord) throws {
        guard version == 1, context.count <= ClientLimits.context, crHash(context) == live.contextDigest,
              batches.count <= 4095, calls.count == live.calls, high <= 65536,
              receiptRevision <= live.snapshot.revision, calls.count <= 32 else { throw ClientError.unavailable }
        let decoded = try JSONDecoder().decode(ClientContext.self, from: context)
        let authority = try ClientAuthority(decoded)
        guard authority.bytes == context, authority.identity == live.identity, authority.anchor == live.anchor,
              authority.namespace == live.namespace, decoded.issued == live.issued, decoded.expires == live.expires else { throw ClientError.unavailable }
        var rebuilt = ClientSnapshot(context: context)
        for b in batches {
            let frame = ReplayEnvelope(firstSequence: b.first, count: b.count, providerCommit: b.commit, eventBytes: b.bytes)
            try rebuilt.append(frame, events: frame.validate(cursor: rebuilt.high, high: rebuilt.high), revision: receiptRevision)
        }
        guard rebuilt.high == high, rebuilt.terminal == terminal, rebuilt.calls.count == calls.count,
              (batches.isEmpty ? receiptRevision == 0 : receiptRevision > 0) else { throw ClientError.unavailable }
        for (expected, actual) in zip(rebuilt.calls, calls) {
            guard expected.identity == actual.identity else { throw ClientError.unavailable }; try actual.validate(context: context)
        }
        guard try maximumFutureBytes() <= live.futureBytes else { throw ClientError.unavailable }
    }
    mutating func append(_ frame: ReplayEnvelope, events: [ReachWire.WireEvent], revision: UInt64) throws {
        guard !terminal, batches.count < 4095, frame.skipPrefix == 0,
              frame.firstSequence == (try crAdd(high, 1)), !batches.contains(where: { $0.commit == frame.providerCommit }) else { throw ClientError.invalid("batch order/commit reuse") }
        let nextHigh = try crAdd(high, UInt64(frame.count))
        guard nextHigh <= 65536, 4+batches.reduce(0, { $0+$1.bytes.count+88 })+frame.eventBytes.count+88 <= ClientLimits.replay else { throw ClientError.full }
        var newCalls = calls
        for event in events {
            if case .toolCallAppendArguments(_, let id, let name, let arguments, _) = event {
                let call = try ClientCall(context: context, id: Data(id.utf8), name: Data(name.utf8), arguments: Data(arguments.utf8))
                guard !newCalls.contains(where: { $0.id == call.id }), newCalls.count < 32 else { throw ClientError.invalid("call alias/capacity") }
                newCalls.append(call)
            }
        }
        batches.append(InboxBatch(frame)); calls = newCalls; high = nextHigh; receiptRevision = revision
        if case .finished? = events.last { terminal = true }
    }
}

import ReachWire

extension DurableClientReceipts {
    func readManifest() throws -> ClientManifest {
        let (plain, frame) = try ClientCrypto.open(fs.read("current"), role: "manifest", environment: environment, key: rootKey, rootKey: rootKey)
        let m = try JSONDecoder().decode(ClientManifest.self, from: plain)
        guard try crEncode(m) == plain, m.revision == frame.revision, frame.record == environment.rootID else { throw ClientError.unavailable }
        try m.validate(environment); return m
    }
    func recover(_ m: ClientManifest) throws {
        // Validate every role before deleting any. Never select prepared or initialize over missing current.
        let names = try fs.names()
        // Expired content is never publishable. Its missing/corrupt bytes must not
        // prevent a later maintenance transaction from pruning identity and key.
        let required = Set(m.records.compactMap { r in
            r.live.flatMap { observed < $0.expires ? $0.snapshot.name : nil }
        })
        guard required.isSubset(of: Set(names)) else { throw ClientError.unavailable }
        var orphans: [String] = []
        for name in names where name != "current" && name != "lock" {
            if name == "prepared" {
                let (plain, f) = try ClientCrypto.open(fs.read(name), role: "manifest", environment: environment, key: rootKey, rootKey: rootKey)
                let prepared = try JSONDecoder().decode(ClientManifest.self, from: plain)
                try prepared.validate(environment)
                guard try crEncode(prepared) == plain, prepared.revision == f.revision, f.record == environment.rootID else { throw ClientError.unavailable }
                orphans.append(name)
            } else {
                let selected = m.records.first { ($0.live?.snapshot.name ?? $0.cleanup?.name) == name }
                if let selected, selected.live == nil || observed >= selected.live!.expires {
                    // Still a validated owned regular role. Authentication remains mandatory
                    // before deletion, which occurs only after keyless retirement is selected.
                    continue
                }
                let data = try fs.read(name)
                let f = try ClientCrypto.inspect(data, role: "snapshot", environment: environment, rootKey: rootKey)
                guard name == "s-"+f.record+".bin" else { throw ClientError.unavailable }
                if let record = selected {
                    let ref = record.live?.snapshot ?? record.cleanup!
                    guard f.generation == record.id, f.revision == ref.revision, data.count == ref.length, crHash(data) == ref.digest else { throw ClientError.unavailable }
                } else { orphans.append(name) }
            }
        }
        for name in orphans { try fs.unlink(name) }
        // Also resolves a previous rename/directory-sync uncertainty before any new decision.
        try fs.sync(); uncertain = false
    }
    func refresh() throws -> ClientManifest {
        try fs.ensure(); let m = try readManifest(); _ = try observe(m)
        try recover(m); return m
    }
    func snapshot(_ record: ClientRecord) throws -> ClientSnapshot {
        guard let live = record.live else { throw ClientError.expired }
        let data = try fs.read(live.snapshot.name)
        guard data.count == live.snapshot.length, crHash(data) == live.snapshot.digest else { throw ClientError.unavailable }
        let (plain, f) = try ClientCrypto.open(data, role: "snapshot", environment: environment, key: SymmetricKey(data: live.key), rootKey: rootKey)
        guard f.generation == record.id, f.revision == live.snapshot.revision,
              live.snapshot.name == "s-"+f.record+".bin" else { throw ClientError.unavailable }
        let result = try JSONDecoder().decode(ClientSnapshot.self, from: plain)
        guard try crEncode(result) == plain else { throw ClientError.unavailable }
        try result.validate(live); return result
    }
    static func allocationBound(_ count: Int) -> Int { ((count+65535)/65536)*65536 }
    func reserve(_ proposed: ClientManifest, old: ClientManifest?, snapshotLength: Int) throws {
        try proposed.validate(environment)
        let usage = try fs.usage()
        var obligation = ClientLimits.metadataReserve, selectedAllocation = 0
        if let old {
            for r in old.records {
                if let name = r.live?.snapshot.name ?? r.cleanup?.name, try fs.exists(name) { selectedAllocation += Int(try fs.info(name).st_blocks)*512 }
            }
        }
        for r in proposed.records {
            if let live = r.live { obligation += 2*Self.allocationBound(live.futureBytes+ClientCrypto.overhead) }
            else if let cleanup = r.cleanup, try fs.exists(cleanup.name) { obligation += Int(try fs.info(cleanup.name).st_blocks)*512 }
        }
        guard obligation <= environment.quota, usage.bytes-selectedAllocation <= environment.quota-obligation,
              usage.bytes + Self.allocationBound(snapshotLength) + ClientLimits.metadataReserve <= environment.quota,
              usage.files+(snapshotLength > 0 ? 2 : 1) <= ClientLimits.files else { throw ClientError.full }
    }
    func commit(_ input: ClientManifest, old: ClientManifest?, replacement: (Int, ClientSnapshot)? = nil) throws -> ClientManifest {
        var m = input
        m.observed = try observe(m)
        var content: (String, Data)?
        if let (i, snapshot) = replacement {
            guard var live = m.records[i].live else { throw ClientError.unavailable }
            let record = UUID().uuidString.lowercased(), name = "s-"+record+".bin"
            let plain = try crEncode(snapshot)
            guard plain.count <= ClientLimits.snapshot else { throw ClientError.full }
            let data = try ClientCrypto.seal(plain, role: "snapshot", record: record, generation: m.records[i].id,
                revision: m.revision, environment: environment, key: SymmetricKey(data: live.key), rootKey: rootKey)
            live.snapshot = .init(name: name, digest: crHash(data), revision: m.revision, length: data.count)
            live.calls = snapshot.calls.count; live.futureBytes = try snapshot.maximumFutureBytes()
            m.records[i].live = live; content = (name, data)
        }
        let plain = try crEncode(m)
        guard plain.count <= ClientLimits.manifest else { throw ClientError.full }
        let meta = try ClientCrypto.seal(plain, role: "manifest", record: environment.rootID, generation: ClientCrypto.zero,
            revision: m.revision, environment: environment, key: rootKey, rootKey: rootKey)
        try reserve(m, old: old, snapshotLength: content?.1.count ?? 0)
        uncertain = true
        if let (name, data) = content { try fs.writeNew(name, data); try hook(.afterSnapshot) }
        try fs.writeNew("prepared", meta)
        guard try fs.usage().bytes <= environment.quota else { throw ClientError.full }
        // From here failure may have selected the new state. Every subsequent API reloads and reconciles current.
        try hook(.beforeManifestRename); try fs.selectPrepared(); try hook(.afterManifestRename)
        try hook(.beforeDirectorySync); try fs.sync()
        try recover(m); uncertain = false; return m
    }
}
