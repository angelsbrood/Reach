import Foundation
import Darwin
import CryptoKit
import DurableHostStore

struct CatalogDocument: Codable {
    var version = 1
    var incarnation: String
    var boot: String
    var clockPolicy: String
    var quota: Int
    var epoch: UInt64
    var lastObserved: UInt64
    var records: [LifecycleRecord] = []
    func validate(_ identity: LifecycleIdentity) throws {
        guard version == 1, incarnation == identity.incarnation, boot == identity.boot, clockPolicy == identity.clockPolicy,
              quota == identity.quota, epoch > 0, lastObserved > 0, records.count <= LifecycleLimits.records,
              records.filter({ $0.phase.reservesExecution }).count <= 1, records.filter({ $0.phase == .queued }).count <= 3 else { throw LifecycleError.invalid("catalog declaration") }
        var ids = Set<String>(), operations = Set<String>(), generationKeys = Set<String>(), waiters = Set<String>(), locators = Set<String>()
        for r in records {
            guard lcUUID(r.id), ids.insert(r.id).inserted, r.high <= UInt64(StoreLimits.events) else { throw LifecycleError.invalid("record identity/count") }
            if let id = r.identity {
                try id.caller.validate(); try lcID(id.generation)
                guard lcUUID(id.namespace), id.ticketExpiry > 0, lcDigest(id.requestDigest), lcDigest(id.operationDigest),
                      generationKeys.insert(id.namespace+":"+id.generation).inserted, operations.insert(id.operationDigest).inserted else { throw LifecycleError.invalid("operation alias") }
                if r.phase == .queued, !waiters.insert(id.namespace).inserted { throw LifecycleError.invalid("multiple session waiters") }
            } else if r.phase != .retiring { throw LifecycleError.invalid("missing operation identity") }
            if let w = r.work {
                guard r.phase != .retiring, r.phase != .tombstone, let id = r.identity, r.cleanup == nil,
                      lcUUID(w.request), lcUUID(w.child), locators.insert("r-"+w.request).inserted,
                      locators.insert("g-"+w.child).inserted else { throw LifecycleError.invalid("live content locators") }
                try w.keys.validate()
                let t = w.times
                guard t.admitted > 0, t.admitted <= t.lastContact, t.lastContact <= lastObserved, t.attachmentEpoch > 0,
                      t.queueUntil == min(try lcAdd(t.admitted, LifecycleLimits.wait), id.ticketExpiry),
                      t.absoluteUntil == min(try lcAdd(t.admitted, LifecycleLimits.inflight), id.ticketExpiry),
                      t.admitted < id.ticketExpiry,
                      t.detachedUntil.map({ $0 >= t.lastContact && $0 <= id.ticketExpiry && $0 <= t.absoluteUntil }) ?? true,
                      t.transitionStartedAt.map({ $0 >= t.admitted && $0 <= lastObserved }) ?? true,
                      t.terminalUntil.map({ $0 <= id.ticketExpiry && $0 <= t.absoluteUntil }) ?? true,
                      t.attached ? t.detachedUntil == nil : t.detachedUntil != nil else { throw LifecycleError.invalid("persisted deadline/attachment") }
                if r.phase == .terminal {
                    guard r.ending != nil, let start = t.transitionStartedAt,
                          t.terminalUntil == min(try lcAdd(start, LifecycleLimits.terminal), t.absoluteUntil, id.ticketExpiry) else { throw LifecycleError.invalid("terminal time join") }
                } else {
                    guard r.ending == nil, t.terminalUntil == nil else { throw LifecycleError.invalid("nonterminal time join") }
                }
            } else {
                guard r.phase == .retiring || r.phase == .tombstone, r.disposition != nil else { throw LifecycleError.invalid("missing live content") }
                if r.phase == .retiring {
                    guard let cleanup = r.cleanup else { throw LifecycleError.invalid("missing cleanup intent") }
                    if let child = cleanup.child { guard lcUUID(child), locators.insert("g-"+child).inserted else { throw LifecycleError.invalid("cleanup child") } }
                    if let request = cleanup.request { guard lcUUID(request), locators.insert("r-"+request).inserted else { throw LifecycleError.invalid("cleanup request") } }
                } else if r.cleanup != nil { throw LifecycleError.invalid("tombstone content") }
            }
        }
    }
}
final class LifecycleCatalog {
    let files: LifecycleFileSystem
    let identity: LifecycleIdentity
    let keys: LifecycleKeys
    let clock: any LifecycleClock
    let epoch: UInt64
    private(set) var uncertain = false
    var fault: LifecycleFaultHook
    init(files: LifecycleFileSystem, identity: LifecycleIdentity, keys: LifecycleKeys, clock: any LifecycleClock, epoch: UInt64, fault: @escaping LifecycleFaultHook) {
        self.files = files; self.identity = identity; self.keys = keys; self.clock = clock; self.epoch = epoch; self.fault = fault
    }
    static func initialize(path: String, identity: LifecycleIdentity, keys: LifecycleKeys, clock: any LifecycleClock, fault: @escaping LifecycleFaultHook) throws -> LifecycleCatalog {
        try identity.validate(clock)
        let files = try LifecycleFileSystem(path: path, create: true)
        let c = LifecycleCatalog(files: files, identity: identity, keys: keys, clock: clock, epoch: 1, fault: fault)
        do {
            let document = CatalogDocument(incarnation: identity.incarnation, boot: identity.boot, clockPolicy: identity.clockPolicy, quota: identity.quota, epoch: 1, lastObserved: try clock.now())
            try c.replace(document, initial: true); return c
        } catch { files.close(); throw error }
    }
    static func reopen(path: String, identity: LifecycleIdentity, keys: LifecycleKeys, clock: any LifecycleClock, fault: @escaping LifecycleFaultHook) throws -> LifecycleCatalog {
        try identity.validate(clock)
        let files = try LifecycleFileSystem(path: path, create: false)
        do {
            var d = try read(files, identity: identity, keys: keys)
            let epoch = try lcAdd(d.epoch, 1), now = try clock.now()
            guard now >= d.lastObserved else { throw LifecycleError.invalid("clock rollback") }
            let c = LifecycleCatalog(files: files, identity: identity, keys: keys, clock: clock, epoch: epoch, fault: fault)
            try c.removePrepared()
            d.epoch = epoch; d.lastObserved = now
            for i in d.records.indices {
                if var w = d.records[i].work {
                    if w.times.attached {
                        w.times.attached = false
                        w.times.detachedUntil = min(try lcAdd(w.times.lastContact, LifecycleLimits.wait), w.times.absoluteUntil, d.records[i].identity!.ticketExpiry)
                    }
                    d.records[i].work = w
                    if d.records[i].phase == .active { d.records[i].phase = .recovering }
                }
            }
            try c.replace(d, initial: true); return c
        } catch { files.close(); throw error }
    }
    static func read(_ files: LifecycleFileSystem, identity: LifecycleIdentity, keys: LifecycleKeys) throws -> CatalogDocument {
        _ = try files.usage()
        let plain = try LifecycleCrypto.open(files.root.read("current", maximum: LifecycleLimits.catalog+LifecycleCrypto.overhead), role: "catalog", identity: identity, key: keys.catalog)
        let document = try JSONDecoder().decode(CatalogDocument.self, from: plain)
        try document.validate(identity)
        guard try lcEncode(document) == plain else { throw LifecycleError.invalid("catalog schema/canonical bytes") }; return document
    }
    func load(allowUncertain: Bool = false) throws -> CatalogDocument {
        try files.ensure(); guard allowUncertain || !uncertain else { throw LifecycleError.uncertain }
        let d = try Self.read(files, identity: identity, keys: keys)
        guard d.epoch == epoch else { throw LifecycleError.stale }; return d
    }
    func time(_ document: inout CatalogDocument) throws -> UInt64 {
        let now = try clock.now(); guard now >= document.lastObserved else { throw LifecycleError.invalid("clock rollback") }
        document.lastObserved = now; return now
    }
    func replace(_ document: CatalogDocument, initial: Bool = false) throws {
        try files.ensure(); guard !uncertain else { throw LifecycleError.uncertain }
        if !initial { let previous = try load(); guard document.lastObserved >= previous.lastObserved else { throw LifecycleError.invalid("clock rollback") }; try removePrepared() }
        try document.validate(identity); guard document.epoch == epoch else { throw LifecycleError.stale }
        let plain = try lcEncode(document)
        guard plain.count <= LifecycleLimits.catalog else { throw LifecycleError.full }
        let cipher = try LifecycleCrypto.seal(plain, role: "catalog", record: UUID().uuidString.lowercased(), identity: identity, key: keys.catalog)
        guard try files.usage().bytes <= identity.quota-cipher.count-4096 else { throw LifecycleError.full }
        try files.root.writeNew("prepared", bytes: cipher, maximum: LifecycleLimits.catalog+LifecycleCrypto.overhead)
        guard try files.root.read("prepared", maximum: cipher.count) == cipher else { throw LifecycleError.invalid("prepared catalog bytes") }
        try fault(.beforeCatalogRename)
        uncertain = true
        guard renameat(files.root.fd, "prepared", files.root.fd, "current") == 0 else { throw LifecycleError.io("catalog rename", errno) }
        try fault(.afterCatalogRename); try fault(.beforeCatalogSync); try files.root.sync(); uncertain = false
        guard try lcEncode(load()) == plain else { throw LifecycleError.invalid("committed catalog bytes") }
    }
    func reconcile() throws -> CatalogDocument {
        let d = try load(allowUncertain: true)
        try files.root.sync(); uncertain = false; try removePrepared(); return d
    }
    func removePrepared() throws {
        if try files.root.exists("prepared") { try files.root.unlink("prepared", maximum: LifecycleLimits.catalog+LifecycleCrypto.overhead); try files.root.sync() }
    }
    func request(_ record: LifecycleRecord) throws -> LifecycleRequest {
        guard let work = record.work, let id = record.identity else { throw LifecycleError.retired }
        let cipher = try files.requests.read(LifecycleFileSystem.requestName(work.request), maximum: LifecycleLimits.request+LifecycleCrypto.overhead)
        let bytes = try LifecycleCrypto.open(cipher, role: "request", record: work.request, identity: identity, key: SymmetricKey(data: work.keys.content))
        let request = try JSONDecoder().decode(LifecycleRequest.self, from: bytes)
        try request.validate()
        guard lcHash(bytes) == id.requestDigest, try lcEncode(request) == bytes, request.namespace == id.namespace,
              request.generation == id.generation, request.caller == id.caller, lcHash(Data(request.provider.operationID.utf8)) == id.operationDigest else { throw LifecycleError.invalid("immutable request join") }
        return request
    }
    func cleanRequests(_ document: CatalogDocument) throws {
        // The authenticated catalog establishes references. Corrupt referenced
        // content stays available for explicit guarded retirement, not admission.
        let referenced = Set(document.records.compactMap { $0.work?.request ?? $0.cleanup?.request }.map(LifecycleFileSystem.requestName))
        for role in try files.requests.names(maximum: 65, allowed: LifecycleFileSystem.requestRole) where !referenced.contains(role) {
            try files.requests.unlink(role, maximum: LifecycleLimits.request+LifecycleCrypto.overhead)
        }
        try files.requests.sync()
        let children = Set(document.records.compactMap { $0.work?.child ?? $0.cleanup?.child }.map(LifecycleFileSystem.childName))
        guard try files.children.names(maximum: 64, allowed: LifecycleFileSystem.childRole).allSatisfy(children.contains) else { throw LifecycleError.invalid("unreferenced child root") }
    }
}
