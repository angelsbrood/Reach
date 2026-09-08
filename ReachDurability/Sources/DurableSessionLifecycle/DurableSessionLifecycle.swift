import Foundation
import CryptoKit
import DurableHostStore
import ResumableMLXProvider

/// Serial, synchronous cooperating owner. Child capabilities never cross this
/// module's public API. Maintenance is a trusted root-key administrative action.
public final class DurableSessionLifecycle {
    let catalog: LifecycleCatalog
    var children: [String: LifecycleChild] = [:]
    public var fault: LifecycleFaultHook { get { catalog.fault } set { catalog.fault = newValue } }
    public var ownerEpoch: UInt64 { catalog.epoch }
    public var uncertain: Bool { catalog.uncertain }
    private init(_ catalog: LifecycleCatalog) { self.catalog = catalog }
    public static func initialize(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys, clock: any LifecycleClock, fault: @escaping LifecycleFaultHook = { _ in }) throws -> DurableSessionLifecycle {
        try .init(LifecycleCatalog.initialize(path: path, identity: identity, keys: keys, clock: clock, fault: fault))
    }
    public static func reopen(at path: String, identity: LifecycleIdentity, keys: LifecycleKeys, clock: any LifecycleClock, fault: @escaping LifecycleFaultHook = { _ in }) throws -> DurableSessionLifecycle {
        let owner = try DurableSessionLifecycle(LifecycleCatalog.reopen(path: path, identity: identity, keys: keys, clock: clock, fault: fault))
        do { try owner.maintenance(); return owner } catch { owner.close(); throw error }
    }
    deinit { close() }
    func closeChildren() { for child in children.values { child.close() }; children.removeAll() }
    public func close() { closeChildren(); catalog.files.close() }
    public func issueTicket(authorization: LifecycleAuthorization, lifetime: UInt64 = LifecycleLimits.session) throws -> SessionTicket {
        try authorization.validate()
        var d = try catalog.load(); _ = try catalog.time(&d)
        try catalog.replace(d)
        let now = try catalog.time(&d)
        return try TicketCodec.issue(identity: catalog.identity, keys: catalog.keys, auth: authorization, now: now, ttl: lifetime)
    }
    func context(_ ticket: SessionTicket, _ auth: LifecycleAuthorization) throws -> (CatalogDocument, TicketClaims) {
        try auth.validate()
        // Check ticket and current authorization before generation lookup or maintenance.
        _ = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: auth, now: catalog.clock.now())
        try maintenance()
        var d = try catalog.load(); let now = try catalog.time(&d)
        _ = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: auth, now: now)
        try catalog.replace(d)
        let fresh = try catalog.time(&d)
        let claims = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: auth, now: fresh)
        return (d, claims)
    }
    func index(_ attachment: LifecycleAttachment, claims: TicketClaims, document: CatalogDocument, attached: Bool = true) throws -> Int {
        guard attachment.ownerEpoch == catalog.epoch,
              let i = document.records.firstIndex(where: { $0.id == attachment.record }),
              let identity = document.records[i].identity, identity.namespace == claims.namespace,
              identity.caller == claims.caller, identity.ticketExpiry == claims.expires,
              let w = document.records[i].work, w.times.attachmentEpoch == attachment.epoch,
              !attached || w.times.attached else { throw LifecycleError.stale }
        return i
    }
    func status(_ r: LifecycleRecord) -> LifecycleStatus {
        .init(phase: r.phase, attachment: r.work.flatMap { $0.times.attached ? .init(record: r.id, ownerEpoch: catalog.epoch, epoch: $0.times.attachmentEpoch) : nil },
            high: r.high, providerEnding: r.ending, disposition: r.disposition, resumable: !r.nonResumable && r.work != nil)
    }
    // Call after the last blocking operation. This final sample is intentionally
    // not followed by another persistence on the live path: no check/fsync loop.
    func publicationReady(_ r: LifecycleRecord, observed: UInt64, ticket: SessionTicket, authorization: LifecycleAuthorization) throws -> Bool {
        try authorization.validate()
        let now = try catalog.clock.now()
        guard now >= observed else { throw LifecycleError.invalid("clock rollback") }
        if let reason = expiry(r, now: now) { try retire(r.id, disposition: reason); return false }
        _ = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: authorization, now: now)
        return true
    }
    func publishedStatus(_ r: LifecycleRecord, observed: UInt64, ticket: SessionTicket, authorization: LifecycleAuthorization) throws -> LifecycleStatus {
        guard try publicationReady(r, observed: observed, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }
        return status(r)
    }
    public func begin(ticket: SessionTicket, authorization: LifecycleAuthorization, generation: String, provider: ProviderBinding) throws -> LifecycleStatus {
        var (d, claims) = try context(ticket, authorization)
        let request = LifecycleRequest(namespace: claims.namespace, generation: generation, caller: claims.caller, provider: provider)
        try request.validate()
        let bytes = try lcEncode(request), digest = lcHash(bytes), op = lcHash(Data(provider.operationID.utf8))
        if let i = d.records.firstIndex(where: { $0.identity?.namespace == claims.namespace && $0.identity?.generation == generation }) {
            guard let id = d.records[i].identity, id.caller == claims.caller, id.ticketExpiry == claims.expires,
                  id.requestDigest == digest, id.operationDigest == op else { throw LifecycleError.invalid("changed duplicate begin") }
            // Repeated begin reports the same state. Only explicit attach/touch
            // may change attachment epoch/contact; fixed deadlines never move.
            return try publishedStatus(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization)
        }
        guard d.records.count < LifecycleLimits.records, !d.records.contains(where: { $0.phase == .retiring }),
              !d.records.contains(where: { $0.identity?.operationDigest == op }) else { throw LifecycleError.full }
        let queued = d.records.contains { $0.phase.reservesExecution }
        if queued {
            guard d.records.filter({ $0.phase == .queued }).count < 3,
                  !d.records.contains(where: { $0.phase == .queued && $0.identity?.namespace == claims.namespace }) else { throw LifecycleError.full }
        }
        try catalog.files.reserve(quota: catalog.identity.quota, child: !queued, request: true)
        let now = d.lastObserved, requestID = UUID().uuidString.lowercased(), childID = UUID().uuidString.lowercased(), keys = try GenerationSecrets()
        let cipher = try LifecycleCrypto.seal(bytes, role: "request", record: requestID, identity: catalog.identity, key: SymmetricKey(data: keys.content))
        try catalog.files.requests.writeNew(LifecycleFileSystem.requestName(requestID), bytes: cipher, maximum: LifecycleLimits.request+LifecycleCrypto.overhead)
        try catalog.files.requests.sync()
        let times = LifecycleTimes(admitted: now, queueUntil: min(try lcAdd(now, LifecycleLimits.wait), claims.expires),
            absoluteUntil: min(try lcAdd(now, LifecycleLimits.inflight), claims.expires), lastContact: now)
        let record = LifecycleRecord(id: UUID().uuidString.lowercased(), identity: .init(namespace: claims.namespace, generation: generation,
            caller: claims.caller, ticketExpiry: claims.expires, requestDigest: digest, operationDigest: op), phase: queued ? .queued : .allocating,
            work: .init(request: requestID, child: childID, keys: keys, times: times))
        d.records.append(record); try catalog.replace(d)
        if !queued { try fault(.afterAllocating) }
        return try publishedStatus(record, observed: d.lastObserved, ticket: ticket, authorization: authorization)
    }
    public func attach(ticket: SessionTicket, authorization: LifecycleAuthorization, generation: String, cursor: UInt64) throws -> LifecycleStatus {
        var (d, claims) = try context(ticket, authorization)
        guard let i = d.records.firstIndex(where: { $0.identity?.namespace == claims.namespace && $0.identity?.generation == generation }),
              d.records[i].identity?.caller == claims.caller else { throw LifecycleError.invalid("unknown generation") }
        guard var w = d.records[i].work else { return try publishedStatus(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) }
        // A context fsync may expire detached residency. Check the original
        // record before clearing that deadline or refreshing authenticated contact.
        guard try publicationReady(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }
        guard cursor <= d.records[i].high else { throw LifecycleError.invalid("cursor above high") }
        w.times.attachmentEpoch = try lcAdd(w.times.attachmentEpoch, 1)
        w.times.attached = true; w.times.detachedUntil = nil; w.times.lastContact = d.lastObserved
        d.records[i].work = w; try catalog.replace(d)
        return try publishedStatus(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization)
    }
    public func touch(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment) throws {
        var (d, claims) = try context(ticket, authorization)
        let i = try index(attachment, claims: claims, document: d)
        guard try publicationReady(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }
        d.records[i].work!.times.lastContact = d.lastObserved; try catalog.replace(d)
        _ = try publishedStatus(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization)
    }
    public func detach(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment) throws {
        var (d, claims) = try context(ticket, authorization)
        let i = try index(attachment, claims: claims, document: d, attached: false)
        guard try publicationReady(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }
        var w = d.records[i].work!
        if w.times.attached {
            w.times.attached = false; w.times.lastContact = d.lastObserved
            w.times.detachedUntil = min(try lcAdd(d.lastObserved, LifecycleLimits.wait), w.times.absoluteUntil, claims.expires)
            d.records[i].work = w; try catalog.replace(d)
        }
        _ = try publishedStatus(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization)
    }
    public func cancel(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment) throws -> LifecycleStatus {
        let (d, claims) = try context(ticket, authorization)
        let i = try index(attachment, claims: claims, document: d, attached: false), id = d.records[i].id
        try retire(id, disposition: "cancelled")
        let retired = try catalog.load()
        guard let r = retired.records.first(where: { $0.id == id }) else { throw LifecycleError.expired }
        return try publishedStatus(r, observed: retired.lastObserved, ticket: ticket, authorization: authorization)
    }
    func expiry(_ r: LifecycleRecord, now: UInt64) -> String? {
        guard let id = r.identity else { return "ticket-expired" }
        if now >= id.ticketExpiry { return "ticket-expired" }
        guard let t = r.work?.times else { return nil }
        if now >= t.absoluteUntil { return "inflight-expired" }
        if let until = t.detachedUntil, now >= until { return "detached-expired" }
        if let until = t.terminalUntil, now >= until { return "terminal-expired" }
        if [.queued, .allocating, .preparing].contains(r.phase), now >= t.queueUntil { return "queue-expired" }
        return nil
    }
    public func maintenance() throws {
        if catalog.uncertain { closeChildren(); _ = try catalog.reconcile() }
        var d = try catalog.load(); _ = try catalog.time(&d); try catalog.replace(d)
        for id in d.records.map(\.id) {
            var current = try catalog.load(); let now = try catalog.time(&current)
            guard let i = current.records.firstIndex(where: { $0.id == id }) else { continue }
            let r = current.records[i]
            if r.phase == .retiring { try finishRetirement(id); continue }
            if r.phase == .tombstone {
                if r.identity!.ticketExpiry <= now { current.records.remove(at: i); try catalog.replace(current) }
                continue
            }
            if let ruling = expiry(r, now: now) { try retire(id, disposition: ruling); continue }
            do {
                _ = try catalog.request(r)
                if r.phase != .queued { try reconcileRecord(&current.records[i]) }
            } catch {
                children.removeValue(forKey: r.id)?.close()
                current.records[i].nonResumable = true
            }
            // A metadata/decryption call can itself cross a fixed deadline.
            let after = try catalog.time(&current); try catalog.replace(current)
            if let ruling = expiry(current.records[i], now: after) { try retire(id, disposition: ruling) }
        }
        d = try catalog.load(); _ = try catalog.time(&d)
        if !d.records.contains(where: { $0.phase.reservesExecution || $0.phase == .retiring }),
           let i = d.records.firstIndex(where: { $0.phase == .queued && !$0.nonResumable }) {
            try catalog.files.reserve(quota: catalog.identity.quota, child: true)
            d.records[i].phase = .allocating; try catalog.replace(d); try fault(.afterAllocating)
        }
        try catalog.cleanRequests(catalog.load())
    }
}
