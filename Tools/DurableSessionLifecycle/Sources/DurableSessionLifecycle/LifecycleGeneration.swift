import Foundation
import Darwin
import DurableHostStore
import ResumableMLXProvider
import ReachWire

final class LifecycleChild {
    let store: DurableHostStore
    var generation: DurableGeneration?
    var delivered: UInt64 = 0
    init(_ store: DurableHostStore) { self.store = store }
    func close() { generation?.close(); generation = nil; store.close() }
}
extension DurableSessionLifecycle {
    func child(_ record: LifecycleRecord) throws -> LifecycleChild {
        try catalog.files.ensure()
        if let existing = children[record.id], !existing.store.isClosed { return existing }
        guard let work = record.work else { throw LifecycleError.retired }
        let request = try catalog.request(record)
        let identity = try StoreIdentity(storeID: work.child, provider: request.provider)
        let store = try DurableHostStore.reopen(at: catalog.files.childPath(work.child), identity: identity, keys: work.keys.storeKeys())
        let handle = LifecycleChild(store); children[record.id] = handle; return handle
    }
    func reconcileRecord(_ record: inout LifecycleRecord) throws {
        guard let work = record.work else { return }
        let exists = try catalog.files.children.exists(LifecycleFileSystem.childName(work.child))
        if record.phase == .allocating {
            guard exists else { return }
            let directory = try OwnedDirectory(parent: catalog.files.children, name: LifecycleFileSystem.childName(work.child)); defer { directory.close() }
            // Only missing authority in allocating is an incomplete pre-provider
            // directory. A present but invalid authority remains non-resumable.
            if !(try directory.exists("current")) { return }
        } else if !exists { throw LifecycleError.nonResumable }
        let state = try child(record).store.snapshot()
        if record.phase == .allocating {
            guard state.candidate == nil else { throw LifecycleError.nonResumable }
            record.phase = .preparing; record.nonResumable = false; return
        }
        guard let candidate = state.candidate else {
            guard record.phase == .preparing else { throw LifecycleError.nonResumable }
            record.high = 0; record.nonResumable = false; return
        }
        struct Ending: Decodable { let terminal: WireFinishReason? }
        let ending = try JSONDecoder().decode(Ending.self, from: candidate.commit.data).terminal
        if state.terminal {
            guard let ending else { throw LifecycleError.nonResumable }
            if record.phase == .terminal {
                guard try lcEncode(record.ending) == lcEncode(ending), work.times.terminalUntil != nil else { throw LifecycleError.nonResumable }
            } else {
                guard let start = work.times.transitionStartedAt, let identity = record.identity else { throw LifecycleError.nonResumable }
                record.work!.times.terminalUntil = min(try lcAdd(start, LifecycleLimits.terminal), work.times.absoluteUntil, identity.ticketExpiry)
            }
            record.phase = .terminal; record.ending = ending
        } else {
            guard record.phase != .terminal, ending == nil else { throw LifecycleError.nonResumable }
            record.phase = .active
            record.work!.times.transitionStartedAt = nil
        }
        record.high = state.high; record.nonResumable = false
    }
    func allocate(_ id: String) throws {
        var d = try catalog.load()
        guard let i = d.records.firstIndex(where: { $0.id == id }), let work = d.records[i].work,
              d.records[i].phase == .allocating, !d.records[i].nonResumable else { throw LifecycleError.nonResumable }
        try catalog.files.reserve(quota: catalog.identity.quota, child: true)
        let childName = LifecycleFileSystem.childName(work.child)
        if try catalog.files.children.exists(childName) {
            let directory = try OwnedDirectory(parent: catalog.files.children, name: childName)
            let hasCurrent = try directory.exists("current"); directory.close()
            if hasCurrent {
                try reconcileRecord(&d.records[i])
                guard d.records[i].phase == .preparing else { throw LifecycleError.nonResumable }
                try catalog.replace(d); return
            }
        } else {
            // A durable allocating record precedes even this empty directory.
            guard mkdirat(catalog.files.children.fd, childName, 0o700) == 0 else { throw LifecycleError.io("child allocation", errno) }
            try catalog.files.children.sync(); try fault(.afterDirectoryCreated)
        }
        let guardFile = try ChildRetirementGuard(parent: catalog.files.children, name: childName, allowIncomplete: true)
        try guardFile.remove { }; guardFile.close()
        let request = try catalog.request(d.records[i]), identity = try StoreIdentity(storeID: work.child, provider: request.provider)
        let store = try DurableHostStore.initialize(at: catalog.files.childPath(work.child), identity: identity, keys: work.keys.storeKeys())
        children[id] = LifecycleChild(store)
        guard try store.snapshot().candidate == nil else { store.close(); throw LifecycleError.nonResumable }
        try fault(.afterEmptyChild)
        d.records[i].phase = .preparing; try catalog.replace(d); try fault(.afterPreparing)
    }
    @discardableResult public func step(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment,
        runtime: () throws -> ProviderRuntime) throws -> LifecycleStatus {
        let (initial, claims) = try context(ticket, authorization)
        let initialIndex = try index(attachment, claims: claims, document: initial), id = initial.records[initialIndex].id
        guard !initial.records[initialIndex].nonResumable else { throw LifecycleError.nonResumable }
        if initial.records[initialIndex].phase == .queued { throw LifecycleError.queued }
        if initial.records[initialIndex].phase == .terminal {
            return try publishedStatus(initial.records[initialIndex], observed: initial.lastObserved, ticket: ticket, authorization: authorization)
        }
        do {
            if initial.records[initialIndex].phase == .allocating { try allocate(id) }
            var d = try catalog.load(); let now = try catalog.time(&d)
            let i = try index(attachment, claims: claims, document: d)
            if let reason = expiry(d.records[i], now: now) { try catalog.replace(d); try retire(id, disposition: reason); return try result(id, ticket: ticket, authorization: authorization) }
            let handle = try child(d.records[i])
            guard handle.delivered == d.records[i].high else { throw StoreError.replayRequired }
            try catalog.files.reserve(quota: catalog.identity.quota, child: true); try handle.store.reserve()
            _ = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: authorization, now: now)
            // Retention uses this persisted lower bound if child commitment
            // survives but catalog promotion/reply does not.
            d.records[i].work!.times.transitionStartedAt = now; try catalog.replace(d)
            // Credit checks and intent fsync can themselves consume the remaining
            // lifetime. Read the clock again immediately before each child call.
            guard try nativeWindow(id, ticket: ticket, authorization: authorization) else { return try result(id, ticket: ticket, authorization: authorization) }
            if try handle.store.snapshot().candidate == nil {
                guard d.records[i].phase == .preparing else { throw LifecycleError.nonResumable }
                handle.generation = try DurableGeneration.start(store: handle.store, runtime: runtime)
                try fault(.afterC0)
            } else {
                if handle.generation == nil {
                    handle.generation = try DurableGeneration.recover(store: handle.store, runtime: runtime)
                    guard try nativeWindow(id, ticket: ticket, authorization: authorization) else { return try result(id, ticket: ticket, authorization: authorization) }
                }
                try handle.generation!.acknowledgeDelivery(through: handle.delivered)
                try handle.generation!.advance()
            }
            if try handle.store.snapshot().terminal { try fault(.afterChildTerminal) }
            d = try catalog.load(); _ = try catalog.time(&d)
            try reconcileRecord(&d.records[i]); try catalog.replace(d)
            guard try publicationReady(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) else { return try result(id, ticket: ticket, authorization: authorization) }
            return status(d.records[i])
        } catch { children.removeValue(forKey: id)?.close(); throw error }
    }
    private func nativeWindow(_ id: String, ticket: SessionTicket, authorization: LifecycleAuthorization) throws -> Bool {
        try authorization.validate()
        var d = try catalog.load(); let now = try catalog.time(&d)
        guard let r = d.records.first(where: { $0.id == id }) else { throw LifecycleError.expired }
        if let reason = expiry(r, now: now) {
            try catalog.replace(d); try retire(id, disposition: reason); return false
        }
        _ = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: authorization, now: now)
        return true
    }
    func result(_ id: String, ticket: SessionTicket, authorization: LifecycleAuthorization) throws -> LifecycleStatus {
        // Outer retirement status is still private caller metadata. Authenticate
        // after the final catalog read, even when no live content can be returned.
        var document = try catalog.load(); let now = try catalog.time(&document)
        _ = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: authorization, now: now)
        guard let record = document.records.first(where: { $0.id == id }) else { throw LifecycleError.expired }
        return status(record)
    }
    public func replay(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment, after cursor: UInt64) throws -> [StoreReplayFrame] {
        var (d, claims) = try context(ticket, authorization)
        let i = try index(attachment, claims: claims, document: d), r = d.records[i]
        guard !r.nonResumable else { throw LifecycleError.nonResumable }
        if [.queued, .allocating, .preparing].contains(r.phase) {
            guard cursor == 0 else { throw LifecycleError.invalid("cursor above empty high") }
            guard try publicationReady(r, observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }; return []
        }
        let frames = try child(r).store.replay(after: cursor)
        _ = try catalog.time(&d); try catalog.replace(d)
        guard try publicationReady(r, observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }
        return frames
    }
    public func acknowledgeDelivery(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment, through cursor: UInt64) throws {
        let (d, claims) = try context(ticket, authorization), i = try index(attachment, claims: claims, document: d)
        guard cursor <= d.records[i].high else { throw LifecycleError.invalid("cursor above high") }
        if [.queued, .allocating].contains(d.records[i].phase) {
            guard cursor == 0 else { throw LifecycleError.invalid("empty delivery") }
            guard try publicationReady(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }; return
        }
        let handle = try child(d.records[i])
        guard try publicationReady(d.records[i], observed: d.lastObserved, ticket: ticket, authorization: authorization) else { throw LifecycleError.expired }
        guard cursor >= handle.delivered else { throw LifecycleError.stale }; handle.delivered = cursor
    }
}
