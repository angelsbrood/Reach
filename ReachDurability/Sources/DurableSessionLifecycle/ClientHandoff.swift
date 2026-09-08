import Foundation
import DurableHostStore
import DurableClientReceipts
import HostClientContract
import ReachWire

extension DurableSessionLifecycle {
    private func exactClaims(_ ticket: SessionTicket, _ auth: LifecycleAuthorization, observed: UInt64) throws -> TicketClaims {
        let now = try catalog.clock.now()
        guard now >= observed else { throw LifecycleError.invalid("clock rollback") }
        let c = try TicketCodec.verify(ticket, identity: catalog.identity, keys: catalog.keys, auth: auth, now: now)
        guard try lcEncode(c.caller) == lcEncode(auth.caller) else { throw LifecycleError.unauthorized }; return c
    }
    private func joinRecord(_ ticket: SessionTicket, _ auth: LifecycleAuthorization, generation: String) throws -> (CatalogDocument, TicketClaims, LifecycleRecord) {
        try lcID(generation)
        _ = try exactClaims(ticket, auth, observed: 0)
        let (d, claims) = try context(ticket, auth)
        _ = try exactClaims(ticket, auth, observed: d.lastObserved)
        guard let r = d.records.first(where: { $0.identity.map {
            HandoffContract.equal($0.namespace, claims.namespace) && HandoffContract.equal($0.generation, generation)
        } ?? false }), let id = r.identity, try lcEncode(id.caller) == lcEncode(claims.caller), id.ticketExpiry == claims.expires else { throw HandoffError.invalid }
        return (d, claims, r)
    }
    private func originalClientAuthority(_ r: LifecycleRecord, _ claims: TicketClaims) throws -> ClientAuthority {
        guard let work = r.work, let id = r.identity, !r.nonResumable else { throw LifecycleError.nonResumable }
        let request = try catalog.request(r), bytes = try lcEncode(request), provider = try lcEncode(request.provider)
        guard HandoffContract.equal(request.namespace, claims.namespace), HandoffContract.equal(request.generation, id.generation),
              try lcEncode(request.caller) == lcEncode(claims.caller), lcHash(bytes) == id.requestDigest,
              lcHash(Data(request.provider.operationID.utf8)) == id.operationDigest else { throw HandoffError.invalid }
        var digest = HandoffDigest("upstream-binding", context: Data(catalog.identity.incarnation.utf8))
        digest.append(Data(work.child.utf8)); digest.append(bytes); digest.append(provider)
        return try ClientAuthority(.init(caller: .init(principal: claims.caller.principal, device: claims.caller.device, app: claims.caller.app),
            host: catalog.identity.incarnation, store: catalog.identity.incarnation, namespace: claims.namespace, generation: id.generation,
            request: request.provider.requestID, operation: request.provider.operationID, upstreamDigest: digest.finish(),
            route: request.provider.lane.route.rawValue, revision: HandoffContract.revision, issued: claims.issued, expires: claims.expires))
    }
    private func joinPublication(_ r: LifecycleRecord, observed: UInt64, ticket: SessionTicket, auth: LifecycleAuthorization,
                                 hook: () throws -> Void) throws -> LifecycleStatus {
        try hook()
        let c = try exactClaims(ticket, auth, observed: observed)
        guard let id = r.identity, try lcEncode(id.caller) == lcEncode(c.caller),
              HandoffContract.equal(id.namespace, c.namespace), id.ticketExpiry == c.expires else { throw HandoffError.invalid }
        return try publishedStatus(r, observed: observed, ticket: ticket, authorization: auth)
    }
    public func exportClientContext(ticket: SessionTicket, authorization: LifecycleAuthorization,
                                    attachment: LifecycleAttachment, publicationHook: () throws -> Void = {}) throws -> Data {
        _ = try exactClaims(ticket, authorization, observed: 0)
        let (d, claims) = try context(ticket, authorization)
        let i = try index(attachment, claims: claims, document: d), r = d.records[i]
        let a = try originalClientAuthority(r, claims)
        _ = try joinPublication(r, observed: d.lastObserved, ticket: ticket, auth: authorization, hook: publicationHook)
        return a.bytes
    }
    public func replayForClient(ticket: SessionTicket, authorization: LifecycleAuthorization, attachment: LifecycleAttachment,
                                after cursor: UInt64, publicationHook: () throws -> Void = {}) throws -> [HandoffBatch] {
        _ = try exactClaims(ticket, authorization, observed: 0)
        let frames = try replay(ticket: ticket, authorization: authorization, attachment: attachment, after: cursor)
        var d = try catalog.load(); _ = try catalog.time(&d)
        let claims = try exactClaims(ticket, authorization, observed: d.lastObserved)
        let i = try index(attachment, claims: claims, document: d)
        let output = frames.map { HandoffBatch(first: $0.firstSequence, count: $0.count, commit: $0.providerCommit, bytes: $0.eventBytes, skip: $0.skipPrefix) }
        _ = try joinPublication(d.records[i], observed: d.lastObserved, ticket: ticket, auth: authorization, hook: publicationHook)
        return output
    }
    private func validateLiveWitness(_ witness: HandoffWitness, root: String, record r: LifecycleRecord, claims: TicketClaims) throws {
        try witness.validate(expectedRoot: root)
        let a = try originalClientAuthority(r, claims)
        guard witness.context == HandoffContract.hash(a.bytes), witness.high <= r.high else { throw HandoffError.invalid }
        var prefix = HandoffPrefix(context: a.bytes), terminal = false, boundary = witness.high == 0
        let frames: [StoreReplayFrame] = r.high == 0 ? [] : try child(r).store.replay(after: 0)
        for f in frames {
            let b = HandoffBatch(first: f.firstSequence, count: f.count, commit: f.providerCommit, bytes: f.eventBytes, skip: f.skipPrefix)
            let last = try b.last()
            if last > witness.high { break }
            guard f.skipPrefix == 0 else { throw HandoffError.invalid }; try prefix.append(b)
            let events = try ClientEvents.decode(f.eventBytes)
            guard events.count == f.count else { throw HandoffError.invalid }
            for event in events {
                if case .toolCallAppendArguments(_, let id, let name, let args, _) = event {
                    try prefix.register(id: Data(id.utf8), name: Data(name.utf8), arguments: Data(args.utf8))
                }
            }
            if case .finished? = events.last { terminal = true }
            if last == witness.high { boundary = true }
        }
        let (batches, calls) = prefix.digests()
        guard boundary, prefix.high == witness.high, batches == witness.prefix, calls == witness.calls,
              prefix.registrations == witness.registrations, terminal == witness.terminal,
              !terminal || (r.phase == .terminal && r.ending != nil && witness.high == r.high) else { throw HandoffError.invalid }
    }
    public func attachClient(ticket: SessionTicket, authorization: LifecycleAuthorization, generation: String,
                             witness: HandoffWitness, expectedClientRoot: String) throws -> LifecycleStatus {
        let (d, claims, r) = try joinRecord(ticket, authorization, generation: generation)
        try validateLiveWitness(witness, root: expectedClientRoot, record: r, claims: claims)
        _ = try joinPublication(r, observed: d.lastObserved, ticket: ticket, auth: authorization, hook: {})
        let result = try attach(ticket: ticket, authorization: authorization, generation: generation, cursor: witness.high)
        _ = try exactClaims(ticket, authorization, observed: d.lastObserved); return result
    }
    /// Trusted local consistency check; no remote persistence attestation.
    public func acceptClientWitness(_ witness: HandoffWitness, expectedClientRoot: String, ticket: SessionTicket,
                                     authorization: LifecycleAuthorization, generation: String, attachment: LifecycleAttachment?,
                                     publicationHook: () throws -> Void = {}) throws -> LifecycleStatus {
        try witness.validate(expectedRoot: expectedClientRoot)
        let (d, claims, r) = try joinRecord(ticket, authorization, generation: generation)
        let fingerprint = try witness.disposition()
        if r.phase == .retiring || r.phase == .tombstone {
            guard r.disposition == fingerprint else { throw HandoffError.invalid }
            if r.phase == .retiring { try finishRetirement(r.id) }
        } else {
            guard let attachment, try index(attachment, claims: claims, document: d) == d.records.firstIndex(where: { $0.id == r.id }) else { throw LifecycleError.stale }
            try validateLiveWitness(witness, root: expectedClientRoot, record: r, claims: claims)
            _ = try joinPublication(r, observed: d.lastObserved, ticket: ticket, auth: authorization, hook: {})
            if !witness.terminal {
                try acknowledgeDelivery(ticket: ticket, authorization: authorization, attachment: attachment, through: witness.high)
            } else {
                let prior = fault
                fault = { point in
                    try prior(point)
                    if point == .beforeRetirementIntent {
                        _ = try self.exactClaims(ticket, authorization, observed: d.lastObserved)
                        guard self.expiry(r, now: try self.catalog.clock.now()) == nil else { throw LifecycleError.expired }
                    }
                }
                defer { fault = prior }
                try retire(r.id, disposition: fingerprint)
            }
        }
        var final = try catalog.load(); _ = try catalog.time(&final)
        guard let record = final.records.first(where: { $0.id == r.id }),
              !witness.terminal || record.disposition == fingerprint else { throw HandoffError.invalid }
        return try joinPublication(record, observed: final.lastObserved, ticket: ticket, auth: authorization, hook: publicationHook)
    }
}
