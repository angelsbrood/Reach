import Foundation
import ResumableMLXProvider
import DurableClientReceipts
import HostClientContract

extension DurableSessionLifecycle {
    private func wireContext(_ ticket:SessionTicket,_ auth:LifecycleAuthorization) throws -> (CatalogDocument,TicketClaims,Data) {
        let frozen=try lcEncode(auth.caller)
        let initial=try TicketCodec.verify(ticket,identity:catalog.identity,keys:catalog.keys,auth:auth,now:catalog.clock.now())
        guard try lcEncode(initial.caller)==frozen else { throw LifecycleError.unauthorized }
        let (d,c)=try context(ticket,auth)
        guard try lcEncode(auth.caller)==frozen,try lcEncode(c.caller)==frozen else { throw LifecycleError.unauthorized }
        return (d,c,frozen)
    }
    private func wirePublish(_ ticket:SessionTicket,_ auth:LifecycleAuthorization,_ d:CatalogDocument,_ claims:TicketClaims,_ frozen:Data,_ hook:() throws -> Void) throws {
        try hook()
        let now=try catalog.clock.now()
        guard now>=d.lastObserved,try lcEncode(auth.caller)==frozen else { throw LifecycleError.unauthorized }
        let final=try TicketCodec.verify(ticket,identity:catalog.identity,keys:catalog.keys,auth:auth,now:now)
        guard try lcEncode(final)==lcEncode(claims),try lcEncode(final.caller)==frozen else { throw LifecycleError.unauthorized }
    }
    /// Issuer-verified namespace, including current exact caller and publication
    /// recheck. It never exposes decoded-but-unverified ticket claims.
    public func wireSessionID(ticket:SessionTicket,authorization:LifecycleAuthorization,publicationHook:() throws -> Void = {}) throws -> String {
        let (d,c,frozen)=try wireContext(ticket,authorization)
        try wirePublish(ticket,authorization,d,c,frozen,publicationHook);return c.namespace
    }
    /// Read-only selected LIVE provider declaration. Receipt retries deliberately
    /// use acceptClientWitness directly, because retirement removes this content.
    public func wireProviderBinding(ticket:SessionTicket,authorization:LifecycleAuthorization,generation:String,publicationHook:() throws -> Void = {}) throws -> ProviderBinding {
        try lcID(generation)
        let (d,c,frozen)=try wireContext(ticket,authorization)
        guard let r=d.records.first(where:{$0.identity?.namespace==c.namespace && $0.identity?.generation==generation}),let id=r.identity,
              try lcEncode(id.caller)==frozen,id.ticketExpiry==c.expires,r.work != nil,!r.nonResumable else { throw LifecycleError.nonResumable }
        let request=try catalog.request(r)
        guard request.namespace==c.namespace,request.generation==generation,try lcEncode(request.caller)==frozen,
              try lcHash(lcEncode(request))==id.requestDigest,lcHash(Data(request.provider.operationID.utf8))==id.operationDigest else { throw LifecycleError.invalid("stored wire binding") }
        _=try publishedStatus(r,observed:d.lastObserved,ticket:ticket,authorization:authorization)
        try wirePublish(ticket,authorization,d,c,frozen,publicationHook)
        return request.provider
    }
    /// Read-only original-context projection BEFORE attach. The derivation is
    /// the accepted S84 ClientHandoff upstream binding; exportClientContext is
    /// checked again after the real attach. No request bytes survive retirement.
    public func wireOriginalClientContext(ticket:SessionTicket,authorization:LifecycleAuthorization,generation:String) throws -> Data {
        let provider=try wireProviderBinding(ticket:ticket,authorization:authorization,generation:generation)
        let (d,c,frozen)=try wireContext(ticket,authorization)
        guard let r=d.records.first(where:{$0.identity?.namespace==c.namespace && $0.identity?.generation==generation}),let work=r.work,
              let id=r.identity,try lcEncode(id.caller)==frozen,id.ticketExpiry==c.expires else { throw LifecycleError.nonResumable }
        let request=try catalog.request(r),bytes=try lcEncode(request)
        guard lcHash(bytes)==id.requestDigest,try lcEncode(request.provider)==lcEncode(provider) else { throw LifecycleError.invalid("context projection") }
        var digest=HandoffDigest("upstream-binding",context:Data(catalog.identity.incarnation.utf8))
        digest.append(Data(work.child.utf8));digest.append(bytes);digest.append(try lcEncode(provider))
        let a=try ClientAuthority(.init(caller:.init(principal:c.caller.principal,device:c.caller.device,app:c.caller.app),
            host:catalog.identity.incarnation,store:catalog.identity.incarnation,namespace:c.namespace,generation:generation,
            request:provider.requestID,operation:provider.operationID,upstreamDigest:digest.finish(),route:provider.lane.route.rawValue,
            revision:HandoffContract.revision,issued:c.issued,expires:c.expires))
        _=try publishedStatus(r,observed:d.lastObserved,ticket:ticket,authorization:authorization)
        try wirePublish(ticket,authorization,d,c,frozen,{});return a.bytes
    }
}


extension DurableSessionLifecycle {
    /// Host-local retirement under an already-acquired lifecycle/key owner. The
    /// transport never exposes this operation to a peer. Its caller supplies the
    /// key-confirmed local reservation; no client journal or replacement ticket
    /// is used to recover authority. The existing retirement/ending rules apply.
    public func wireCancelLocalReservation(namespace: String, generation: String, requestDigest: String,
                                           authorization: LifecycleAuthorization) throws -> LifecycleStatus? {
        try lcID(generation); try authorization.caller.validate()
        guard authorization.allowed, lcUUID(namespace), requestDigest.utf8.count == 64 else { throw LifecycleError.unauthorized }
        let document = try catalog.load()
        guard let record = document.records.first(where: { $0.identity?.namespace == namespace && $0.identity?.generation == generation }),
              let identity = record.identity, try lcEncode(identity.caller) == lcEncode(authorization.caller) else { return nil }
        if record.work != nil {
            let request = try catalog.request(record)
            guard lcHash(Data(request.provider.requestID.utf8)) == requestDigest, try lcHash(lcEncode(request)) == identity.requestDigest else { throw LifecycleError.nonResumable }
        }
        try retire(record.id, disposition: "cancelled")
        let final = try catalog.load()
        guard let retained = final.records.first(where: { $0.id == record.id }) else { return nil }
        return status(retained)
    }
}

extension DurableSessionLifecycle {
    /// Non-content observation of the currently committed native checkpoint.
    /// This uses the already-owned store and authenticates again before publish;
    /// it cannot attach, restore a model, or manufacture checkpoint state.
    public func wireNativeCheckpointPhase(ticket: SessionTicket, authorization: LifecycleAuthorization,
                                          attachment: LifecycleAttachment) throws -> String? {
        let (document, claims, frozen) = try wireContext(ticket, authorization)
        let i = try index(attachment, claims: claims, document: document)
        let record = document.records[i]
        guard record.work != nil, !record.nonResumable else { throw LifecycleError.nonResumable }
        let candidate = try child(record).store.snapshot().candidate
        struct Projection: Decodable { let phase: String }
        let phase = try candidate.map { try JSONDecoder().decode(Projection.self, from: $0.checkpointBytes).phase }
        _ = try publishedStatus(record, observed: document.lastObserved, ticket: ticket, authorization: authorization)
        try wirePublish(ticket, authorization, document, claims, frozen, {})
        return phase
    }
}
