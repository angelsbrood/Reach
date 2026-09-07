import Foundation
import RecoveryContract

public struct RecoveredClient {
    public let authority: ClientAuthority, handle: ClientHandle, receipt: DurableReceipt
}
extension DurableClientReceipts {
    func recoveryBinding(_ binding: RecoveryBinding) throws {
        try fs.ensure(); try environment.validate(clock); try binding.validate()
        guard crEqual(binding.clientRoot,environment.rootID), crEqual(binding.boot,environment.boot),
              crEqual(binding.clientPolicy,environment.policy) else { throw RecoveryError.invalid }
    }
    func recoveryCaller(_ auth: ClientAuthorization, frozen: Data? = nil) throws -> Data {
        try fs.ensure(); try auth.caller.validate(); let bytes=try crEncode(auth.caller)
        guard auth.allowed, frozen == nil || frozen == bytes else { throw RecoveryError.unauthorized }; return bytes
    }
    func recoveryTime(_ live: LiveClientRecord, _ m: ClientManifest) throws {
        let now=try observe(m); guard now>=live.issued, now<live.expires else { throw RecoveryError.expired }
    }
    func recoveryManifest(_ auth: ClientAuthorization, frozen: Data, hook: RecoveryHook) throws -> ClientManifest {
        let m=try readManifest(); guard m.ownerEpoch==ownerEpoch else { throw RecoveryError.stale }
        _=try observe(m); try hook(.afterManifest); _=try recoveryCaller(auth,frozen:frozen); return m
    }
    func recoveryAuthority(_ r: ClientRecord, _ m: ClientManifest, binding: RecoveryBinding,
                           auth: ClientAuthorization, frozen: Data, hook: RecoveryHook) throws -> (ClientAuthority,ClientSnapshot) {
        guard let live=r.live else { throw RecoveryError.expired }
        try hook(.beforeSnapshot); _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(live,m)
        let s=try snapshot(r) // Never called for expired or cleanup-only records.
        try hook(.afterSnapshot); _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(live,m)
        let a=try ClientAuthority(JSONDecoder().decode(ClientContext.self,from:s.context))
        guard a.bytes==s.context, crEqual(a.context.host,binding.host), crEqual(a.context.store,binding.host),
              a.context.revision=="s84-host-client-v1" else { throw RecoveryError.invalid }
        return (a,s)
    }
    func recoveryPublish(_ auth: ClientAuthorization, frozen: Data, m: ClientManifest,
                         live: [LiveClientRecord], hook: RecoveryHook) throws {
        try hook(.beforePublication); _=try recoveryCaller(auth,frozen:frozen)
        for record in live { try recoveryTime(record,m) }
    }
    public func discover(binding: RecoveryBinding, authorization auth: ClientAuthorization, hook: RecoveryHook = { _ in }) throws -> [RecoverySummary] {
        try recoveryBinding(binding); let frozen=try recoveryCaller(auth), m=try recoveryManifest(auth,frozen:frozen,hook:hook)
        var result:[RecoverySummary]=[], published:[LiveClientRecord]=[]
        for r in m.records {
            guard let live=r.live else { continue }
            let now=try observe(m); if now<live.issued || now>=live.expires { continue }
            let (a,s)=try recoveryAuthority(r,m,binding:binding,auth:auth,frozen:frozen,hook:hook)
            guard try crEncode(a.context.caller)==frozen else { continue }
            result.append(.init(record:r.id,contextDigest:live.contextDigest,ownerEpoch:ownerEpoch,snapshotRevision:live.snapshot.revision,
                issued:live.issued,expires:live.expires,high:s.high,terminal:s.terminal,calls:s.calls.count)); published.append(live)
        }
        guard result.count<=RecoveryLimits.records else { throw RecoveryError.full }
        _=try RecoveryCodec.encode(result,maximum:RecoveryLimits.summaries)
        try recoveryPublish(auth,frozen:frozen,m:m,live:published,hook:hook); return result
    }
    func selectedRecovery(_ selection: RecoverySummary, binding: RecoveryBinding, auth: ClientAuthorization,
                          frozen: Data, hook: RecoveryHook) throws -> (ClientManifest,ClientRecord,RecoveredClient) {
        try recoveryBinding(binding); _=try recoveryCaller(auth,frozen:frozen)
        let m=try recoveryManifest(auth,frozen:frozen,hook:hook)
        guard selection.ownerEpoch==ownerEpoch, let r=m.records.first(where:{$0.id==selection.record}), let live=r.live,
              selection.contextDigest==live.contextDigest, selection.snapshotRevision==live.snapshot.revision,
              selection.issued==live.issued, selection.expires==live.expires else { throw RecoveryError.stale }
        try recoveryTime(live,m)
        let (a,s)=try recoveryAuthority(r,m,binding:binding,auth:auth,frozen:frozen,hook:hook)
        guard try crEncode(a.context.caller)==frozen else { throw RecoveryError.unauthorized }
        return (m,r,.init(authority:a,handle:.init(record:r.id,ownerEpoch:ownerEpoch),receipt:s.receipt()))
    }
    public func resolve(_ selection: RecoverySummary, binding: RecoveryBinding,
                        authorization auth: ClientAuthorization, hook: RecoveryHook = { _ in }) throws -> RecoveredClient {
        let frozen=try recoveryCaller(auth), (m,r,client)=try selectedRecovery(selection,binding:binding,auth:auth,frozen:frozen,hook:hook)
        try recoveryPublish(auth,frozen:frozen,m:m,live:[r.live!],hook:hook); return client
    }
}
