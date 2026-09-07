import Foundation
import RecoveryContract
import HostClientContract

public struct RecoveredHostJoin {
    public let client:RecoveredClient, ticket:Data, witness:HandoffWitness
}

extension DurableClientReceipts {
    func checkRecoveryTicket(_ ticket:Data, authority:ClientAuthority, binding:RecoveryBinding) throws {
        let claims=try RecoveryTicketClaims.parse(ticket), c=authority.context
        guard claims.incarnation==binding.host, claims.boot==binding.boot, crEqual(claims.policy,binding.hostPolicy),
              crEqual(claims.namespace,c.namespace), claims.issued==c.issued, claims.expires==c.expires,
              try crEncode(claims.caller)==crEncode(c.caller) else { throw RecoveryError.invalid }
    }
    /// Explicit enrollment creates only the fixed sibling directory, after client ownership.
    public func enrollRecovery(in parent:String, binding:RecoveryBinding) throws {
        try recoveryBinding(binding); let directory=try recoveryDirectory(parent,binding:binding,fresh:true)
        defer { directory.close() }; try directory.sync()
    }
    public func registerRecoveryTicket(_ ticket:Data, selection:RecoverySummary, in parent:String, binding:RecoveryBinding,
                                       authorization auth:ClientAuthorization, hook:RecoveryHook = { _ in }) throws {
        let frozen=try recoveryCaller(auth), (m,r,client)=try selectedRecovery(selection,binding:binding,auth:auth,frozen:frozen,hook:hook)
        try checkRecoveryTicket(ticket,authority:client.authority,binding:binding)
        let directory=try recoveryDirectory(parent,binding:binding,fresh:false); defer { directory.close() }
        let role=RecoveryFileSystem.role(r.id)
        if try directory.exists(role) {
            let data=try directory.read(role); try hook(.afterEnvelope)
            _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(r.live!,m)
            guard try RecoveryEncryption.open(data,live:r.live!,record:r.id,binding:binding,root:rootKey)==ticket else { throw RecoveryError.invalid }
            try directory.sync(); try recoveryPublish(auth,frozen:frozen,m:m,live:[r.live!],hook:hook); return
        }
        guard !(try directory.exists("pending")) else { throw RecoveryError.incomplete }
        _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(r.live!,m)
        let envelope=try RecoveryEncryption.seal(ticket,live:r.live!,record:r.id,binding:binding,root:rootKey)
        try directory.write(envelope,hook:hook)
        try hook(.beforeSelection); _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(r.live!,m)
        try directory.select(role); try hook(.afterSelection); try hook(.beforeDirectorySync); try directory.sync()
        try recoveryPublish(auth,frozen:frozen,m:m,live:[r.live!],hook:hook)
    }
    public func recoverHostTicket(_ selection:RecoverySummary, in parent:String, binding:RecoveryBinding,
                                  authorization auth:ClientAuthorization, hook:RecoveryHook = { _ in }) throws -> Data {
        let frozen=try recoveryCaller(auth), (m,r,client)=try selectedRecovery(selection,binding:binding,auth:auth,frozen:frozen,hook:hook)
        let directory=try recoveryDirectory(parent,binding:binding,fresh:false); defer { directory.close() }
        let role=RecoveryFileSystem.role(r.id)
        guard try directory.exists(role) else { throw RecoveryError.incomplete }
        let data=try directory.read(role); try hook(.afterEnvelope)
        _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(r.live!,m)
        let ticket=try RecoveryEncryption.open(data,live:r.live!,record:r.id,binding:binding,root:rootKey)
        try checkRecoveryTicket(ticket,authority:client.authority,binding:binding)
        try directory.sync() // Resolves selected/lost-sync uncertainty without promotion of pending bytes.
        try recoveryPublish(auth,frozen:frozen,m:m,live:[r.live!],hook:hook); return ticket
    }
    public func recoverHostJoin(_ selection:RecoverySummary, in parent:String, binding:RecoveryBinding,
                                authorization auth:ClientAuthorization, hook:RecoveryHook = { _ in }) throws -> RecoveredHostJoin {
        let frozen=try recoveryCaller(auth), (m,r,client)=try selectedRecovery(selection,binding:binding,auth:auth,frozen:frozen,hook:hook)
        let ticket=try recoverHostTicket(selection,in:parent,binding:binding,authorization:auth,hook:hook)
        _=try recoveryCaller(auth,frozen:frozen); try recoveryTime(r.live!,m)
        let witness=try hostWitness(client.handle,authority:client.authority,authorization:auth)
        try recoveryPublish(auth,frozen:frozen,m:m,live:[r.live!],hook:hook)
        return .init(client:client,ticket:ticket,witness:witness)
    }
}
