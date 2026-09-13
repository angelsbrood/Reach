import Foundation
import CryptoKit
import RecoveryContract
import RecoveryAuthorityContract

extension DurableClientReceipts {
    public static func initializeRecoveryAuthority(at path: String, environment e: ClientEnvironment, metadataKey: Data) throws {
        guard let original=e.authority, !original.provision.native, metadataKey.count == 32 else { throw AuthorityError.scope }
        try original.validate()
        let fs=try ClientFileSystem(path:path,create:true); defer { fs.close() }
        let m=try ClientManifest(version:3,authority:original.digest,root:e.rootID,boot:e.boot,policy:e.policy,
            revision:1,ownerEpoch:1,observed:original.anchor)
        try selectAuthorityManifest(m,fs:fs,environment:e,key:SymmetricKey(data:metadataKey),check:{})
    }
    private static func selectAuthorityManifest(_ m: ClientManifest, fs: ClientFileSystem, environment e: ClientEnvironment,
        key: SymmetricKey, check: () throws -> Void) throws {
        try check(); try m.validate(e)
        guard !(try fs.exists("prepared")) else { throw AuthorityError.partial }
        let bytes=try ClientCrypto.seal(crEncode(m),role:"manifest",record:e.rootID,generation:ClientCrypto.zero,
            revision:m.revision,environment:e,key:key,rootKey:key)
        try check(); try fs.writeNew("prepared",bytes); try check()
        try fs.selectPrepared(); try fs.sync(); try check()
    }
    private static func readAuthorityManifest(_ fs: ClientFileSystem, environment e: ClientEnvironment,
        key: SymmetricKey, action: RecoveryAuthorityAction) throws -> ClientManifest {
        guard let original=e.authority else { throw AuthorityError.scope }; try original.check(action.scope,role:"client")
        try action.check(scope:action.scope,operation:action.operation)
        let cipher=try fs.read("current"); try action.check(scope:action.scope,operation:action.operation)
        let (bytes,frame)=try ClientCrypto.open(cipher,role:"manifest",environment:e,key:key,rootKey:key)
        let m=try JSONDecoder().decode(ClientManifest.self,from:bytes); try m.validate(e)
        guard try crEncode(m) == bytes, m.version == 3, m.ownerEpoch == 1, m.observed == (try original.anchor),
              m.revision == frame.revision, frame.record == e.rootID, !(try fs.exists("prepared")), m.records.count <= 1 else { throw AuthorityError.state }
        try action.check(scope:action.scope,operation:action.operation); return m
    }
    /// Explicit trusted original local acceptance. The issuer pin and successful
    /// host export digest come separately from the controller's live host result.
    /// A selected manifest with a missing envelope refuses; it never reenrolls.
    public static func acceptRecoveryAuthority(at path: String, parent: String, environment e: ClientEnvironment,
        metadataKey: Data, acceptance: AuthorityAcceptance, action: RecoveryAuthorityAction,
        fault: RecoveryHook = { _ in }) throws {
        let a=try acceptance.admission(), scope=a.scope
        try action.check(scope:scope,operation:.acceptClient)
        guard let original=e.authority, !original.provision.native, metadataKey.count == 32, scope.client.boot == (try ClientEnvironment.bootIdentity()) else { throw AuthorityError.scope }
        try original.check(scope,role:"client")
        let fs=try ClientFileSystem(path:path,create:false); defer { fs.close() }; try action.check(scope:scope,operation:.acceptClient)
        let key=SymmetricKey(data:metadataKey), old=try readAuthorityManifest(fs,environment:e,key:key,action:action)
        if !old.records.isEmpty {
            let existing=try readClientAuthority(old,fs:fs,parent:parent,environment:e,key:key,action:action)
            guard existing == a, old.records[0].live?.retention?.acceptance == acceptance else { throw AuthorityError.partial }
            try action.publication(a); return
        }
        guard old.revision == 1, Set(try fs.names()) == Set(["current","lock"]) else { throw AuthorityError.partial }
        let context=try AuthorityCodec.decode(ClientContext.self,a.context)
        let retention=try ClientLocalRetention(acceptance:acceptance), authority=try ClientAuthority(context,retention:retention)
        try e.check(retention)
        let id=UUID().uuidString.lowercased(), snapID=UUID().uuidString.lowercased(), contentKey=clientRandomKey()
        let snapshot=try ClientSnapshot(version:2,authority:scope.digest,context:a.context)
        let cipher=try ClientCrypto.seal(crEncode(snapshot),role:"snapshot",record:snapID,generation:id,revision:2,
            environment:e,key:SymmetricKey(data:contentKey),rootKey:key)
        let ref=SnapshotReference(name:"s-"+snapID+".bin",digest:crHash(cipher),revision:2,length:cipher.count)
        let live=try LiveClientRecord(identity:authority.identity,namespace:authority.namespace,anchor:authority.anchor,
            contextDigest:crHash(a.context),issued:context.issued,expires:context.expires,key:contentKey,snapshot:ref,
            calls:0,futureBytes:snapshot.maximumFutureBytes(),retention:retention)
        var m=old; m.revision=2; m.records=[ClientRecord(id:id,live:live,cleanup:nil)]
        try m.validate(e); try snapshot.validate(live)
        func check() throws { try action.check(scope:scope,operation:.acceptClient) }
        try check(); try fs.writeNew(ref.name,cipher); try fault(.afterSnapshot); try check()
        try selectAuthorityManifest(m,fs:fs,environment:e,key:key,check:check)
        try fault(.afterManifest); try check()
        let binding=try RecoveryBinding(recoveryAuthority:scope)
        let dir=try RecoveryFileSystem(parent:parent,binding:binding,fresh:true); defer { dir.close() }; try check()
        let envelope=try RecoveryEncryption.seal(a.ticket,live:live,record:id,binding:binding,root:key)
        try dir.write(envelope,hook:{ point in try fault(point); try check() }); try check()
        try dir.select(RecoveryFileSystem.role(id)); try dir.sync(); try check()
        try fault(.afterEnvelope); try check()
        // This same original admission is bound locally through final publication.
        try action.bindAuthenticated(a); try action.publication(a)
    }
    private static func readClientAuthority(_ m: ClientManifest, fs: ClientFileSystem, parent: String,
        environment e: ClientEnvironment, key: SymmetricKey, action: RecoveryAuthorityAction) throws -> AuthorityAdmission {
        guard [.acceptClient,.authenticateClient].contains(action.operation), m.revision == 2, m.records.count == 1,
              let live=m.records[0].live, m.records[0].cleanup == nil, live.calls == 0,
              live.snapshot.revision == 2, let retention=live.retention, let acceptance=retention.acceptance else { throw AuthorityError.state }
        let a=try acceptance.admission(), scope=a.scope
        func check() throws { try action.check(scope:scope,operation:action.operation) }
        try check(); try e.check(retention)
        guard Set(try fs.names()) == Set(["current","lock",live.snapshot.name]) else { throw AuthorityError.partial }
        let cipher=try fs.read(live.snapshot.name); try check()
        guard cipher.count == live.snapshot.length, crHash(cipher) == live.snapshot.digest else { throw AuthorityError.invalid }
        let (bytes,frame)=try ClientCrypto.open(cipher,role:"snapshot",environment:e,key:SymmetricKey(data:live.key),rootKey:key)
        let snapshot=try JSONDecoder().decode(ClientSnapshot.self,from:bytes)
        guard try crEncode(snapshot) == bytes, frame.generation == m.records[0].id, frame.revision == 2,
              live.snapshot.name == "s-"+frame.record+".bin", snapshot.context == a.context,
              snapshot.high == 0, !snapshot.terminal, snapshot.receiptRevision == 0,
              snapshot.batches.isEmpty, snapshot.calls.isEmpty else { throw AuthorityError.state }
        try snapshot.validate(live); try check()
        let binding=try RecoveryBinding(recoveryAuthority:scope)
        let dir=try RecoveryFileSystem(parent:parent,binding:binding,fresh:false); defer { dir.close() }; try check()
        let role=RecoveryFileSystem.role(m.records[0].id)
        guard Set(try dir.names()) == Set(["lock",role]) else { throw AuthorityError.partial }
        let envelope=try dir.read(role); try check()
        let ticket=try RecoveryEncryption.open(envelope,live:live,record:m.records[0].id,binding:binding,root:key)
        let claims=try RecoveryTicketClaims.parse(ticket), context=try AuthorityCodec.decode(ClientContext.self,a.context)
        let host=try scope.provision.originals.records().host
        guard ticket == a.ticket, claims.version == 2, claims.authority == (try scope.digest), claims.boot == scope.host.boot,
              claims.policy == scope.provision.hostPolicy, claims.incarnation == scope.host.localID,
              claims.namespace == scope.namespace, claims.issued == host.anchor, claims.expires == host.deadline,
              context.authority == (try scope.digest), context.generation == scope.generation,
              try crEncode(claims.caller) == crEncode(context.caller), context.issued == host.anchor, context.expires == host.deadline else { throw AuthorityError.invalid }
        try check(); try action.bindAuthenticated(a); return a
    }
    public static func authenticateRecoveryAuthority(at path: String, parent: String, environment e: ClientEnvironment,
        metadataKey: Data, scope: AuthorityScope, action: RecoveryAuthorityAction,
        blocking: () throws -> Void = {}) throws -> AuthorityDiagnostic {
        try action.check(scope:scope,operation:.authenticateClient)
        guard metadataKey.count == 32 else { throw AuthorityError.invalid }
        let fs=try ClientFileSystem(path:path,create:false); defer { fs.close() }
        try action.check(scope:scope,operation:.authenticateClient)
        let key=SymmetricKey(data:metadataKey), m=try readAuthorityManifest(fs,environment:e,key:key,action:action)
        let a=try readClientAuthority(m,fs:fs,parent:parent,environment:e,key:key,action:action)
        try blocking()
        return try AuthorityDiagnostic(admission:a,phase:"registered-empty",action:action)
    }
}
