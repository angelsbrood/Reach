import Foundation
import CryptoKit
import RecoveryContract
import RecoveryAuthorityContract

extension DurableClientReceipts {
    public static func initializeNativeRecovery(at path: String, environment e: ClientEnvironment, metadataKey: Data) throws {
        guard let original=e.authority, original.provision.native, metadataKey.count == 32 else { throw AuthorityError.scope }
        try original.validate()
        let fs=try ClientFileSystem(path:path,create:true); defer { fs.close() }
        let m=try ClientManifest(version:4,authority:original.digest,root:e.rootID,boot:e.boot,policy:e.policy,
            revision:1,ownerEpoch:1,observed:original.anchor)
        try selectNativeManifest(m,fs:fs,environment:e,key:SymmetricKey(data:metadataKey),check:{})
    }
    static func selectNativeManifest(_ m: ClientManifest, fs: ClientFileSystem, environment e: ClientEnvironment,
        key: SymmetricKey, check: () throws -> Void) throws {
        try check(); try m.validate(e)
        guard !(try fs.exists("prepared")) else { throw AuthorityError.partial }
        let bytes=try ClientCrypto.seal(crEncode(m),role:"manifest",record:e.rootID,generation:ClientCrypto.zero,
            revision:m.revision,environment:e,key:key,rootKey:key)
        try check(); try fs.writeNew("prepared",bytes); try check()
        try fs.selectPrepared(); try fs.sync(); try check()
    }
    static func readNativeManifest(_ fs: ClientFileSystem, environment e: ClientEnvironment,
        key: SymmetricKey, action: GenerationAuthorityAction) throws -> ClientManifest {
        guard let original=e.authority else { throw AuthorityError.scope }; try original.check(action.scope,role:"client")
        try action.check(scope:action.scope,operation:action.operation)
        let cipher=try fs.read("current"); try action.check(scope:action.scope,operation:action.operation)
        let (bytes,frame)=try ClientCrypto.open(cipher,role:"manifest",environment:e,key:key,rootKey:key)
        let m=try JSONDecoder().decode(ClientManifest.self,from:bytes); try m.validate(e)
        guard try crEncode(m) == bytes, m.version == 4, m.ownerEpoch > 0, m.observed == (try original.anchor),
              m.revision == frame.revision, frame.record == e.rootID, m.records.count <= 1 else { throw AuthorityError.state }
        try action.check(scope:action.scope,operation:action.operation); return m
    }
    /// Explicit trusted original local acceptance. The issuer pin and successful
    /// host export digest come separately from the controller's live host result.
    /// A selected manifest with a missing envelope refuses; it never reenrolls.
    public static func acceptNativeRecovery(at path: String, parent: String, environment e: ClientEnvironment,
        metadataKey: Data, acceptance: AuthorityAcceptance, action: GenerationAuthorityAction,
        fault: RecoveryHook = { _ in }) throws {
        let a=try acceptance.admission(), scope=a.scope
        try action.check(scope:scope,operation:.acceptClient)
        guard let original=e.authority, original.provision.native, metadataKey.count == 32, scope.client.boot == (try ClientEnvironment.bootIdentity()) else { throw AuthorityError.scope }
        try original.check(scope,role:"client")
        let fs=try ClientFileSystem(path:path,create:false); defer { fs.close() }; try action.check(scope:scope,operation:.acceptClient)
        let key=SymmetricKey(data:metadataKey), old=try readNativeManifest(fs,environment:e,key:key,action:action)
        if !old.records.isEmpty {
            let existing=try readNativeClient(old,fs:fs,parent:parent,environment:e,key:key,action:action)
            guard existing == a, old.records[0].live?.retention?.acceptance == acceptance else { throw AuthorityError.partial }
            try action.publication(a); return
        }
        guard old.revision == 1, Set(try fs.names()) == Set(["current","lock"]) else { throw AuthorityError.partial }
        let context=try AuthorityCodec.decode(ClientContext.self,a.context)
        let retention=try ClientLocalRetention(acceptance:acceptance), authority=try ClientAuthority(context,retention:retention)
        try e.check(retention)
        let id=UUID().uuidString.lowercased(), snapID=UUID().uuidString.lowercased(), contentKey=clientRandomKey()
        let snapshot=try ClientSnapshot(version:3,authority:scope.digest,context:a.context)
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
        try selectNativeManifest(m,fs:fs,environment:e,key:key,check:check)
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
    static func readNativeClient(_ m: ClientManifest, fs: ClientFileSystem, parent: String,
        environment e: ClientEnvironment, key: SymmetricKey, action: GenerationAuthorityAction) throws -> AuthorityAdmission {
        guard action.scope.provision.native, m.revision >= 2, m.records.count == 1,
              let live=m.records[0].live, m.records[0].cleanup == nil, (0...1).contains(live.calls),
              live.snapshot.revision >= 2, let retention=live.retention, let acceptance=retention.acceptance else { throw AuthorityError.state }
        let a=try acceptance.admission(), scope=a.scope
        func check() throws { try action.check(scope:scope,operation:action.operation) }
        try check(); try e.check(retention)
        _=try fs.names()
        let cipher=try fs.read(live.snapshot.name); try check()
        guard cipher.count == live.snapshot.length, crHash(cipher) == live.snapshot.digest else { throw AuthorityError.invalid }
        let (bytes,frame)=try ClientCrypto.open(cipher,role:"snapshot",environment:e,key:SymmetricKey(data:live.key),rootKey:key)
        let snapshot=try JSONDecoder().decode(ClientSnapshot.self,from:bytes)
        guard try crEncode(snapshot) == bytes, frame.generation == m.records[0].id, frame.revision == live.snapshot.revision,
              live.snapshot.name == "s-"+frame.record+".bin", snapshot.context == a.context else { throw AuthorityError.state }
        try snapshot.validate(live); try check()
        let binding=try RecoveryBinding(recoveryAuthority:scope)
        let dir=try RecoveryFileSystem(parent:parent,binding:binding,fresh:false); defer { dir.close() }; try check()
        let role=RecoveryFileSystem.role(m.records[0].id)
        guard Set(try dir.names()) == Set(["lock",role]) else { throw AuthorityError.partial }
        let envelope=try dir.read(role); try check()
        let ticket=try RecoveryEncryption.open(envelope,live:live,record:m.records[0].id,binding:binding,root:key)
        let claims=try RecoveryTicketClaims.parse(ticket), context=try AuthorityCodec.decode(ClientContext.self,a.context)
        let host=try scope.provision.originals.records().host
        guard ticket == a.ticket, claims.version == 3, claims.authority == (try scope.digest), claims.boot == scope.host.boot,
              claims.policy == scope.provision.hostPolicy, claims.incarnation == scope.host.localID,
              claims.namespace == scope.namespace, claims.issued == host.anchor, claims.expires == host.deadline,
              context.authority == (try scope.digest), context.generation == scope.generation,
              try crEncode(claims.caller) == crEncode(context.caller), context.issued == host.anchor, context.expires == host.deadline else { throw AuthorityError.invalid }
        try check(); try action.bindAuthenticated(a); return a
    }
}

/// Original acceptance plus one closed native inbox. No ClientClock, effect
/// methods, imported replacement ticket or retention renewal enters this owner.
public final class NativeClientOwner {
    public let admission: AuthorityAdmission
    private let fs: ClientFileSystem, environment: ClientEnvironment, key: SymmetricKey, parent: String
    public let ownerEpoch: UInt64
    private let authorityBinding: GenerationAuthorityBinding
    public var fault: ClientFaultHook = {_ in}
    public private(set) var uncertain=false
    public init(path: String, parent: String, environment: ClientEnvironment, metadataKey: Data,
        scope: AuthorityScope, action: GenerationAuthorityAction) throws {
        try action.check(scope:scope,operation:.reopen)
        authorityBinding=try action.bindResource()
        guard environment.authorityMode == .nativeRecovery, metadataKey.count == 32 else { throw AuthorityError.scope }
        let files=try ClientFileSystem(path:path,create:false), root=SymmetricKey(data:metadataKey)
        do {
            var m=try DurableClientReceipts.readNativeManifest(files,environment:environment,key:root,action:action)
            let a=try DurableClientReceipts.readNativeClient(m,fs:files,parent:parent,environment:environment,key:root,action:action)
            guard a.scope == scope else { throw AuthorityError.scope }
            fs=files; self.environment=environment; key=root; self.parent=parent; admission=a
            ownerEpoch=try crAdd(m.ownerEpoch,1); try cleanup(m,action:action)
            m.ownerEpoch=ownerEpoch; m.revision=try crAdd(m.revision,1)
            try select(m,action:action)
        } catch { files.close(); throw error }
    }
    private func check(_ action: GenerationAuthorityAction) throws {
        try authorityBinding.validate(action,permitting:[.reopen,.prepare,.advance,.delivery,.terminalReplay])
        try action.publication(admission)
    }
    private func read(action: GenerationAuthorityAction) throws -> (ClientManifest,ClientSnapshot) {
        try check(action)
        let m=try DurableClientReceipts.readNativeManifest(fs,environment:environment,key:key,action:action)
        guard m.ownerEpoch == ownerEpoch else { throw ClientError.stale }
        let a=try DurableClientReceipts.readNativeClient(m,fs:fs,parent:parent,environment:environment,key:key,action:action)
        guard a == admission, let live=m.records.first?.live else { throw AuthorityError.scope }
        let (bytes,_)=try ClientCrypto.open(fs.read(live.snapshot.name),role:"snapshot",environment:environment,key:SymmetricKey(data:live.key),rootKey:key)
        try check(action)
        let s=try JSONDecoder().decode(ClientSnapshot.self,from:bytes); try s.validate(live)
        return (m,s)
    }
    private func cleanup(_ m: ClientManifest, action: GenerationAuthorityAction) throws {
        try check(action)
        guard let live=m.records.first?.live else { throw AuthorityError.state }
        let names=try fs.names(); try check(action)
        // Never promote prepared. Authenticate ownership of every orphan before
        // deleting any, then sync the selected state under this fresh action.
        for name in names where !["current","lock",live.snapshot.name].contains(name) {
            let bytes=try fs.read(name); try check(action)
            if name == "prepared" {
                let (plain,f)=try ClientCrypto.open(bytes,role:"manifest",environment:environment,key:key,rootKey:key)
                let other=try JSONDecoder().decode(ClientManifest.self,from:plain); try other.validate(environment)
                guard try crEncode(other) == plain, f.record == environment.rootID, f.revision == other.revision,
                      other.records.count == 1, other.records[0].id == m.records[0].id,
                      other.records[0].live?.retention == live.retention,
                      other.records[0].live?.key == live.key else { throw AuthorityError.partial }
            } else {
                let f=try ClientCrypto.inspect(bytes,role:"snapshot",environment:environment,rootKey:key)
                guard name == "s-"+f.record+".bin", f.generation == m.records[0].id else { throw AuthorityError.partial }
            }
        }
        for name in names where !["current","lock",live.snapshot.name].contains(name) {
            try check(action); try fs.unlink(name); try check(action)
        }
        try fs.sync(); try check(action); uncertain=false
    }
    private func select(_ m: ClientManifest, action: GenerationAuthorityAction) throws {
        try check(action); try m.validate(environment)
        let bytes=try ClientCrypto.seal(crEncode(m),role:"manifest",record:environment.rootID,generation:ClientCrypto.zero,
            revision:m.revision,environment:environment,key:key,rootKey:key)
        guard try fs.usage().bytes <= environment.quota-ClientLimits.metadataReserve else { throw ClientError.full }
        try check(action); uncertain=true
        try fs.writeNew("prepared",bytes); try check(action)
        try fault(.beforeManifestRename); try check(action); try fs.selectPrepared()
        try fault(.afterManifestRename); try check(action)
        try fault(.beforeDirectorySync); try check(action); try fs.sync(); try check(action)
        try cleanup(m,action:action)
    }
    public func accept(_ frame: ReplayEnvelope, action: GenerationAuthorityAction) throws {
        guard [.delivery,.terminalReplay,.reopen,.advance,.prepare].contains(action.operation) else { throw AuthorityError.scope }
        var (m,s)=try read(action:action); try cleanup(m,action:action)
        if frame.skipPrefix != 0 {
            let context=try AuthorityCodec.decode(ClientContext.self,s.context)
            guard context.route != "required" else { throw AuthorityError.state }
        }
        if let known=s.batches.first(where:{$0.first == frame.firstSequence}) {
            guard known.matches(frame) else { throw AuthorityError.state }; try check(action); return
        }
        let events=try frame.validate(cursor:s.high,high:s.high)
        guard var live=m.records[0].live else { throw AuthorityError.state }
        var prefix=try s.nativePrefix(live)
        try prefix.append(.init(first:frame.firstSequence,count:frame.count,commit:frame.providerCommit,bytes:frame.eventBytes))
        m.revision=try crAdd(m.revision,1); try s.append(frame,events:events,revision:m.revision)
        live.calls=s.calls.count
        let id=UUID().uuidString.lowercased(), name="s-"+id+".bin"
        let bytes=try ClientCrypto.seal(crEncode(s),role:"snapshot",record:id,generation:m.records[0].id,revision:m.revision,
            environment:environment,key:SymmetricKey(data:live.key),rootKey:key)
        live.snapshot = .init(name:name,digest:crHash(bytes),revision:m.revision,length:bytes.count)
        live.futureBytes=try s.maximumFutureBytes(); m.records[0].live=live
        try s.validate(live); try m.validate(environment)
        guard try fs.usage().bytes+2*DurableClientReceipts.allocationBound(bytes.count)+ClientLimits.metadataReserve <= environment.quota else { throw ClientError.full }
        try check(action); uncertain=true; try fs.writeNew(name,bytes)
        try fault(.afterSnapshot); try check(action)
        try select(m,action:action); try fault(.afterInbox); try check(action)
    }
    public func witness(action: GenerationAuthorityAction) throws -> HandoffWitness {
        let (m,s)=try read(action:action); try cleanup(m,action:action)
        guard let live=m.records[0].live else { throw AuthorityError.state }
        var prefix=try s.nativePrefix(live)
        let registrations=prefix.registrations,digests=prefix.digests()
        let w=HandoffWitness(context:crHash(admission.context),clientRoot:admission.scope.client.localID,
            revision:s.receiptRevision,high:s.high,terminal:s.terminal,prefix:digests.0,registrations:registrations,calls:digests.1)
        try fault(.beforePublication); try check(action); return w
    }
    public func inbox(action: GenerationAuthorityAction) throws -> [HandoffBatch] {
        let (_,s)=try read(action:action)
        let result=s.batches.map { HandoffBatch(first:$0.first,count:$0.count,commit:$0.commit,bytes:$0.bytes) }
        try fault(.beforePublication); try check(action); return result
    }
    public func close() { fs.close() }
    deinit { close() }
}

import HostClientContract
