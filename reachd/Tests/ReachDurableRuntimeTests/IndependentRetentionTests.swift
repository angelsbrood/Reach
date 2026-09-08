import Foundation
import XCTest
import CryptoKit
import DurableRootKeys
import DurableSessionLifecycle
import RecoveryContract
import HostClientContract
import ReachWire
@testable import DurableClientReceipts
@testable import ReachDurableRuntime

final class IndependentRetentionFixture {
    var raw: UInt64 = 1_000_100
    let root: String, boot: String, epoch = UUID().uuidString.lowercased(), hostEpoch = UUID().uuidString.lowercased()
    let pair = String(repeating:"a",count:64), host = UUID().uuidString.lowercased(), client = UUID().uuidString.lowercased()
    let cap: UInt64, key = Data(repeating:7,count:32)
    let auth = ClientAuthorization(caller:.init(principal:"ca-pin",device:"leaf-pin",app:IndependentContract.application))
    var clock: RoleMonotonicClock!, environment: ClientEnvironment!, binding: RecoveryBinding!, owner: DurableClientReceipts!
    init(cap: UInt64 = 1000) throws {
        self.cap=cap; boot=try RootKeyCodec.boot()
        root=try ArtifactFixtures.base()+"/retention-"+UUID().uuidString.lowercased()
        try LocalFiles.createDirectory(root);try LocalFiles.createDirectory(root+"/bootstrap")
        clock=try RoleMonotonicClock(origin:1_000_000,epoch:epoch,boot:boot,rawNow:{ [unowned self] in self.raw })
        environment=try .init(rootID:client,clock:clock,authorityMode:.independent,pairDigest:pair,retentionCap:cap)
        binding = .init(bootstrap:UUID().uuidString.lowercased(),core:String(repeating:"b",count:64),clientRoot:client,host:host,localBoot:boot,localPolicy:clock.policy,pair:pair)
        owner=try DurableClientReceipts(path:root+"/bootstrap/client",create:true,environment:environment,metadataKey:key,clock:clock)
    }
    deinit { owner?.close();try? FileManager.default.removeItem(atPath:root) }
    func ticket(issued: UInt64 = 9_000_000_000_000, duration: UInt64 = 1000, hostBoot: String? = nil) throws -> (ClientContext,Data) {
        let namespace=UUID().uuidString.lowercased()
        let c=ClientContext(caller:auth.caller,host:host,store:host,namespace:namespace,generation:"original",request:"request",operation:"operation",upstreamDigest:String(repeating:"c",count:64),route:"ordinary",revision:"s84-host-client-v1",issued:issued,expires:issued+duration)
        struct Claims: Encodable { let version=1; let incarnation:String, boot:String, policy:String, namespace:String; let caller:ClientCaller; let issued:UInt64, expires:UInt64 }
        let claims=try crEncode(Claims(incarnation:host,boot:hostBoot ?? UUID().uuidString.lowercased(),policy:"role-monotonic-ns-v1:"+hostEpoch,namespace:namespace,caller:auth.caller,issued:issued,expires:issued+duration))
        return (c,crUInt(UInt64(claims.count))+claims+Data(repeating:9,count:32))
    }
    func accept(_ c: ClientContext,_ ticket:Data) throws -> (ClientAuthority,ClientHandle) {
        let a=try owner.originalAuthority(c,ticket:ticket,anchor:owner.originalAnchor())
        let h=try owner.open(a,authorization:auth)
        try owner.enrollRecovery(in:root,binding:binding)
        try owner.registerRecoveryTicket(ticket,selection:select(),in:root,binding:binding,authorization:auth)
        return (a,h)
    }
    func select() throws -> RecoverySummary { try XCTUnwrap(owner.discover(binding:binding,authorization:auth).first) }
    func reopen() throws { owner.close();owner=try DurableClientReceipts(path:root+"/bootstrap/client",create:false,environment:environment,metadataKey:key,clock:clock) }
}

final class IndependentRetentionTests: XCTestCase {
    func testUnequalDomainsOriginalDeadlineSurvivesDuplicateAndFreshOwner() throws {
        let f=try IndependentRetentionFixture(),(context,ticket)=try f.ticket()
        let (a,h)=try f.accept(context,ticket)
        XCTAssertEqual(a.localIssued,101);XCTAssertEqual(a.localExpires,1101)
        XCTAssertNotEqual(a.retention?.hostBoot,a.retention?.boot)
        XCTAssertEqual(a.bytes,try ClientAuthority(context).bytes)
        f.raw+=10
        XCTAssertEqual(try f.owner.open(a,authorization:f.auth).record,h.record)
        let renewed=try f.owner.originalAuthority(context,ticket:ticket,anchor:f.owner.originalAnchor())
        XCTAssertThrowsError(try f.owner.open(renewed,authorization:f.auth))
        try f.reopen()
        let join=try f.owner.recoverHostJoin(f.select(),in:f.root,binding:f.binding,authorization:f.auth)
        XCTAssertEqual(join.ticket,ticket);XCTAssertEqual(join.client.authority.bytes,a.bytes)
        XCTAssertEqual(join.client.authority.retention,a.retention)
        XCTAssertEqual(join.client.authority.localExpires,1101)
        try f.owner.registerRecoveryTicket(ticket,selection:f.select(),in:f.root,binding:f.binding,authorization:f.auth)
    }
    func testMissingAnchorDelayedReplyAndArithmeticRefuse() throws {
        let f=try IndependentRetentionFixture(),(c,t)=try f.ticket()
        XCTAssertThrowsError(try f.owner.originalAuthority(c,ticket:t,anchor:nil))
        let anchor=try f.owner.originalAnchor();f.raw+=1000
        XCTAssertThrowsError(try f.owner.originalAuthority(c,ticket:t,anchor:anchor))
        XCTAssertThrowsError(try ClientLocalRetention(anchor:UInt64.max-10,cap:1000,boot:f.boot,policy:f.clock.policy,pair:f.pair,context:c,ticket:t))
        let (tooLong,invalid)=try f.ticket(duration:ClientLimits.session+1)
        XCTAssertThrowsError(try f.owner.originalAuthority(tooLong,ticket:invalid,anchor:f.owner.originalAnchor()))
        XCTAssertTrue(try f.owner.discover(binding:f.binding,authorization:f.auth).isEmpty)
    }
    func testExpiryStopsSnapshotPublicationEffectsAndPrunesLocalIdentityAndTicket() throws {
        let f=try IndependentRetentionFixture(cap:100),(c,t)=try f.ticket()
        let (a,h)=try f.accept(c,t),selected=try f.select()
        f.raw+=100
        XCTAssertLessThan(f.raw,c.expires) // Host clock values are deliberately unrelated.
        XCTAssertThrowsError(try f.owner.inbox(h,authority:a,authorization:f.auth))
        XCTAssertThrowsError(try f.owner.hostWitness(h,authority:a,authorization:f.auth))
        XCTAssertThrowsError(try f.owner.resolve(selected,binding:f.binding,authorization:f.auth))
        XCTAssertThrowsError(try f.owner.effect(.init(id:Data("x".utf8),name:Data("x".utf8),arguments:Data()),handle:h,authority:a,authorization:f.auth))
        var snapshotReads=0
        XCTAssertTrue(try f.owner.discover(binding:f.binding,authorization:f.auth,hook:{ if $0 == .beforeSnapshot { snapshotReads+=1 } }).isEmpty)
        XCTAssertEqual(snapshotReads,0)
        try f.owner.maintainRecovery(in:f.root,binding:f.binding)
        XCTAssertTrue(try f.owner.readManifest().records.isEmpty)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:f.root+"/tickets-"+f.binding.bootstrap),["lock"])
    }
    func testExpiryAtSnapshotAndPublicationBoundariesRefuses() throws {
        for point in [RecoveryFault.beforeSnapshot,.afterSnapshot,.afterEnvelope,.beforePublication] {
            let f=try IndependentRetentionFixture(cap:100),(c,t)=try f.ticket();_=try f.accept(c,t)
            XCTAssertThrowsError(try f.owner.recoverHostJoin(f.select(),in:f.root,binding:f.binding,authorization:f.auth,hook:{ if $0==point { f.raw=1_000_200 } }))
        }
    }
    func testRetentionDigestFromAuthenticatedManifestBindsEnvelope() throws {
        let f=try IndependentRetentionFixture(),(c,t)=try f.ticket();let (a,_)=try f.accept(c,t)
        let selected=try f.select(),m=try f.owner.readManifest(),record=try XCTUnwrap(m.records.first)
        let path=f.root+"/tickets-"+f.binding.bootstrap+"/"+RecoveryFileSystem.role(selected.record)
        let bytes=try Data(contentsOf:URL(fileURLWithPath:path))
        var live=record.live!
        live.retention=try ClientLocalRetention(anchor:a.localIssued+1,cap:f.cap,boot:f.boot,policy:f.clock.policy,pair:f.pair,context:c,ticket:t)
        XCTAssertThrowsError(try RecoveryEncryption.open(bytes,live:live,record:record.id,binding:f.binding,root:f.owner.rootKey))
        live.retention=nil
        XCTAssertThrowsError(try RecoveryEncryption.open(bytes,live:live,record:record.id,binding:f.binding,root:f.owner.rootKey))
        var altered=t;altered[altered.count-1]^=1
        XCTAssertThrowsError(try f.owner.registerRecoveryTicket(altered,selection:selected,in:f.root,binding:f.binding,authorization:f.auth))
    }
    func testMissingOrCorruptModeRetentionRefusesBeforeSnapshot() throws {
        for corruption in ["missing","pair","hostPolicy","mode"] {
            let f=try IndependentRetentionFixture(),(c,t)=try f.ticket();_=try f.accept(c,t)
            var m=try f.owner.readManifest()
            var object=try XCTUnwrap(JSONSerialization.jsonObject(with:crEncode(m)) as? [String:Any])
            if corruption=="mode" { object["version"]=1 }
            else {
                var records=object["records"] as! [[String:Any]],live=records[0]["live"] as! [String:Any]
                if corruption=="missing" { live.removeValue(forKey:"retention") }
                else { var retention=live["retention"] as! [String:Any];retention[corruption]="bad";live["retention"]=retention }
                records[0]["live"]=live;object["records"]=records
            }
            let plain=try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes])
            m=try JSONDecoder().decode(ClientManifest.self,from:plain)
            XCTAssertThrowsError(try m.validate(f.environment))
            let cipher=try ClientCrypto.seal(plain,role:"manifest",record:f.client,generation:ClientCrypto.zero,revision:m.revision,environment:f.environment,key:f.owner.rootKey,rootKey:f.owner.rootKey)
            try cipher.write(to:URL(fileURLWithPath:f.root+"/bootstrap/client/current"))
            XCTAssertThrowsError(try f.reopen())
        }
    }
    func testLegacyModeAndClockRollbackCannotReopenIndependentState() throws {
        let f=try IndependentRetentionFixture(),(c,t)=try f.ticket();_=try f.accept(c,t)
        f.raw-=1
        XCTAssertThrowsError(try f.owner.discover(binding:f.binding,authorization:f.auth))
        f.raw+=1; f.owner.close()
        let legacyClock=SystemClientClock(),e=try ClientEnvironment(rootID:f.client,clock:legacyClock)
        XCTAssertThrowsError(try DurableClientReceipts(path:f.root+"/bootstrap/client",create:false,environment:e,metadataKey:f.key,clock:legacyClock))
    }
    func testHostExpiryRemainsAuthoritativeWithLiveLocalWindow() throws {
        let f=try IndependentRetentionFixture(),hostRoot=f.root+"/host-test"
        var raw:UInt64=9_000_000_000_000
        let clock=try RoleMonotonicClock(origin:1,epoch:f.hostEpoch,boot:f.boot,rawNow:{raw})
        let host=try DurableSessionLifecycle.initialize(at:hostRoot,identity:.init(incarnation:f.host,clock:clock),keys:.init(catalog:Data(repeating:1,count:32),ticket:Data(repeating:2,count:32)),clock:clock)
        defer { host.close() }
        let auth=LifecycleAuthorization(caller:.init(principal:f.auth.caller.principal,device:f.auth.caller.device,app:f.auth.caller.app),allowed:true)
        let ticket=try host.issueTicket(authorization:auth,lifetime:1000),claims=try RecoveryTicketClaims.parse(ticket.data)
        let c=ClientContext(caller:f.auth.caller,host:f.host,store:f.host,namespace:claims.namespace,generation:"original",request:"request",operation:"operation",upstreamDigest:String(repeating:"c",count:64),route:"ordinary",revision:"s84-host-client-v1",issued:claims.issued,expires:claims.expires)
        let (a,h)=try f.accept(c,ticket.data)
        raw+=1000
        XCTAssertThrowsError(try host.wireSessionID(ticket:ticket,authorization:auth))
        XCTAssertEqual(try f.owner.hostWitness(h,authority:a,authorization:f.auth).high,0)
    }
    func testLocalExpiryWhileActualHostTicketRemainsLive() throws {
        let f=try IndependentRetentionFixture(cap:10),hostRoot=f.root+"/host-test"
        let clock=try RoleMonotonicClock(origin:1,epoch:f.hostEpoch,boot:f.boot,rawNow:{9_000_000_000_000})
        let host=try DurableSessionLifecycle.initialize(at:hostRoot,identity:.init(incarnation:f.host,clock:clock),keys:.init(catalog:Data(repeating:1,count:32),ticket:Data(repeating:2,count:32)),clock:clock)
        defer { host.close() }
        let auth=LifecycleAuthorization(caller:.init(principal:f.auth.caller.principal,device:f.auth.caller.device,app:f.auth.caller.app),allowed:true)
        let ticket=try host.issueTicket(authorization:auth,lifetime:1000),claims=try RecoveryTicketClaims.parse(ticket.data)
        let c=ClientContext(caller:f.auth.caller,host:f.host,store:f.host,namespace:claims.namespace,generation:"original",request:"request",operation:"operation",upstreamDigest:String(repeating:"c",count:64),route:"ordinary",revision:"s84-host-client-v1",issued:claims.issued,expires:claims.expires)
        let (a,h)=try f.accept(c,ticket.data);f.raw+=10
        XCTAssertEqual(try host.wireSessionID(ticket:ticket,authorization:auth),claims.namespace)
        XCTAssertThrowsError(try f.owner.hostWitness(h,authority:a,authorization:f.auth))
    }
    func testRoleClockRejectsFutureOriginMalformedEpochBackwardAndOwnBootChange() throws {
        let boot=try RootKeyCodec.boot(),epoch=UUID().uuidString.lowercased()
        XCTAssertThrowsError(try RoleMonotonicClock(origin:100,epoch:epoch,boot:boot,rawNow:{99}))
        XCTAssertThrowsError(try RoleMonotonicClock(origin:1,epoch:"bad",boot:boot))
        var raw:UInt64=100, observedBoot=boot
        let clock=try RoleMonotonicClock(origin:10,epoch:epoch,boot:boot,rawNow:{raw},currentBoot:{observedBoot})
        XCTAssertEqual(try clock.now(),91);raw=99;XCTAssertThrowsError(try clock.now())
        raw=100;observedBoot=UUID().uuidString.lowercased();XCTAssertThrowsError(try clock.now())
    }
    func testEffectiveWindowGatesActualToolKnowledgeAndDirectSnapshotReads() throws {
        let f=try IndependentRetentionFixture(cap:100),(c,t)=try f.ticket();let (a,h)=try f.accept(c,t)
        let event=WireEvent.toolCallAppendArguments(entryID:nil,id:"call",name:"tool",content:"{}",tokenCount:1)
        let batch=HandoffBatch(first:1,count:1,commit:String(repeating:"d",count:64),bytes:try crEncode([event]))
        _=try f.owner.acceptHostBatch(batch,requestedCursor:0,handle:h,authority:a,authorization:f.auth)
        let call=try ToolBinding(id:Data("call".utf8),name:Data("tool".utf8),arguments:Data("{}".utf8))
        XCTAssertEqual(try f.owner.effect(call,handle:h,authority:a,authorization:f.auth),.unbegun)
        let record=try XCTUnwrap(f.owner.readManifest().records.first)
        f.raw+=100
        XCTAssertThrowsError(try f.owner.snapshot(record)) { XCTAssertEqual($0 as? ClientError,.expired) }
        XCTAssertThrowsError(try f.owner.effect(call,handle:h,authority:a,authorization:f.auth)) { XCTAssertEqual($0 as? ClientError,.expired) }
        XCTAssertThrowsError(try f.owner.beginEffect(call,handle:h,authority:a,authorization:f.auth)) { XCTAssertEqual($0 as? ClientError,.expired) }
    }
    func testLegacyLiveRecordRoundTripsWithoutRetentionField() throws {
        let id="00000000-0000-0000-0000-000000000001",digest=String(repeating:"a",count:64)
        let object:[String:Any]=["identity":digest,"namespace":digest,"anchor":digest,"contextDigest":digest,"issued":10,"expires":20,"key":Data(repeating:7,count:32).base64EncodedString(),"snapshot":["name":"s-"+id+".bin","digest":digest,"revision":1,"length":148],"calls":0,"futureBytes":8192]
        let old=try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes])
        let decoded=try JSONDecoder().decode(LiveClientRecord.self,from:old)
        XCTAssertNil(decoded.retention);XCTAssertEqual(try crEncode(decoded),old)
        XCTAssertEqual(decoded.localIssued,10);XCTAssertEqual(decoded.localExpires,20)
    }
    func testLegacyEncodedAuthorityManifestAndAADRemainExact() throws {
        let f=try IndependentRetentionFixture(),(c,_)=try f.ticket()
        let bytes=try crEncode(c),a=try ClientAuthority(c)
        XCTAssertEqual(bytes,a.bytes);XCTAssertNil(a.retention)
        let m=ClientManifest(root:f.client,boot:f.boot,policy:"system-monotonic-raw-ns-v1",revision:1,ownerEpoch:1,observed:100)
        let expected: [String:Any] = ["version":1,"root":f.client,"boot":f.boot,"policy":"system-monotonic-raw-ns-v1","revision":1,"ownerEpoch":1,"observed":100,"records":[]]
        XCTAssertEqual(try crEncode(m),try JSONSerialization.data(withJSONObject:expected,options:[.sortedKeys,.withoutEscapingSlashes]))
        let aad=ClientCrypto.AAD(version:1,mode:nil,pair:nil,root:f.client,boot:f.boot,policy:"system-monotonic-raw-ns-v1",role:"manifest",record:f.client,generation:ClientCrypto.zero,revision:1)
        let expectedAAD:[String:Any]=["version":1,"root":f.client,"boot":f.boot,"policy":"system-monotonic-raw-ns-v1","role":"manifest","record":f.client,"generation":ClientCrypto.zero,"revision":1]
        XCTAssertEqual(try crEncode(aad),try JSONSerialization.data(withJSONObject:expectedAAD,options:[.sortedKeys,.withoutEscapingSlashes]))
        let binding=RecoveryBinding(bootstrap:f.binding.bootstrap,core:f.binding.core,clientRoot:f.client,host:f.host,boot:f.boot,hostPolicy:"legacy",clientPolicy:"legacy")
        let encoded=String(decoding:try RecoveryCodec.encode(binding),as:UTF8.self)
        XCTAssertFalse(encoded.contains("mode"));XCTAssertFalse(encoded.contains("pair"))
    }
}

final class IndependentReportPublicationTests: XCTestCase {
    private func cachedReport(_ f: IndependentRetentionFixture) throws -> TransportClientReport {
        let (context, ticket) = try f.ticket(), (authority, handle) = try f.accept(context, ticket)
        for sequence in 1...4 {
            let event = WireEvent.responseAppend(entryID: "answer", text: "retained-\(sequence)", segmentID: "text", tokenCount: 1)
            let batch = HandoffBatch(first: UInt64(sequence), count: 1, commit: String(repeating: String(sequence), count: 64), bytes: try crEncode([event]))
            _ = try f.owner.acceptHostBatch(batch, requestedCursor: UInt64(sequence - 1), handle: handle, authority: authority, authorization: f.auth)
        }
        // Populate the prefix from an actual authenticated recovered journal,
        // as runtime.recover does before retaining the report cache.
        let join = try f.owner.recoverHostJoin(f.select(), in: f.root, binding: f.binding, authorization: f.auth)
        let inbox = try f.owner.hostInbox(join.client.handle, authority: join.client.authority, authorization: f.auth)
        let accepted = DurableGenerationAcceptedPayload(requestID: "recover", reference: .init(session: .init(modelID: TransportContract.model, profile: DurableWire.independentProfile, sessionID: context.namespace), generationID: context.generation, operationID: context.operation), kind: .recover, context: authority.bytes, contextDigest: crHash(authority.bytes))
        return .init(retention: authority.retention, stage: "stopped", acquisition: TransportRoleAudit(.client).snapshot, peerDigests: [], connections: 2, reconnects: 1, registered: true, high: 4, terminal: false, inbox: inbox, beforeRecovery: [inbox], accepted: accepted)
    }
    private func publish(_ f: IndependentRetentionFixture, to path: String, independent: Bool = true,
                         assemble: () throws -> TransportClientReport) throws {
        try TransportClientReportPublication.write(assemble, to: path, independent: independent, owner: f.owner,
            root: f.root, binding: f.binding, authorization: f.auth, clock: f.clock)
    }
    func testExpiredRecoveryReportDoesNotRepublishCachedContent() throws {
        let f = try IndependentRetentionFixture(cap: 100), cached = try cachedReport(f)
        XCTAssertEqual(cached.beforeRecovery.first?.count, 4)
        XCTAssertEqual(cached.inbox.count, 4); XCTAssertFalse(try XCTUnwrap(cached.accepted).context.isEmpty)
        let previous = f.root + "/previous.json", expired = f.root + "/expired.json"
        try publish(f, to: previous) { cached }
        let previousBytes = try Data(contentsOf: URL(fileURLWithPath: previous))
        XCTAssertEqual(previousBytes, try TransportContract.encode(cached))
        f.raw += 100
        XCTAssertTrue(try f.owner.discover(binding: f.binding, authorization: f.auth).isEmpty)
        XCTAssertThrowsError(try publish(f, to: expired) { cached }) {
            guard case TransportRuntimeError.expired = $0 else { return XCTFail("unexpected refusal: \($0)") }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: expired))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: previous)), previousBytes)
    }
    func testExpiryDuringReportAssemblyRefusesAllCollectedContent() throws {
        let f = try IndependentRetentionFixture(cap: 100), cached = try cachedReport(f)
        let path = f.root + "/assembly-expired.json"
        var assembled = false
        XCTAssertThrowsError(try publish(f, to: path) {
            let collected = cached // Already-read inbox, recovery prefix and acceptance.
            XCTAssertEqual(collected.beforeRecovery.first?.count, 4)
            f.raw += 100; assembled = true
            return collected
        })
        XCTAssertTrue(assembled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
    func testLegacyReportPreservesExistingBytesWithoutIndependentGate() throws {
        let f = try IndependentRetentionFixture(cap: 100), cached = try cachedReport(f)
        var accepted = try XCTUnwrap(cached.accepted)
        accepted.reference.session.profile = DurableWire.profile
        let legacy = TransportClientReport(stage: cached.stage, acquisition: cached.acquisition, peerDigests: cached.peerDigests, connections: cached.connections, reconnects: cached.reconnects, registered: cached.registered, high: cached.high, terminal: cached.terminal, inbox: cached.inbox, beforeRecovery: cached.beforeRecovery, accepted: accepted)
        f.raw += 100; f.owner.close() // Legacy publication must not acquire new local authority.
        let path = f.root + "/legacy.json"
        try publish(f, to: path, independent: false) { legacy }
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), try TransportContract.encode(legacy))
    }
}
