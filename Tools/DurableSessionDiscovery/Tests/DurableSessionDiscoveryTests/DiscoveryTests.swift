import XCTest
import Foundation
import CryptoKit
import Darwin
import RecoveryContract
import HostClientContract
@testable import DurableClientReceipts

/// Actual encrypted S83 stores with synthetic contract tickets; OS/host-MAC proof is in separate workers.
final class DiscoveryFixture {
    let parent:String, clientPath:String, binding:RecoveryBinding, clock:FixtureClientClock, metadata=clientRandomKey()
    var owner:DurableClientReceipts
    var sidecar:String { parent+"/tickets-"+binding.bootstrap }
    init(enroll:Bool=true) throws {
        guard let base=ProcessInfo.processInfo.environment["S86_FIXTURES"] else { throw RecoveryError.invalid }
        parent=base+"/unit-"+UUID().uuidString.lowercased(); clientPath=parent+"/bootstrap/client"
        for p in [parent,parent+"/bootstrap"] { guard mkdir(p,0o700)==0 else { throw RecoveryError.io("fixture",errno) } }
        clock=try .init(id:"s86-client",time:1_000_000_000)
        binding = .init(bootstrap:UUID().uuidString.lowercased(),core:String(repeating:"a",count:64),clientRoot:UUID().uuidString.lowercased(),
            host:UUID().uuidString.lowercased(),boot:try ClientEnvironment.bootIdentity(),hostPolicy:"fixture-ns-v1:s86-host",clientPolicy:clock.policy)
        owner=try .init(path:clientPath,create:true,environment:.init(rootID:binding.clientRoot,clock:clock),metadataKey:metadata,clock:clock)
        if enroll { try owner.enrollRecovery(in:parent,binding:binding) }
    }
    deinit { owner.close(); try? FileManager.default.removeItem(atPath:parent) }
    static func caller(_ name:String="alice") -> ClientCaller { .init(principal:name,device:"fixture-device",app:"fixture-app") }
    func auth(_ name:String="alice") -> ClientAuthorization { .init(caller:Self.caller(name)) }
    func create(_ generation:String="g1",caller:String="alice",expires:UInt64=10_000_000_000) throws -> (ClientAuthority,Data) {
        let a=try ClientAuthority(.init(caller:Self.caller(caller),host:binding.host,store:binding.host,namespace:UUID().uuidString.lowercased(),generation:generation,
            request:"fixture-request",operation:"fixture-operation",upstreamDigest:String(repeating:"b",count:64),route:"required",revision:HandoffContract.revision,issued:clock.time,expires:expires))
        _=try owner.open(a,authorization:auth(caller))
        let claims:[String:Any] = ["version":1,"incarnation":binding.host,"boot":binding.boot,"policy":binding.hostPolicy,"namespace":a.context.namespace,
            "caller":["principal":caller,"device":"fixture-device","app":"fixture-app"],"issued":a.context.issued,"expires":expires]
        let body=try JSONSerialization.data(withJSONObject:claims,options:[.sortedKeys,.withoutEscapingSlashes])
        var length=UInt64(body.count).bigEndian
        let ticket=withUnsafeBytes(of:&length) { Data($0) }+body+Data(HMAC<SHA256>.authenticationCode(for:body,using:SymmetricKey(data:metadata)))
        return (a,ticket)
    }
    func select(_ a:ClientAuthority,auth:ClientAuthorization?=nil) throws -> RecoverySummary {
        let auth=auth ?? .init(caller:a.context.caller)
        guard let s=try owner.discover(binding:binding,authorization:auth).first(where:{$0.contextDigest==crHash(a.bytes)}) else { throw RecoveryError.unavailable }; return s
    }
    func register(_ a:ClientAuthority,_ ticket:Data,hook:RecoveryHook={_ in}) throws {
        try owner.registerRecoveryTicket(ticket,selection:select(a),in:parent,binding:binding,authorization:.init(caller:a.context.caller),hook:hook)
    }
    func ticket(_ a:ClientAuthority,hook:RecoveryHook={_ in}) throws -> Data {
        try owner.recoverHostTicket(select(a),in:parent,binding:binding,authorization:.init(caller:a.context.caller),hook:hook)
    }
    func reopen() throws {
        owner.close(); owner=try .init(path:clientPath,create:false,environment:.init(rootID:binding.clientRoot,clock:clock),metadataKey:metadata,clock:clock)
    }
    func seed(_ a:ClientAuthority,known:Bool) throws -> ToolBinding {
        let auth=ClientAuthorization(caller:a.context.caller), h=try owner.resolve(select(a),binding:binding,authorization:auth).handle
        let data=try ClientEvents.encode([.toolCallAppendArguments(entryID:"entry",id:"call",name:"fake",content:"{}",tokenCount:1),.usage(inputTokens:1,outputTokens:1),.finished(.complete)])
        _=try owner.acceptHostBatch(.init(first:1,count:3,commit:String(repeating:"c",count:64),bytes:data),requestedCursor:0,handle:h,authority:a,authorization:auth)
        let t=try ToolBinding(id:Data("call".utf8),name:Data("fake".utf8),arguments:Data("{}".utf8))
        guard case .fresh=try owner.beginEffect(t,handle:h,authority:a,authorization:auth) else { throw RecoveryError.invalid }
        if known { _=try owner.recordOutcome(.make(kind:.success,result:Data("fixture-known".utf8),binding:t,authority:a),binding:t,handle:h,authority:a,authorization:auth) }
        return t
    }
}
final class DiscoveryTests:XCTestCase {
    func testCallerOwnedBoundedDiscoveryAndExactResolution() throws {
        let f=try DiscoveryFixture(), (a,_)=try f.create("a"), (b,_)=try f.create("b"), (other,_)=try f.create("other",caller:"bob")
        let alice=try f.owner.discover(binding:f.binding,authorization:f.auth()); XCTAssertEqual(alice.count,2)
        XCTAssertTrue(Set(alice.map(\.contextDigest))==Set([crHash(a.bytes),crHash(b.bytes)]))
        XCTAssertLessThanOrEqual(try RecoveryCodec.encode(alice,maximum:RecoveryLimits.summaries).count,RecoveryLimits.summaries)
        XCTAssertTrue(try f.owner.resolve(f.select(a),binding:f.binding,authorization:f.auth()).authority.bytes==a.bytes)
        XCTAssertEqual(try f.owner.discover(binding:f.binding,authorization:f.auth("bob")).count,1)
        XCTAssertThrowsError(try f.owner.resolve(f.select(other),binding:f.binding,authorization:f.auth()))
        XCTAssertTrue(try f.owner.discover(binding:f.binding,authorization:f.auth("absent")).isEmpty)
    }
    func testCallerRevocationAndSwitchAcrossIOAndPublication() throws {
        let f=try DiscoveryFixture(); _=try f.create()
        for point in [RecoveryFault.afterManifest,.beforeSnapshot,.afterSnapshot,.beforePublication] {
            for changeCaller in [false,true] {
                let auth=f.auth()
                XCTAssertThrowsError(try f.owner.discover(binding:f.binding,authorization:auth,hook:{ p in
                    if p==point { if changeCaller { auth.caller=DiscoveryFixture.caller("bob") } else { auth.allowed=false } }
                }))
            }
        }
        let denied=f.auth(); denied.allowed=false
        XCTAssertThrowsError(try f.owner.discover(binding:f.binding,authorization:denied))
    }
    func testExpiryBeforeDecryptionAndFinalPublication() throws {
        let f=try DiscoveryFixture(), (a,_)=try f.create(expires:2_000_000_000), selected=try f.select(a)
        f.clock.time=2_000_000_000
        let record=try XCTUnwrap(f.owner.readManifest().records.first), file=f.clientPath+"/"+record.live!.snapshot.name
        try Data("corrupt expired ciphertext".utf8).write(to:URL(fileURLWithPath:file))
        var decrypted=false
        XCTAssertTrue(try f.owner.discover(binding:f.binding,authorization:f.auth(),hook:{ if $0 == .beforeSnapshot { decrypted=true } }).isEmpty)
        XCTAssertFalse(decrypted); XCTAssertThrowsError(try f.owner.resolve(selected,binding:f.binding,authorization:f.auth()))
        let g=try DiscoveryFixture(); _=try g.create(expires:2_000_000_000)
        XCTAssertThrowsError(try g.owner.discover(binding:g.binding,authorization:g.auth(),hook:{ if $0 == .afterSnapshot { g.clock.time=2_000_000_000 } }))
    }
    func testExpiredEarlierSummaryIsRecheckedAfterLaterIO() throws {
        let f=try DiscoveryFixture(); _=try f.create("first",expires:2_000_000_000); _=try f.create("second")
        var count=0
        XCTAssertThrowsError(try f.owner.discover(binding:f.binding,authorization:f.auth(),hook:{ p in
            if p == .afterSnapshot { count+=1; if count==2 { f.clock.time=2_000_000_000 } }
        }))
        XCTAssertEqual(count,2)
    }
    func testStaleSelectionAndHandleDoNotCreateHistory() throws {
        let f=try DiscoveryFixture(), (a,_)=try f.create(), s=try f.select(a), client=try f.owner.resolve(s,binding:f.binding,authorization:f.auth())
        try f.reopen(); let before=try Data(contentsOf:URL(fileURLWithPath:f.clientPath+"/current"))
        XCTAssertThrowsError(try f.owner.resolve(s,binding:f.binding,authorization:f.auth()))
        XCTAssertThrowsError(try f.owner.receipt(client.handle,authority:a,authorization:f.auth()))
        XCTAssertTrue(try Data(contentsOf:URL(fileURLWithPath:f.clientPath+"/current"))==before)
    }
    func testBootstrapRootBootAndSnapshotSubstitutionRefuse() throws {
        let f=try DiscoveryFixture(), (a,_)=try f.create(), s=try f.select(a)
        let bad=RecoveryBinding(bootstrap:f.binding.bootstrap,core:f.binding.core,clientRoot:UUID().uuidString.lowercased(),host:f.binding.host,
            boot:f.binding.boot,hostPolicy:f.binding.hostPolicy,clientPolicy:f.binding.clientPolicy)
        XCTAssertThrowsError(try f.owner.resolve(s,binding:bad,authorization:f.auth()))
        let badBoot=RecoveryBinding(bootstrap:f.binding.bootstrap,core:f.binding.core,clientRoot:f.binding.clientRoot,host:f.binding.host,
            boot:UUID().uuidString.lowercased(),hostPolicy:f.binding.hostPolicy,clientPolicy:f.binding.clientPolicy)
        XCTAssertThrowsError(try f.owner.discover(binding:badBoot,authorization:f.auth()))
        let r=try XCTUnwrap(f.owner.readManifest().records.first); try Data("substitute".utf8).write(to:URL(fileURLWithPath:f.clientPath+"/"+r.live!.snapshot.name))
        XCTAssertThrowsError(try f.owner.resolve(s,binding:f.binding,authorization:f.auth()))
    }
}
