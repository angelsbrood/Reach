import Foundation
import XCTest
import Darwin
import ReachWire
import MLX
import DurableSessionLifecycle
import DurableClientReceipts
import DurableStoreBootstrap
import RecoveryContract
import WireAdapterContract
import WireAdapterFixtures
import DurableHostWireAdapter
import DurableClientWireAdapter

/// Real local lifecycle/journal stores with disposable in-process test keys.
/// Separate worker cells prove S85/Keychain acquisition and actual process death.
final class AdapterPair {
    let root:String,core:BootstrapCore,hostClock:FixtureLifecycleClock,clientClock:FixtureClientClock
    let hostOwner:DurableSessionLifecycle,hostAuth:LifecycleAuthorization,clientAuth:ClientAuthorization
    let metadata=Data(repeating:3,count:32),configuration=AdapterConfiguration(dialect:2,optIn:true,ready:true)
    var clientOwner:DurableClientReceipts,client:DurableClientWireAdapter
    let native=WireNativeFixture()
    var host:DurableHostWireAdapter
    var opened:DurableSessionOpened?,accepted:DurableGenerationAccepted?,beginBytes:Data?
    init() throws {
        root=try WireFixture.base()+"/unit-"+UUID().uuidString.lowercased();guard mkdir(root,0o700)==0 else { throw AdapterError.invalid }
        hostClock=try .init(id:"s88-host",time:1_000_000_000);clientClock=try .init(id:"s88-client",time:1_000_000_000)
        core=try .init(container:WireFixture.container(),policy:.init(boot:ClientEnvironment.bootIdentity(),hostClock:hostClock.policy,clientClock:clientClock.policy))
        hostAuth = .init(caller:.init(principal:"s88-alice",device:"device",app:"app"),allowed:true)
        clientAuth = .init(caller:.init(principal:"s88-alice",device:"device",app:"app"))
        hostOwner=try .initialize(at:root+"/host",identity:.init(incarnation:core.hostID,clock:hostClock),keys:.init(catalog:Data(repeating:1,count:32),ticket:Data(repeating:2,count:32)),clock:hostClock)
        clientOwner=try .init(path:root+"/client",create:true,environment:.init(rootID:core.clientID,clock:clientClock),metadataKey:metadata,clock:clientClock)
        client=try .init(configuration:configuration,owner:clientOwner,authorization:clientAuth,core:core,parent:WireFixture.base(),allowNew:true)
        let f=native
        host=try .init(configuration:configuration,owner:hostOwner,authorization:hostAuth,expectedClientRoot:core.clientID,allowNew:true,
            prepare:{try f.binding($0,reference:$1,configuration:$2)},runtime:{try f.runtime($0,configuration:$1)})
    }
    deinit {
        clientOwner.close();hostOwner.close();try? FileManager.default.removeItem(atPath:root)
        if let parent=try? WireFixture.base() { try? FileManager.default.removeItem(atPath:parent+"/tickets-"+core.identifier) }
    }
    func toHost(_ bytes:Data,fragmented:Bool=false) throws -> [Data] {
        var out:[Data]=[];let width=fragmented ? 3 : 65_536
        for start in stride(from:0,to:bytes.count,by:width) { out += try host.receive(Data(bytes[start..<min(bytes.count,start+width)])) };return out
    }
    func toClient(_ bytes:Data) throws { for start in stride(from:0,to:bytes.count,by:65_536) { try client.receive(Data(bytes[start..<min(bytes.count,start+65_536)])) } }
    func exchange(_ bytes:Data) throws -> Data {
        let replies=try toHost(bytes,fragmented:true);let reply=try XCTUnwrap(replies.first);XCTAssertEqual(replies.count,1);try toClient(reply);return reply
    }
    func setup(_ route:String="ordinary") throws {
        let caps=try host.capabilities();try toClient(caps+caps) // Coalesced real frames.
        let open=try exchange(client.open(requestID:"open"))
        var r=FrameReassembler();opened=try r.feed(open)[0].decode()
        beginBytes=try client.begin(requestID:"begin",generation:"g-1",operation:"op-1",request:AdapterContract.request(route))
        let reply=try exchange(beginBytes!)
        var rr=FrameReassembler();accepted=try rr.feed(reply)[0].decode()
    }
    func reopenClient() throws {
        clientOwner.close()
        clientOwner=try .init(path:root+"/client",create:false,environment:.init(rootID:core.clientID,clock:clientClock),metadataKey:metadata,clock:clientClock)
        client=try .init(configuration:configuration,owner:clientOwner,authorization:clientAuth,core:core,parent:WireFixture.base(),allowNew:false)
    }
    func refused(_ bytes:Data) throws -> DurableRefused {
        var r=FrameReassembler();return try r.feed(XCTUnwrap(toHost(bytes).first))[0].decode()
    }
}
final class NegotiationTests:XCTestCase {
    func testDefaultAndIncompatibleAdaptersGateBeforeDispatch() throws {
        let f=try AdapterPair();let before=f.native.preparations
        for config in [AdapterConfiguration(),AdapterConfiguration(dialect:1,optIn:true,ready:true),AdapterConfiguration(dialect:2,model:"other",optIn:true,ready:true),AdapterConfiguration(dialect:2,profile:"other",optIn:true,ready:true)] {
            f.host.configuration=config;f.client.configuration=config
            XCTAssertThrowsError(try f.host.receive(Data([0,0,0,1,51])))
            XCTAssertThrowsError(try f.client.receive(Data([0,0,0,1,50])))
        }
        XCTAssertEqual(f.native.preparations,before);XCTAssertEqual(f.host.issues,0)
    }
    func testFragmentedCoalescedFramesAndBoundedMalformedInput() throws {
        let f=try AdapterPair();try f.setup();XCTAssertEqual(f.client.negotiation.phase,.accepted)
        XCTAssertThrowsError(try f.host.receive(Data(repeating:0,count:65_537)))
        XCTAssertThrowsError(try f.client.receive(Data(repeating:0,count:65_537)))
        let malformed=Data([0,0,0,2,53,123]);XCTAssertThrowsError(try f.host.receive(malformed))
        XCTAssertEqual(f.native.calls,0)
        let g=try AdapterPair();XCTAssertThrowsError(try g.host.receive(Data([1,0,0,1,53])))
        XCTAssertEqual(g.host.begins,0)
    }
}
