import Foundation
import XCTest
import ReachWire
import DurableSessionLifecycle
import WireAdapterContract
import MLX

final class BindingRefusalTests:XCTestCase {
    private func open(_ f:AdapterPair) throws {
        try f.toClient(f.host.capabilities());_=try f.exchange(f.client.open(requestID:"open"))
    }
    private func withdraw(_ f:AdapterPair,readiness:Bool,onPublication:@escaping ()->Void = {}) {
        f.host.publicationHook={ [unowned host=f.host] in
            if readiness { host.configuration.ready=false } else { host.configuration.optIn=false }
            onPublication()
        }
    }
    private func step(_ f:AdapterPair) throws {
        defer { XCTAssertLessThanOrEqual(Memory.peakMemory,128<<20) }
        _=try Device.withDefaultDevice(Device(.cpu)) { try f.host.step() }
    }
    func testFirstBeginAcceptanceRejectsOtherSupportedRequest() throws {
        for (sent,substituted) in [("ordinary","required"),("required","ordinary")] {
            let f=try AdapterPair();try open(f)
            let request=try AdapterContract.request(sent)
            let bytes=try f.client.begin(requestID:"begin",generation:"g-1",operation:"op-1",request:request)
            var decoder=FrameReassembler();var altered:DurableGenerateBegin=try decoder.feed(bytes)[0].decode()
            altered.payload.request=try AdapterContract.request(substituted)
            let replies=try f.toHost(DurableMessage.begin(altered).encode(version:2))
            XCTAssertEqual(replies.count,1)
            let reply=try XCTUnwrap(replies.first);var response=FrameReassembler()
            let accepted:DurableGenerationAccepted=try response.feed(reply)[0].decode()
            let actual=try AdapterContract.context(accepted.payload.context,reference:accepted.payload.reference,configuration:f.configuration)
            XCTAssertNotEqual(actual.context.request,try AdapterContract.requestBinding(request,configuration:f.configuration,route:sent))
            // The real host accepted the substituted supported mapping. The
            // client must refuse it before creating a journal or ticket sidecar.
            let binding=try WireFixture.binding(f.core)
            XCTAssertTrue(try f.clientOwner.discover(binding:binding,authorization:f.clientAuth).isEmpty)
            XCTAssertThrowsError(try f.toClient(reply),sent+" -> "+substituted)
            XCTAssertEqual(f.client.negotiation.phase,.beginning)
            XCTAssertTrue(try f.clientOwner.discover(binding:binding,authorization:f.clientAuth).isEmpty)
            XCTAssertFalse(FileManager.default.fileExists(atPath:try WireFixture.base()+"/tickets-"+f.core.identifier))
            XCTAssertThrowsError(try f.client.witness());XCTAssertEqual(f.native.calls,0)
        }
    }
    func testHostConfigurationWithdrawalRefusesTicketReplies() throws {
        for readiness in [false,true] {
            for operation in ["open","begin","recover","receipt"] {
                let f=try AdapterPair();let bytes:Data
                switch operation {
                case "open":try f.toClient(f.host.capabilities());bytes=try f.client.open(requestID:"open")
                case "begin":try open(f);bytes=try f.client.begin(requestID:"begin",generation:"g-1",operation:"op-1",request:AdapterContract.request("ordinary"))
                case "recover":try f.setup();try f.reopenClient();try f.toClient(f.host.capabilities());bytes=try f.client.recover(requestID:"recover")
                default:try f.setup();bytes=try f.client.receipt(requestID:"receipt")
                }
                let counts=[f.host.issues,f.host.begins,f.host.recoveries]
                withdraw(f,readiness:readiness)
                let replies=try f.toHost(bytes);XCTAssertEqual(replies.count,1)
                var decoder=FrameReassembler();let raw=try decoder.feed(XCTUnwrap(replies.first))[0]
                XCTAssertEqual(raw.type,.durableRefused,"\(operation), readiness=\(readiness)")
                if raw.type == .durableRefused {
                    let refusal:DurableRefused=try raw.decode();XCTAssertEqual(refusal.payload.correlation.operation.rawValue,operation)
                }
                XCTAssertEqual([f.host.issues,f.host.begins,f.host.recoveries],counts)
                XCTAssertEqual(f.native.calls,0)
            }
            let f=try AdapterPair();withdraw(f,readiness:readiness)
            XCTAssertThrowsError(try f.host.capabilities()) // Existing no-ticket behavior stays intact.
        }
    }
    func testHostConfigurationWithdrawalRefusesNativePublication() throws {
        for readiness in [false,true] {
            let f=try AdapterPair();try f.setup()
            for _ in 0..<64 { try step(f);if (f.host.status?.high ?? 0)>0 {break} }
            XCTAssertGreaterThan(f.host.status?.high ?? 0,0);XCTAssertNil(f.host.status?.providerEnding)
            let prefix=try f.host.replay();XCTAssertFalse(prefix.isEmpty)
            let calls=f.native.calls;withdraw(f,readiness:readiness)
            XCTAssertThrowsError(try f.host.replay());XCTAssertEqual(f.native.calls,calls)
            f.host.configuration=f.configuration;f.host.publicationHook={}
            for frame in prefix { try f.toClient(frame) }
            _=try f.exchange(f.client.receipt(requestID:"prefix"))
            var publications=0;withdraw(f,readiness:readiness) { publications+=1 }
            // Store work may complete before withdrawal. Only publication of
            // success is forbidden; there is no rollback requirement.
            XCTAssertThrowsError(try step(f))
            XCTAssertEqual(publications,1) // Reaches publication after real work, not an earlier credit refusal.
        }
    }
    func testHostConfigurationWithdrawalRefusesCheckedKnowledge() throws {
        for readiness in [false,true] {
            let f=try AdapterPair();try f.setup("required")
            for _ in 0..<128 { try step(f);if f.host.status?.providerEnding != nil {break} }
            XCTAssertNotNil(f.host.status?.providerEnding)
            for frame in try f.host.replay() { try f.toClient(frame) }
            _=try f.client.beginLocalEffect() // Intent only; no fixture effect is invoked here.
            let report=try f.client.knowledge();withdraw(f,readiness:readiness)
            XCTAssertThrowsError(try f.toHost(report));XCTAssertEqual(f.host.peerReports,0)
        }
    }
    func testTicketNamespaceOperationAndWholeRequestSubstitution() throws {
        let f=try AdapterPair();try f.setup()
        var raw=FrameReassembler();let original:DurableGenerateBegin=try raw.feed(f.beginBytes!)[0].decode()
        let mutations:[(inout DurableGenerateBeginPayload)->Void]=[
            {$0.ticket[0] ^= 1},{$0.reference.session.sessionID="00000000-0000-0000-0000-000000000001"},
            {$0.reference.session.modelID="other"},{$0.reference.session.profile="other"},{$0.reference.operationID="other"},
            {$0.request.options.maximumResponseTokens=999},{$0.request.id=UUID()}
        ]
        for mutate in mutations { var value=original;mutate(&value.payload);_=try f.refused(DurableMessage.begin(value).encode(version:2)) }
        XCTAssertEqual(f.native.preparations,1);XCTAssertEqual(f.native.calls,0);XCTAssertEqual(f.host.begins,1)
        var changed=original;changed.payload.request=try AdapterContract.request("required")
        XCTAssertEqual(try f.refused(DurableMessage.begin(changed).encode(version:2)).payload.reason,.invalid)
        let stored=try f.hostOwner.wireProviderBinding(ticket:SessionTicket(data:original.payload.ticket),authorization:f.hostAuth,generation:"g-1")
        XCTAssertEqual(stored.requestID,try AdapterContract.requestBinding(original.payload.request,configuration:f.configuration,route:"ordinary"))
    }
    func testCurrentCallerExpiryAndAcrossIOPublicationRefuse() throws {
        let f=try AdapterPair();try f.setup()
        f.hostAuth.allowed=false;XCTAssertThrowsError(try f.toHost(f.beginBytes!));f.hostAuth.allowed=true
        f.hostAuth.caller = .init(principal:"substitute",device:"device",app:"app")
        XCTAssertThrowsError(try f.toHost(f.beginBytes!));f.hostAuth.caller = .init(principal:"s88-alice",device:"device",app:"app")
        f.host.publicationHook={f.hostAuth.allowed=false}
        XCTAssertEqual(try f.refused(f.beginBytes!).payload.reason,.unauthorized)
        XCTAssertEqual(f.native.calls,0);f.hostAuth.allowed=true;f.host.publicationHook={}
        f.hostClock.time += LifecycleLimits.session
        XCTAssertEqual(try f.refused(f.beginBytes!).payload.reason,.expired)
    }
}
