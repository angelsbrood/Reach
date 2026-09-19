import XCTest
import Foundation
import Darwin
import ClockPolicy
@testable import WitnessAccess

final class OwnershipTests:XCTestCase {
    func testFinishKeepsExactSixtyFourActionBudgetAndWitnessNonceBudgetAcrossOwners() throws {
        let wc=FixtureClock(),w=try Witness(clock:wc),p=selection(),d=try descriptor(w,[p])
        var allRequests=Set<Data>()
        for _ in 0..<2 {
            let owner=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
            for _ in 0..<64 {
                let a=try owner.exchange {request,_ in try w.respond(to:request)}
                XCTAssertTrue(allRequests.insert(a.request).inserted)
                XCTAssertEqual(try owner.evaluate(a).outcome,.eligible)
                try owner.finish(a)
            }
            refuses(Refusal.capacity) {_=try owner.exchange {request,_ in try w.respond(to:request)}}
            XCTAssertFalse(owner.lost)
        }
        XCTAssertEqual(allRequests.count,128)
        wc.now+=500*second // Neither expiry nor a fresh connection/owner reclaims issuer nonces.
        let third=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
        refuses(Refusal.capacity) {_=try third.exchange {request,_ in try w.respond(to:request)}}
        XCTAssertTrue(third.lost)
        refuses(Refusal.invalidated) {_=try third.exchange {request,_ in try w.respond(to:request)}}
    }
    func testEveryAmbiguousExchangeFailureLatchesOwnerAndPriorAction() throws {
        for error in [AccessError.io,.timeout,.frame,.peer,.selection] {
            let w=try Witness(clock:FixtureClock()),p=selection(),d=try descriptor(w,[p])
            let owner=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
            let prior=try owner.exchange {request,_ in try w.respond(to:request)}
            try owner.finish(prior)
            refuses(error) {_=try owner.exchange {_,_ in throw error}}
            XCTAssertTrue(owner.lost)
            refuses(Refusal.invalidated) {_=try owner.evaluate(prior)}
            refuses(Refusal.invalidated) {_=try owner.exchange {request,_ in try w.respond(to:request)}}
            let fresh=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
            XCTAssertEqual(try fresh.evaluate(fresh.exchange {request,_ in try w.respond(to:request)}).outcome,.eligible)
        }
    }
    func testResponseReplayCrossActionRefusalAndWrongIssuerInvalidate() throws {
        let w=try Witness(clock:FixtureClock()),p=selection(),d=try descriptor(w,[p])
        let owner=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
        let a=try owner.exchange {request,_ in try w.respond(to:request)}
        refuses(Refusal.replay) {_=try w.respond(to:a.request)}
        try owner.finish(a)
        refuses(Refusal.binding) {_=try owner.exchange {_,_ in a.response}}
        XCTAssertTrue(owner.lost)
        let other=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
        refuses(Refusal.binding) {_=try other.exchange {_,_ in a.response}}
        XCTAssertTrue(other.lost)
        let replacement=try Witness(clock:FixtureClock())
        let oldPin=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
        refuses(Refusal.binding) {_=try oldPin.exchange {request,_ in try replacement.respond(to:request)}}
        XCTAssertTrue(oldPin.lost)
        let malformed=try AccessOwner(descriptor:d,subject:p.subject,clock:FixtureClock())
        refuses(Refusal.malformed) {_=try malformed.exchange {_,_ in Data("{\"refusal\":\"binding\"}".utf8)}}
        XCTAssertTrue(malformed.lost)
    }
    func testSendBracketPrecedesTransportAndFiveSecondBudgetNeverRestarts() throws {
        let w=try Witness(clock:FixtureClock()),p=selection(),d=try descriptor(w,[p]),rc=FixtureClock()
        let owner=try AccessOwner(descriptor:d,subject:p.subject,clock:rc)
        let original=try rc.sample()
        refuses(AccessError.timeout) {
            _=try owner.exchange {request,deadline in
                XCTAssertEqual(deadline.start,original)
                XCTAssertEqual(owner.attemptedSend,original)
                let response=try w.respond(to:request)
                rc.now+=4*second;try deadline.check()
                rc.now+=second;return response
            }
        }
        XCTAssertTrue(owner.lost)
        refuses(Refusal.invalidated) {_=try owner.exchange {request,_ in try w.respond(to:request)}}
    }
    func testSameActionMustBeEvaluatedAfterBlockingAndCompletedEOFIsNotLoss() throws {
        let w=try Witness(clock:FixtureClock()),p=selection(client:4*second),d=try descriptor(w,[p]),rc=FixtureClock()
        let owner=try AccessOwner(descriptor:d,subject:p.subject,clock:rc)
        let a=try owner.exchange {request,_ in try w.respond(to:request)}
        XCTAssertEqual(try owner.evaluate(a).outcome,.eligible)
        XCTAssertFalse(owner.lost)
        rc.now+=2*second
        XCTAssertEqual(try owner.evaluate(a).outcome,.clientExpired)
        rc.now+=9*second
        refuses(Refusal.age) {_=try owner.evaluate(a)}
    }
    func testServicePartialProvisioningClockFaultAbortsBeforeEndpointReadiness() throws {
        final class FailingClock:PolicyClock {
            let base=FixtureClock();var reads=0
            func sample() throws -> Sample {reads+=1;if reads==3 {throw Refusal.clock};return try base.sample()}
        }
        let root=try directory();defer {try? FileManager.default.removeItem(atPath:root)}
        let endpoint=try UnixEndpoint(path:root+"/s",uid:getuid()),clock=FailingClock()
        refuses(Refusal.clock) {_=try WitnessService(endpoint:endpoint,selections:[selection()],clock:clock)}
        XCTAssertEqual(clock.reads,3)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:root).isEmpty)
    }
    func testServiceDeadlineClockFaultCannotRecoverOrAcceptLaterRequest() throws {
        for kind in ["sample-error","deadline-regression","epoch"] {
            let rig=try ServiceRig();let v=try Verifier(originals:rig.originals,clock:FixtureClock())
            let request=try v.begin(purpose:.candidate).request
            let first=try serviceConnection(request),later=try serviceConnection(request)
            defer {first.0.close();first.1.close();later.0.close();later.1.close()}
            var accepted=0,signedReplies=0
            func run() throws {
                try rig.service.run(accept:{
                    accepted+=1
                    guard accepted==1 else {throw ServiceTestError.completed}
                    rig.clock.script=[.sample(101*second),kind=="sample-error" ? .failure : (kind=="epoch" ? .epoch : .sample(100*second)),.sample(102*second)]
                    return first.0
                },beforeReply:{_ in signedReplies+=1})
            }
            if kind=="sample-error" {refuses(ServiceTestError.transient,run)} else {refuses(Refusal.clock,run)}
            XCTAssertEqual(accepted,1);XCTAssertEqual(signedReplies,0)
            XCTAssertEqual(first.0.value,-1);XCTAssertEqual(rig.listener.value,-1)
            XCTAssertEqual(try rig.clock.sample().nanoseconds,102*second) // The next underlying read really is healthy.
            refuses(Refusal.invalidated) {try rig.service.run(accept:{accepted+=1;return later.0})}
            XCTAssertEqual(accepted,1)
        }
    }
    func testClockFaultDuringBestEffortRefusalAlsoEndsService() throws {
        let rig=try ServiceRig(),v=try Verifier(originals:rig.originals,clock:FixtureClock())
        let connection=try serviceConnection(v.begin(purpose:.candidate).request)
        defer {connection.0.close();connection.1.close()}
        var accepted=0,signedReplies=0
        refuses(ServiceTestError.transient) {
            try rig.service.run(accept:{
                accepted+=1;guard accepted==1 else {throw ServiceTestError.completed};return connection.0
            },beforeReply:{_ in
                signedReplies+=1
                // A recoverable connection failure enters the refusal path. Its first
                // observe is healthy; the refusal's own deadline read then fails once.
                rig.clock.script=[.sample(102*second),.failure,.sample(103*second)]
                throw AccessError.io
            })
        }
        XCTAssertEqual(accepted,1);XCTAssertEqual(signedReplies,1)
        XCTAssertEqual(connection.0.value,-1);XCTAssertEqual(rig.listener.value,-1)
        XCTAssertEqual(try rig.clock.sample().nanoseconds,103*second)
        refuses(Refusal.invalidated) {try rig.service.run(accept:{XCTFail("closed service accepted again");return nil})}
    }
    func testMalformedAndTimedOutPeerLeaveSameIssuerAvailableForNextRequest() throws {
        for timeout in [false,true] {
            let rig=try ServiceRig(),rc=FixtureClock(),v=try Verifier(originals:rig.originals,clock:rc)
            let next=try v.begin(purpose:.candidate)
            let other=try Verifier(originals:rig.originals,clock:FixtureClock())
            let first=try serviceConnection(timeout ? other.begin(purpose:.candidate).request : Data("{}".utf8))
            let secondConnection=try serviceConnection(next.request)
            defer {first.0.close();first.1.close();secondConnection.0.close();secondConnection.1.close()}
            var accepted=0,replies=0
            refuses(ServiceTestError.completed) {
                try rig.service.run(accept:{
                    accepted+=1
                    if accepted==1 {return first.0};if accepted==2 {return secondConnection.0}
                    throw ServiceTestError.completed
                },beforeReply:{_ in
                    replies+=1
                    if timeout && replies==1 {rig.clock.base.now+=6*second}
                })
            }
            XCTAssertEqual(accepted,3)
            let ioClock=FixtureClock(),deadline=try IODeadline(start:ioClock.sample(),clock:ioClock)
            if timeout {
                refuses(AccessError.frame) {_=try SocketIO.readFrame(from:first.1,deadline:deadline)}
            } else {
                struct Rejected:Codable {let refusal:String}
                let refusal=try SocketIO.readFrame(from:first.1,deadline:deadline)
                XCTAssertEqual(try Wire.decode(Rejected.self,refusal).refusal,"malformed")
                try SocketIO.expectEOF(first.1,deadline:deadline)
            }
            let signed=try SocketIO.readFrame(from:secondConnection.1,deadline:deadline)
            try SocketIO.expectEOF(secondConnection.1,deadline:deadline)
            try v.receive(signed,for:next);XCTAssertEqual(try v.evaluate(next).outcome,.eligible)
            XCTAssertEqual(try rig.service.descriptor.select(subject:rig.subject),rig.originals)
        }
    }
}

private enum ServiceTestError:Error {case transient,completed}
private final class ServiceClock:PolicyClock {
    enum Read {case sample(UInt64),failure,epoch}
    let base=FixtureClock();var script:[Read]=[]
    func sample() throws -> Sample {
        guard !script.isEmpty else {return try base.sample()}
        switch script.removeFirst() {
        case .failure:throw ServiceTestError.transient
        case .sample(let value):base.now=value;return try base.sample()
        case .epoch:return Sample(boot:uuid(),incarnation:base.incarnation,nanoseconds:base.now)
        }
    }
}
private func serviceSockets() throws -> (SocketFD,SocketFD) {
    var values:[Int32]=[0,0];guard socketpair(AF_UNIX,SOCK_STREAM,0,&values)==0 else {throw AccessError.io}
    return try (SocketFD(values[0]),SocketFD(values[1]))
}
private func serviceConnection(_ body:Data) throws -> (SocketFD,SocketFD) {
    let pair=try serviceSockets(),c=FixtureClock(),d=try IODeadline(start:c.sample(),clock:c)
    try SocketIO.writeFrame(body,to:pair.1,deadline:d);try SocketIO.halfClose(pair.1,deadline:d);return pair
}
private final class ServiceRig {
    let clock=ServiceClock(),subject=uuid(),root:String,service:WitnessService,listener:SocketFD,other:SocketFD,originals:Originals
    init() throws {
        root=try directory();let pair=try serviceSockets();listener=pair.0;other=pair.1
        let endpoint=try UnixEndpoint(path:root+"/s",uid:getuid())
        service=try WitnessService(endpoint:endpoint,selections:[selection(subject)],clock:clock,listen:{pair.0})
        originals=try service.descriptor.select(subject:subject)
    }
    deinit {listener.close();other.close();try? FileManager.default.removeItem(atPath:root)}
}
