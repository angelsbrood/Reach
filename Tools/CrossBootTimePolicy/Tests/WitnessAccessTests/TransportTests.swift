import XCTest
import Foundation
import Darwin
import ClockPolicy
@testable import WitnessAccess

final class TransportTests:XCTestCase {
    func testDeadlineExactBoundaryOverflowRegressionAndEpochChange() throws {
        let clock=FixtureClock(),start=try clock.sample(),deadline=try IODeadline(start:start,clock:clock)
        clock.now+=IODeadline.maximumNanoseconds-1;try deadline.check()
        clock.now+=1;refuses(AccessError.timeout) {try deadline.check()}
        clock.now=UInt64.max
        refuses(AccessError.overflow) {_=try IODeadline(start:clock.sample(),clock:clock)}
        for change in ["regression","boot","incarnation"] {
            let c=FixtureClock(),d=try IODeadline(start:c.sample(),clock:c)
            if change=="regression" {c.now-=1} else if change=="boot" {c.boot=uuid()} else {c.incarnation=uuid()}
            refuses(Refusal.clock) {try d.check()}
        }
    }
    func sockets() throws -> (SocketFD,SocketFD) {
        var values:[Int32]=[0,0]
        guard socketpair(AF_UNIX,SOCK_STREAM,0,&values)==0 else {throw AccessError.io}
        return try (SocketFD(values[0]),SocketFD(values[1]))
    }
    func testFrameBoundsPartialEOFAndExtraBytes() throws {
        for bytes in [Data(),Data([0,0]),Data([0,0,0,0]),Data([0,1,0,1]),Data([0,0,0,2,65])] {
            let (sender,receiver)=try sockets();defer {sender.close();receiver.close()}
            let clock=FixtureClock(),d=try IODeadline(start:clock.sample(),clock:clock)
            try SocketIO.writeBytes(bytes,to:sender,deadline:d);try SocketIO.halfClose(sender,deadline:d)
            refuses(AccessError.frame) {_=try SocketIO.readFrame(from:receiver,deadline:d)}
        }
        let (sender,receiver)=try sockets();defer {sender.close();receiver.close()}
        let c=FixtureClock(),d=try IODeadline(start:c.sample(),clock:c)
        let body=Data([1,2,3]);try SocketIO.writeFrame(body,to:sender,deadline:d)
        try SocketIO.writeFrame(body,to:sender,deadline:d);try SocketIO.halfClose(sender,deadline:d)
        XCTAssertEqual(try SocketIO.readFrame(from:receiver,deadline:d),body)
        refuses(AccessError.frame) {try SocketIO.expectEOF(receiver,deadline:d)}
    }
    func testExactFrameAndEOFDoNotInventLossAndRejectInvalidOutgoingSizes() throws {
        let (sender,receiver)=try sockets();defer {sender.close();receiver.close()}
        let c=FixtureClock(),d=try IODeadline(start:c.sample(),clock:c),body=Data(repeating:42,count:512)
        try SocketIO.writeFrame(body,to:sender,deadline:d);try SocketIO.halfClose(sender,deadline:d)
        XCTAssertEqual(try SocketIO.readFrame(from:receiver,deadline:d),body)
        try SocketIO.expectEOF(receiver,deadline:d)
        refuses(AccessError.frame) {try SocketIO.writeFrame(Data(),to:receiver,deadline:d)}
        refuses(AccessError.frame) {try SocketIO.writeFrame(Data(repeating:0,count:65537),to:receiver,deadline:d)}
    }
    func testExpiredDeadlineStopsBeforeConnectReadWriteOrEOF() throws {
        let (sender,receiver)=try sockets();defer {sender.close();receiver.close()}
        let c=FixtureClock(),d=try IODeadline(start:c.sample(),clock:c)
        c.now+=5*second
        let endpoint=try UnixEndpoint(path:"/private/tmp/nonexistent-s106/s",uid:getuid())
        refuses(AccessError.timeout) {_=try endpoint.connect(deadline:d)}
        refuses(AccessError.timeout) {_=try SocketIO.readFrame(from:receiver,deadline:d)}
        refuses(AccessError.timeout) {try SocketIO.writeFrame(Data([1]),to:sender,deadline:d)}
        refuses(AccessError.timeout) {try SocketIO.expectEOF(receiver,deadline:d)}
    }
    func testClosedPeerWriteRefusesWithoutSIGPIPE() throws {
        let (sender,receiver)=try sockets();defer {sender.close()};receiver.close()
        let c=FixtureClock(),d=try IODeadline(start:c.sample(),clock:c)
        refuses(AccessError.io) {try SocketIO.writeFrame(Data([1]),to:sender,deadline:d)}
    }
}
