import XCTest
import Foundation
import ClockPolicy
import RecoveryAuthorityContract
import ResumableMLXProvider
import DurableHostStore
import DurableSessionLifecycle
import DurableClientReceipts
import HostClientContract
@testable import ReachDurableRuntime

final class NativeAuthorityBindingTests: XCTestCase {
    func testForeignOwnerCannotAdoptLiveResources() throws { try foreignOwner(openingState:"live") }
    func testForeignOwnerCannotReplaceInvalidatedOpeningOwner() throws { try foreignOwner(openingState:"invalidated") }
    func testForeignOwnerCannotResetExhaustedOpeningOwner() throws { try foreignOwner(openingState:"exhausted") }

    private func active(_ f: NativeRecoveryFixture) throws -> (NativeLifecycleOwner,NativeClientOwner,GuardedNativeGeneration) {
        _=try f.provision()
        var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
        try a.finish(); a=try f.action(.prepare)
        let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        try f.deliver(h,c,g,a); try a.finish(); a=try f.action(.advance)
        try g.advance(action:a); try h.synchronize(action:a); try f.deliver(h,c,g,a)
        try a.finish(); return (h,c,g)
    }
    private func foreignOwner(openingState: String) throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(), (h,c,g)=try active(f)
        defer { g.close(); h.close(); c.close() }
        let capture=try f.action(.delivery); try h.store.authorize(capture)
        let receipt=try c.witness(action:capture), frame=try XCTUnwrap(h.store.replay(after:0).first)
        try capture.finish()
        if openingState == "invalidated" {
            f.owner.observeWitnessLoss(); XCTAssertThrowsError(try f.owner.begin(.advance))
        } else if openingState == "exhausted" {
            while f.owner.actionCount < 64 { let a=try f.action(.delivery); try a.finish() }
            XCTAssertThrowsError(try f.owner.begin(.advance))
        }
        var foreignRootChecks=0
        let replacement=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock,validateOwnedRoots:{ foreignRootChecks += 1 })
        let b=try f.action(.advance,owner:replacement)
        // Give B the same valid originals, receiver clock and authenticated
        // admission. Scope/admission equality must not substitute for owner A.
        try b.bindAuthenticated(h.admission)
        let checks=foreignRootChecks, before=try f.hashes(), calls=f.counter.calls, models=f.counter.models
        var touched=0; h.store.fault={_ in touched += 1}; h.fault={_ in touched += 1}; c.fault={_ in touched += 1}
        XCTAssertThrowsError(try h.store.authorize(b))
        XCTAssertThrowsError(try g.advance(action:b))
        XCTAssertThrowsError(try h.synchronize(action:b))
        XCTAssertThrowsError(try h.timerBytes(action:b))
        XCTAssertThrowsError(try c.witness(action:b))
        XCTAssertThrowsError(try c.inbox(action:b))
        XCTAssertThrowsError(try c.accept(.init(firstSequence:frame.firstSequence,count:frame.count,providerCommit:frame.providerCommit,eventBytes:frame.eventBytes),action:b))
        XCTAssertThrowsError(try h.acceptReceipt(receipt,action:b))
        XCTAssertThrowsError(try g.acknowledgeDelivery(through:receipt.high,action:b))
        XCTAssertEqual(foreignRootChecks,checks,"Reject the owner before invoking its replacement root-check closure")
        XCTAssertEqual(touched,0); XCTAssertEqual(f.counter.calls,calls); XCTAssertEqual(f.counter.models,models)
        XCTAssertEqual(try f.hashes(),before)
        try b.finish(); g.close(); h.close(); c.close()

        // B becomes a legitimate owner only after actual resource close/reopen.
        let reopen=try f.action(.reopen,owner:replacement), host=try f.openHost(reopen), client=try f.openClient(reopen)
        defer { host.close(); client.close() }
        let restored=try GuardedNativeGeneration.restore(store:host.store,action:reopen,runtime:f.runtime)
        defer { restored.close() }
        XCTAssertEqual(f.counter.calls,calls)
        try f.deliver(host,client,restored,reopen); try reopen.finish()
        let step=try f.action(.advance,owner:replacement)
        try restored.advance(action:step); try host.synchronize(action:step); try f.deliver(host,client,restored,step)
        XCTAssertEqual(f.counter.calls,calls+1); try step.finish()
    } }

    func testOriginalAdmissionOperationsCannotUseExistingResources() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(), (h,c,g)=try active(f)
        defer { g.close(); h.close(); c.close() }
        let read=try f.action(.delivery); try h.store.authorize(read)
        let receipt=try c.witness(action:read), frame=try XCTUnwrap(h.store.replay(after:0).first)
        try read.finish()
        for operation in [GenerationOperation.admitHost,.acceptClient] {
            let a=try f.action(operation), before=try f.hashes(), calls=f.counter.calls
            var touched=0; h.store.fault={_ in touched += 1}; h.fault={_ in touched += 1}; c.fault={_ in touched += 1}
            XCTAssertThrowsError(try h.store.authorize(a))
            XCTAssertThrowsError(try h.store.replay(after:0))
            XCTAssertThrowsError(try h.store.snapshot())
            XCTAssertThrowsError(try h.synchronize(action:a))
            XCTAssertThrowsError(try h.timerBytes(action:a))
            XCTAssertThrowsError(try c.witness(action:a))
            XCTAssertThrowsError(try c.inbox(action:a))
            XCTAssertThrowsError(try c.accept(.init(firstSequence:frame.firstSequence,count:frame.count,providerCommit:frame.providerCommit,eventBytes:frame.eventBytes),action:a))
            XCTAssertThrowsError(try h.acceptReceipt(receipt,action:a))
            XCTAssertThrowsError(try g.acknowledgeDelivery(through:receipt.high,action:a))
            XCTAssertEqual(touched,0); XCTAssertEqual(f.counter.calls,calls); XCTAssertEqual(try f.hashes(),before)
            try a.finish()
        }
    } }

    func testReadActionsCannotReserveOrCommitNativeState() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(), (h,c,g)=try active(f)
        defer { g.close(); h.close(); c.close() }
        let a=try f.action(.delivery); try h.store.authorize(a)
        let selected=try h.store.snapshot(), before=try f.hashes(), calls=f.counter.calls
        XCTAssertThrowsError(try h.store.reserve())
        XCTAssertThrowsError(try h.store.commit(XCTUnwrap(selected.candidate)))
        XCTAssertThrowsError(try h.store.reconcile())
        XCTAssertEqual(try f.hashes(),before); XCTAssertEqual(f.counter.calls,calls)
        try f.deliver(h,c,g,a); try h.synchronize(action:a); try a.finish()
    } }

    func testTerminalReplayRetainsSameOwnerAndRejectsForeignHandles() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(), (h,c,g)=try active(f)
        defer { g.close(); h.close(); c.close() }
        var a=try f.action(.advance); try h.store.authorize(a)
        while try !h.store.snapshot().terminal {
            try g.advance(action:a); try h.synchronize(action:a); try f.deliver(h,c,g,a)
            try a.finish(); a=try f.action(.advance); try h.store.authorize(a)
        }
        let expected=try c.inbox(action:a), receipt=try c.witness(action:a), calls=f.counter.calls
        try a.finish(); a=try f.action(.terminalReplay); try h.store.authorize(a)
        try f.deliver(h,c,g,a); try h.synchronize(action:a)
        XCTAssertEqual(try c.witness(action:a),receipt); XCTAssertEqual(try AuthorityCodec.encode(c.inbox(action:a)),try AuthorityCodec.encode(expected)); XCTAssertEqual(f.counter.calls,calls)
        try a.finish()
        let other=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock), b=try f.action(.terminalReplay,owner:other)
        try b.bindAuthenticated(h.admission)
        XCTAssertThrowsError(try h.store.authorize(b)); XCTAssertThrowsError(try c.inbox(action:b)); XCTAssertThrowsError(try h.synchronize(action:b))
        XCTAssertEqual(f.counter.calls,calls); try b.finish()
    } }
}
