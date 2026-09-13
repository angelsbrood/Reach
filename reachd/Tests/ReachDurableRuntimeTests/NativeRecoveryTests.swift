import XCTest
import Foundation
import ClockPolicy
import RecoveryAuthorityContract
import ResumableMLXProvider
import ReachWire
import DurableRootKeys
import DurableStoreBootstrap
import RecoveryContract
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts
@testable import ReachDurableRuntime

final class NativeRecoveryTests: XCTestCase {
    func testProfileAndLegacyAcquisitionSeparation() throws {
        let f=try NativeRecoveryFixture(); _=try f.provision()
        XCTAssertEqual(f.scope.profile,AuthorityCodec.nativeProfile)
        XCTAssertThrowsError(try RecoveryAuthorityAction(scope:f.scope,operation:.authenticateHost,clock:f.receiverClock))
        XCTAssertThrowsError(try StoreIdentity(authority:f.scope,storeID:UUID().uuidString.lowercased(),provider:f.provider))
        XCTAssertThrowsError(try DurableClientReceipts(path:f.client+"/bootstrap/client",create:false,environment:f.clientEnvironment,metadataKey:f.clientKey,clock:SystemClientClock()))
        XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:f.hostKeys,clock:SystemLifecycleClock()))
        let s100=try RecoveryAuthorityFixture()
        XCTAssertThrowsError(try GenerationAuthorityOwner(scope:s100.scope,clock:f.receiverClock))
    }
    func testOwnerLossReplacementAndActionBudgetRemainLatched() throws {
        let f=try NativeRecoveryFixture()
        let a=try f.action(.reopen); try a.finish()
        XCTAssertThrowsError(try a.check())
        let b=try f.action(.advance); b.observeWitnessLoss()
        XCTAssertThrowsError(try b.check()); XCTAssertThrowsError(try b.finish()); XCTAssertThrowsError(try f.owner.begin(.delivery))
        let g=try NativeRecoveryFixture(), c=try g.action(.reopen)
        XCTAssertThrowsError(try c.observeWitnessIdentity(f.witness.identity)); XCTAssertThrowsError(try g.owner.begin(.reopen))
        let bounded=try NativeRecoveryFixture()
        for _ in 0..<64 { let a=try bounded.action(.delivery); try a.check(); try a.finish() }
        XCTAssertEqual(bounded.owner.actionCount,64); XCTAssertThrowsError(try bounded.owner.begin(.delivery))
    }
    func testWrongCertificateOperationAndScopeRefuse() throws {
        let f=try NativeRecoveryFixture(), g=try NativeRecoveryFixture(), a=try f.action(.reopen)
        XCTAssertThrowsError(try a.check(scope:g.scope,operation:.reopen)); XCTAssertThrowsError(try a.check(scope:f.scope,operation:.advance))
        try a.finish(); let b=try f.owner.begin(.advance)
        let wrong=try g.owner.begin(.advance)
        XCTAssertThrowsError(try b.receive(g.witness.respond(to:wrong.request))); XCTAssertThrowsError(try b.check())
    }
    func testHostAheadReplayAndPositiveRestorePreserveOriginals() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(); let admission=try f.provision()
        var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
        try a.finish(); a=try f.action(.prepare)
        let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        try f.deliver(h,c,g,a); try a.finish(); a=try f.action(.advance)
        try g.advance(action:a); try h.synchronize(action:a)
        XCTAssertGreaterThan(try h.store.snapshot().high,try c.witness(action:a).high)
        let calls=f.counter.calls, original=try AuthorityCodec.encode(admission)
        g.close(); h.close(); c.close(); try a.finish()
        let rebootClock=AuthorityFixtureClock(time:1_000_000_000), reopened=try GenerationAuthorityOwner(scope:f.scope,clock:rebootClock)
        let b=try f.action(.reopen,owner:reopened), host=try f.openHost(b), client=try f.openClient(b)
        defer { host.close(); client.close() }
        let live=try GuardedNativeGeneration.restore(store:host.store,action:b,runtime:f.runtime)
        XCTAssertEqual(f.counter.calls,calls)
        XCTAssertEqual(try AuthorityCodec.encode(host.admission),original)
        XCTAssertThrowsError(try live.advance(action:b))
        try f.deliver(host,client,live,b)
        XCTAssertEqual(try client.witness(action:b).high,try host.store.snapshot().high)
        try b.finish(); let step=try f.action(.advance,owner:reopened)
        try live.advance(action:step); XCTAssertGreaterThan(f.counter.calls,calls)
        let d=try JSONSerialization.jsonObject(with:host.timerBytes(action:step)) as! [String:Any]
        XCTAssertEqual((d["admitted"] as? NSNumber)?.uint64Value,100_000_000_000)
        XCTAssertEqual((d["lastContact"] as? NSNumber)?.uint64Value,100_000_000_000)
        XCTAssertEqual((d["absoluteUntil"] as? NSNumber)?.uint64Value,190_000_000_000)
        live.close(); try step.finish()
    } }
    func testNativeToCommitAgeFailureSelectsOriginalCandidate() throws { try gap(.afterNativeBeforeCommit,selected:false) }
    func testCommitToAcknowledgementAgeFailureReconcilesSelectedCandidate() throws { try gap(.afterCommitBeforeAck,selected:true) }
    private func gap(_ fault: StoreFaultPoint, selected: Bool) throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(); _=try f.provision()
        var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
        defer { h.close(); c.close() }
        try a.finish(); a=try f.action(.prepare); let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        try f.deliver(h,c,g,a); let original=try h.store.snapshot().candidate!.commit
        let receipt=try c.witness(action:a)
        try a.finish(); a=try f.action(.advance)
        h.store.fault={ point in if point == fault { f.receiverClock.advance(10_000_000_001) } }
        XCTAssertThrowsError(try g.advance(action:a)); XCTAssertThrowsError(try h.store.snapshot()); XCTAssertThrowsError(try c.witness(action:a))
        try a.finish(); let fresh=try f.action(.reopen); try h.store.authorize(fresh)
        let state=try h.store.reconcile()
        XCTAssertEqual(state.candidate?.commit == original,!selected)
        XCTAssertEqual(try c.witness(action:fresh),receipt)
        h.store.fault={_ in}; let restored=try GuardedNativeGeneration.restore(store:h.store,action:fresh,runtime:f.runtime)
        let calls=f.counter.calls; try f.deliver(h,c,restored,fresh); XCTAssertEqual(f.counter.calls,calls)
        restored.close(); try fresh.finish()
    } }
    func testIndependentExpiryBeforeNativeMakesZeroCalls() throws {
        for caps in [(UInt64(30),UInt64(90)),(90,30)] {
            let f=try NativeRecoveryFixture(hostCap:caps.0,clientCap:caps.1); _=try f.provision()
            let a=try f.action(.reopen), h=try f.openHost(a); defer { h.close() }; try a.finish()
            f.witnessClock.advance(29_000_000_000); let b=try f.action(.prepare)
            XCTAssertThrowsError(try GuardedNativeGeneration.start(store:h.store,action:b,runtime:f.runtime)); XCTAssertEqual(f.counter.calls,0)
            try b.finish()
        }
    }
    func testTerminalRecoveryDoesNotInvokeRuntimeFactory() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(); _=try f.provision()
        var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a)
        try a.finish(); a=try f.action(.prepare); let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        try f.deliver(h,c,g,a)
        while try !h.store.snapshot().terminal { try a.finish(); a=try f.action(.advance); try g.advance(action:a); try f.deliver(h,c,g,a) }
        let expected=try c.witness(action:a), calls=f.counter.calls
        g.close(); h.close(); c.close(); try a.finish()
        a=try f.action(.reopen); let reopened=try f.openHost(a), client=try f.openClient(a); defer { reopened.close(); client.close() }
        var factories=0
        let terminal=try GuardedNativeGeneration.restore(store:reopened.store,action:a,runtime:{ factories += 1; throw AuthorityError.state })
        try f.deliver(reopened,client,terminal,a)
        XCTAssertEqual(factories,0); XCTAssertEqual(f.counter.calls,calls); XCTAssertEqual(try client.witness(action:a),expected)
        terminal.close(); try a.finish()
    } }
    func testV5OriginalKeysAndS100ReaderSeparation() throws {
        let f=try NativeRecoveryFixture(), root=try LifecycleFixture(unlock:true,authority:f.scope.provision)
        XCTAssertEqual(root.core.version,5); XCTAssertEqual(try RoleOwnershipReceipt(ready:root.ready).version,3)
        XCTAssertThrowsError(try RoleBootstrapStore.inspect(at:root.root,role:.client))
        XCTAssertThrowsError(try RoleBootstrapStore.inspectRecoveryAuthority(at:root.root,role:.client))
        let (_,lease)=try RoleLifecycleLease.selectNativeRecovery(receipt:root.receipt,expectedDigest:XCTUnwrap(root.digest)); defer { lease.close() }
        _=try RoleBootstrapStore.acquireNativeRecovery(ready:root.ready,lease:lease,provider:root.provider)
        try lease.confirmNativeBoundary(RoleOwnershipReceipt(nativeRecovery:root.ready),expectedDigest:XCTUnwrap(root.digest))
        let reference=try root.core.reference(.clientMetadata)
        root.provider.values[reference.identifier]=(try root.core.binding(),try RootKeyMaterial(Data(repeating:0,count:32)))
        XCTAssertThrowsError(try RoleBootstrapStore.acquireNativeRecovery(ready:root.ready,lease:lease,provider:root.provider))
    }
    func testOriginalIssuerExportScopeAndProviderSwapsRefuse() throws {
        let f=try NativeRecoveryFixture(), g=try NativeRecoveryFixture(), admission=try f.provision()
        let issued=try AuthorityIssued(admission,ticketKey:f.ticketKey)
        XCTAssertThrowsError(try AuthorityAcceptance(issued:issued,originalIssuer:AuthorityIssued.issuerKey(ticketKey:g.ticketKey,native:true).publicKey.rawRepresentation,originalSuccessfulExportDigest:AuthorityCodec.digest(issued)))
        XCTAssertThrowsError(try AuthorityAcceptance(issued:issued,originalIssuer:AuthorityIssued.issuerKey(ticketKey:f.ticketKey,native:true).publicKey.rawRepresentation,originalSuccessfulExportDigest:String(repeating:"e",count:64)))
        let a=try f.action(.reopen); defer { try? a.finish() }
        XCTAssertThrowsError(try NativeLifecycleOwner(path:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:g.hostKeys,scope:f.scope,action:a))
        XCTAssertThrowsError(try NativeLifecycleOwner(path:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:f.hostKeys,scope:g.scope,action:a))
        var changed=f.provider; changed.operationID="replacement-operation"
        XCTAssertThrowsError(try StoreIdentity(native:f.scope,storeID:admission.store,provider:changed))
    }
    func testClientCommitBeforePublicationAgeGapReconcilesWithoutDuplicateReceipt() throws { try LocalDurableRuntime.withCPU {
        let f=try NativeRecoveryFixture(); _=try f.provision()
        var a=try f.action(.reopen); let h=try f.openHost(a), c=try f.openClient(a); defer { h.close(); c.close() }
        try a.finish(); a=try f.action(.prepare); let g=try GuardedNativeGeneration.start(store:h.store,action:a,runtime:f.runtime)
        try f.deliver(h,c,g,a); try a.finish(); a=try f.action(.advance); try g.advance(action:a)
        let frame=try XCTUnwrap(h.store.replay(after:0).first)
        let input=ReplayEnvelope(firstSequence:frame.firstSequence,count:frame.count,providerCommit:frame.providerCommit,eventBytes:frame.eventBytes)
        c.fault={ point in if point == .afterManifestRename { f.receiverClock.advance(10_000_000_001) } }
        XCTAssertThrowsError(try c.accept(input,action:a)); XCTAssertTrue(c.uncertain)
        XCTAssertThrowsError(try c.witness(action:a))
        try a.finish(); let fresh=try f.action(.delivery); c.fault={_ in}
        let selected=try c.witness(action:fresh); XCTAssertEqual(selected.high,UInt64(frame.count)); XCTAssertFalse(c.uncertain)
        try c.accept(input,action:fresh); XCTAssertEqual(try c.witness(action:fresh),selected)
        try h.acceptReceipt(selected,action:fresh); g.close(); try fresh.finish()
    } }
    func testOrdinaryInboxRejectsEffectsBeforeAnyMutation() throws {
        let f=try NativeRecoveryFixture(); _=try f.provision()
        let a=try f.action(.reopen), c=try f.openClient(a); defer { c.close(); try? a.finish() }
        let before=try f.hashes()
        let event=ReachWire.WireEvent.toolCallAppendArguments(entryID:nil,id:"effect",name:"write",content:"{}",tokenCount:1)
        let bytes=try ClientEvents.encode([event])
        XCTAssertThrowsError(try c.accept(.init(firstSequence:1,count:1,providerCommit:String(repeating:"e",count:64),eventBytes:bytes),action:a))
        XCTAssertEqual(try f.hashes(),before)
    }

    func testCurrentRootBlockingChargesOriginalActionAge() throws {
        let f=try NativeRecoveryFixture()
        let owner=try GenerationAuthorityOwner(scope:f.scope,clock:f.receiverClock,validateOwnedRoots:{ f.receiverClock.advance(10_000_000_001) })
        let a=try f.action(.reopen,owner:owner)
        XCTAssertThrowsError(try a.check()); try a.finish()
    }

    func testReplacementPreparedBindingRefusesBeforeAdmissionWrites() throws {
        let f=try NativeRecoveryFixture(), before=try f.hashes()
        var changed=f.provider; changed.operationID="replacement"
        let a=try f.action(.admitHost); defer { try? a.finish() }
        XCTAssertThrowsError(try DurableSessionLifecycle.admitNativeRecovery(at:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:f.hostKeys,scope:f.scope,caller:f.caller,provider:changed,action:a))
        XCTAssertEqual(try f.hashes(),before)
    }

}
