import Foundation
import XCTest
import CryptoKit
import ClockPolicy
import RecoveryAuthorityContract
import DurableRootKeys
import DurableStoreBootstrap
import RecoveryContract
import WireAdapterContract
@testable import DurableHostStore
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts
@testable import ReachDurableRuntime

final class RecoveryAuthorityTests: XCTestCase {
    func testActualRecordsDuplicateAdmissionAndReadOnlyFreshReceiver() throws {
        let f=try RecoveryAuthorityFixture(), issued=try f.admit(); try f.accept(issued)
        let before=try f.hashes()
        XCTAssertEqual(try f.admit(),issued); try f.accept(issued)
        XCTAssertEqual(try f.hashes(),before)
        let rebooted=AuthorityFixtureClock(time:1_000_000_000)
        let host=try f.authenticate("host",action:f.action(.authenticateHost,clock:rebooted))
        let client=try f.authenticate("client",action:f.action(.authenticateClient,clock:rebooted))
        XCTAssertEqual(host.phase,"preparing"); XCTAssertEqual(client.phase,"registered-empty")
        XCTAssertEqual(host.admission,client.admission); XCTAssertEqual(host.ticket,client.ticket)
        XCTAssertNotEqual(host.evaluation.r.boot,f.scope.host.boot)
        XCTAssertEqual(try f.hashes(),before)
    }
    func testFreshLowerBoundDoesNotRebaseStoredAnchors() throws {
        let f=try RecoveryAuthorityFixture(), issued=try f.admit(); try f.accept(issued)
        let before=try f.hashes(), action=try f.action(.authenticateHost)
        f.receiverClock.advance(8_000_000_000)
        let uncertain=try action.check(scope:f.scope,operation:.authenticateHost); try action.finish()
        f.witnessClock.advance(1_000_000_000)
        let fresh=try f.authenticate("host")
        XCTAssertLessThan(fresh.evaluation.upper,uncertain.upper)
        XCTAssertEqual(fresh.evaluation.hostDeadline,190_000_000_000)
        XCTAssertEqual(fresh.evaluation.clientDeadline,250_000_000_000)
        XCTAssertEqual(try f.hashes(),before)
    }
    func testHostAndClientExpiryAreIndependentAndStrict() throws {
        for caps in [(UInt64(30),UInt64(90)),(90,30)] {
            let f=try RecoveryAuthorityFixture(hostCap:caps.0,clientCap:caps.1), issued=try f.admit(); try f.accept(issued)
            let before=try f.hashes(); f.witnessClock.advance(29_000_000_000)
            for role in ["host","client"] { XCTAssertThrowsError(try f.authenticate(role)) }
            XCTAssertEqual(try f.hashes(),before)
        }
    }
    func testBlockingReadChargesOriginalSendAgeBeforePublication() throws {
        for role in ["host","client"] {
            let f=try RecoveryAuthorityFixture(), issued=try f.admit(); try f.accept(issued)
            let before=try f.hashes(); var published=false
            XCTAssertThrowsError(try {
                _=try f.authenticate(role,blocking:{ f.receiverClock.advance(10_000_000_001) }); published=true
            }())
            XCTAssertFalse(published); XCTAssertEqual(try f.hashes(),before)
        }
    }
    func testObservedWitnessLossAndReplacementNeverPublish() throws {
        for role in ["host","client"] {
            let f=try RecoveryAuthorityFixture(), issued=try f.admit(); try f.accept(issued)
            let before=try f.hashes(), a=try f.action(role == "host" ? .authenticateHost : .authenticateClient)
            XCTAssertThrowsError(try f.authenticate(role,action:a,blocking:{ a.observeWitnessLoss() }))
            XCTAssertEqual(try f.hashes(),before)
            let replacement=try Witness(clock:f.witnessClock)
            let b=try f.action(role == "host" ? .authenticateHost : .authenticateClient)
            XCTAssertThrowsError(try b.observeWitnessIdentity(replacement.identity))
            XCTAssertThrowsError(try f.authenticate(role,action:b))
        }
    }
    func testLocalActionScopeOperationFinishAndResponseReplay() throws {
        let f=try RecoveryAuthorityFixture(), g=try RecoveryAuthorityFixture(), a=try f.action(.authenticateHost)
        XCTAssertThrowsError(try a.check(scope:g.scope,operation:.authenticateHost))
        XCTAssertThrowsError(try a.check(scope:f.scope,operation:.authenticateClient))
        try a.finish(); XCTAssertThrowsError(try a.check(scope:f.scope,operation:.authenticateHost))
        let b=try RecoveryAuthorityAction(scope:f.scope,operation:.authenticateHost,clock:f.receiverClock)
        let response=try f.witness.respond(to:b.request); try b.receive(response)
        XCTAssertThrowsError(try b.receive(response))
        let c=try RecoveryAuthorityAction(scope:f.scope,operation:.authenticateHost,clock:f.receiverClock)
        XCTAssertThrowsError(try c.receive(response))
        XCTAssertThrowsError(try c.check(scope:f.scope,operation:.authenticateHost))
    }
    func testPartialAdmissionAndRegistrationNeverRepairOrReadmit() throws {
        for point in [LifecycleFault.afterAllocating,.afterEmptyChild] {
            let f=try RecoveryAuthorityFixture()
            XCTAssertThrowsError(try f.admit(fault:{ if $0 == point { throw AuthorityError.partial } }))
            let before=try f.hashes(); XCTAssertThrowsError(try f.admit()); XCTAssertEqual(try f.hashes(),before)
        }
        let f=try RecoveryAuthorityFixture(), issued=try f.admit()
        XCTAssertThrowsError(try f.accept(issued,fault:{ if $0 == .afterManifest { throw AuthorityError.partial } }))
        let before=try f.hashes(); XCTAssertThrowsError(try f.accept(issued)); XCTAssertThrowsError(try f.authenticate("client"))
        XCTAssertEqual(try f.hashes(),before)
    }
    func testAuthenticatedActiveTerminalAndNonResumableStateRefuse() throws {
        for phase in [LifecyclePhase.active,.recovering,.terminal] {
            let f=try RecoveryAuthorityFixture(); _=try f.admit()
            try f.catalog { $0.records[0].phase=phase }
            let before=try f.hashes(); XCTAssertThrowsError(try f.authenticate("host")); XCTAssertEqual(try f.hashes(),before)
        }
        let f=try RecoveryAuthorityFixture(); _=try f.admit(); try f.catalog { $0.records[0].nonResumable=true }
        XCTAssertThrowsError(try f.authenticate("host"))
    }
    func testAuthenticatedClientEffectsAndRevisionAdvancementRefuse() throws {
        for calls in [0,1] {
            let f=try RecoveryAuthorityFixture(), issued=try f.admit(); try f.accept(issued)
            try f.clientManifest { m in if calls == 1 { m.records[0].live!.calls=1 } else { m.ownerEpoch=2 } }
            let before=try f.hashes(); XCTAssertThrowsError(try f.authenticate("client")); XCTAssertEqual(try f.hashes(),before)
        }
    }
    func testStoreCandidateReplayAndOrphanPresenceRefuseBeforeUse() throws {
        let f=try RecoveryAuthorityFixture(), issued=try f.admit()
        let a=try f.acceptance(issued).admission(), folder=f.host+"/bootstrap/host/children/g-"+a.store
        try LocalFiles.writeNew(Data([0]),to:folder+"/b-"+UUID().uuidString.lowercased()+".bin")
        let before=try f.hashes(); XCTAssertThrowsError(try f.authenticate("host")); XCTAssertEqual(try f.hashes(),before)
    }
    func testWrongOriginalKeysAndSwappedAuthenticatedCatalogRefuse() throws {
        let f=try RecoveryAuthorityFixture(), g=try RecoveryAuthorityFixture(); _=try f.admit(); _=try g.admit()
        let action=try f.action(.authenticateHost)
        XCTAssertThrowsError(try DurableSessionLifecycle.authenticateRecoveryAuthority(at:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:g.hostKeys,scope:f.scope,action:action))
        let replacement=try Data(contentsOf:URL(fileURLWithPath:g.host+"/bootstrap/host/current"))
        try replacement.write(to:URL(fileURLWithPath:f.host+"/bootstrap/host/current"))
        XCTAssertThrowsError(try f.authenticate("host"))
    }
    func testOriginalIssuerAndExportDigestAreRequiredForFirstAcceptance() throws {
        let f=try RecoveryAuthorityFixture(), g=try RecoveryAuthorityFixture(), issued=try f.admit()
        let digest=try AuthorityCodec.digest(issued)
        XCTAssertThrowsError(try AuthorityAcceptance(issued:issued,originalIssuer:AuthorityIssued.issuerKey(ticketKey:g.clientKey).publicKey.rawRepresentation,originalSuccessfulExportDigest:digest))
        XCTAssertThrowsError(try AuthorityAcceptance(issued:issued,originalIssuer:AuthorityIssued.issuerKey(ticketKey:f.ticketKey).publicKey.rawRepresentation,originalSuccessfulExportDigest:String(repeating:"0",count:64)))
        let a=try g.action(.acceptClient)
        XCTAssertThrowsError(try DurableClientReceipts.acceptRecoveryAuthority(at:g.client+"/bootstrap/client",parent:g.client,environment:g.clientEnvironment,metadataKey:g.clientKey,acceptance:f.acceptance(issued),action:a))
    }
    func testVersionedTicketTamperRefusesEvenWithReSignedExport() throws {
        let f=try RecoveryAuthorityFixture(), issued=try f.admit(), original=try f.acceptance(issued).admission()
        var ticket=original.ticket; ticket[ticket.count-1] ^= 1
        let forged=try AuthorityAdmission(scope:original.scope,ticket:ticket,context:original.context,requestDigest:original.requestDigest,providerDigest:original.providerDigest,record:original.record,store:original.store)
        try f.catalog { $0.admission=try AuthorityIssued(forged,ticketKey:f.ticketKey) }
        XCTAssertThrowsError(try f.authenticate("host"))
    }
    func testOrdinaryAcquisitionAndWireProfileRefuseNewAuthority() throws {
        let f=try RecoveryAuthorityFixture()
        XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at:f.host+"/bootstrap/host",identity:f.hostIdentity,keys:f.hostKeys,clock:SystemLifecycleClock()))
        XCTAssertThrowsError(try DurableClientReceipts(path:f.client+"/bootstrap/client",create:false,environment:f.clientEnvironment,metadataKey:f.clientKey,clock:SystemClientClock()))
        XCTAssertThrowsError(try AdapterConfiguration(dialect:2,model:"local-llama-258-v1",profile:AuthorityCodec.profile,optIn:true,ready:true).validate())
        let b=try RecoveryBinding(recoveryAuthority:f.scope)
        XCTAssertTrue(b.authorityOnly); XCTAssertFalse(b.independent); XCTAssertEqual(try b.envelopeVersion,3)
    }
    func testOrdinaryReaderRejectsAuthenticatedMixedVersionManifest() throws {
        let f=try RecoveryAuthorityFixture(), path=f.base+"/ordinary-mixed"
        let identity=try StoreIdentity(provider:f.provider)
        let keys=try StoreKeys(metadata:Data(repeating:1,count:32),content:Data(repeating:2,count:32))
        let original=try DurableHostStore.initialize(at:path,identity:identity,keys:keys); original.close()
        let current=URL(fileURLWithPath:path+"/current")
        let plain=try StoreCrypto.open(Data(contentsOf:current),identity:identity,role:"manifest",epoch:nil,keys:keys)
        var manifest=try JSONDecoder().decode(StoreManifest.self,from:plain)
        XCTAssertEqual(manifest.version,1); XCTAssertNil(manifest.authority)
        manifest.authority=try f.scope.digest
        let mixed=try storeEncode(manifest)
        // Authentic legacy framing/AAD with a canonical, incompatible body:
        // rejection must occur in the ordinary schema reader, after decryption.
        let cipher=try StoreCrypto.seal(mixed,identity:identity,role:"manifest",record:UUID().uuidString.lowercased(),epoch:nil,keys:keys)
        XCTAssertEqual(cipher.prefix(8),Data("S81GCM01".utf8))
        XCTAssertEqual(try StoreCrypto.open(cipher,identity:identity,role:"manifest",epoch:nil,keys:keys),mixed)
        try cipher.write(to:current)
        let before=try f.hashes()
        do {
            let reopened=try DurableHostStore.reopen(at:path,identity:identity,keys:keys); reopened.close()
            XCTFail("Ordinary reader accepted an authenticated v1 manifest with authority metadata")
            return
        } catch { XCTAssertEqual(error as? StoreError,.invalid("authenticated manifest declaration")) }
        XCTAssertEqual(try f.hashes(),before)
    }
    func testOrdinaryEmptyStoreReopensWithoutAuthorityMetadata() throws {
        let f=try RecoveryAuthorityFixture(), path=f.base+"/ordinary-empty"
        let identity=try StoreIdentity(provider:f.provider)
        let keys=try StoreKeys(metadata:Data(repeating:1,count:32),content:Data(repeating:2,count:32))
        let original=try DurableHostStore.initialize(at:path,identity:identity,keys:keys)
        XCTAssertEqual(try original.snapshot().epoch,1); original.close()
        let reopened=try DurableHostStore.reopen(at:path,identity:identity,keys:keys); defer { reopened.close() }
        let snapshot=try reopened.snapshot()
        XCTAssertEqual(snapshot.epoch,2); XCTAssertEqual(snapshot.high,0)
        XCTAssertNil(snapshot.candidate); XCTAssertFalse(snapshot.terminal)
        XCTAssertTrue(try reopened.replay(after:0).isEmpty)
        let plain=try StoreCrypto.open(Data(contentsOf:URL(fileURLWithPath:path+"/current")),identity:identity,role:"manifest",epoch:nil,keys:keys)
        let manifest=try JSONDecoder().decode(StoreManifest.self,from:plain)
        XCTAssertEqual(manifest.version,1); XCTAssertNil(manifest.authority)
        XCTAssertEqual(try storeEncode(manifest),plain)
    }
    func testNewBootstrapReceiptUsesOriginalKeysAndOrdinaryRefusal() throws {
        let f=try RecoveryAuthorityFixture(), root=try LifecycleFixture(unlock:true,authority:f.scope.provision)
        XCTAssertEqual(root.core.version,4)
        let receipt=try RoleOwnershipReceipt(ready:root.ready); XCTAssertEqual(receipt.version,2)
        XCTAssertThrowsError(try RoleBootstrapStore.inspect(at:root.root,role:.client))
        XCTAssertThrowsError(try RoleLifecycleLease.acquire(ready:root.ready))
        let (_,lease)=try RoleLifecycleLease.selectRecoveryAuthority(receipt:root.receipt,expectedDigest:XCTUnwrap(root.digest)); defer { lease.close() }
        _=try RoleBootstrapStore.acquireRecoveryAuthority(ready:root.ready,lease:lease,provider:root.provider)
        XCTAssertEqual(root.provider.creates,1); XCTAssertEqual(root.provider.loads,1)
        XCTAssertThrowsError(try RoleLifecycleLease.selectRecoveryAuthority(receipt:root.receipt,expectedDigest:XCTUnwrap(root.digest)))
        let reference=try root.core.reference(.clientMetadata)
        root.provider.values[reference.identifier]=(try root.core.binding(),try RootKeyMaterial(Data(repeating:0,count:32)))
        XCTAssertThrowsError(try RoleBootstrapStore.acquireRecoveryAuthority(ready:root.ready,lease:lease,provider:root.provider))
    }
}
