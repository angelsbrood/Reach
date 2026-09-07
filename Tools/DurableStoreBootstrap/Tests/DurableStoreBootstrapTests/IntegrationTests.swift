import XCTest
import Foundation
import DurableRootKeys
import LifecycleFixtures
import HostClientContract
@testable import DurableStoreBootstrap
@testable import DurableSessionLifecycle
@testable import DurableClientReceipts

final class ActualEmptyBootstrap {
    let fixture: BootstrapTestFixture
    let hostClock = SystemLifecycleClock(), clientClock = SystemClientClock()
    let ready: BootstrapReady
    static func keys(_ keys: BootstrapKeys) throws -> LifecycleKeys {
        try keys.key(.hostCatalog).use { catalog in try keys.key(.hostTicket).use { try .init(catalog:catalog,ticket:$0) } }
    }
    init() throws {
        let f = try BootstrapTestFixture(); fixture = f
        let hc = hostClock, cc = clientClock
        ready = try XCTUnwrap(DurableStoreBootstrap.create(optIn:true,at:f.root,container:f.container,policy:f.policy,
            provider:f.factory,initializeStores:{ core,keys in
                let host = try DurableSessionLifecycle.initialize(at:f.root+"/host",
                    identity:LifecycleIdentity(incarnation:core.hostID,clock:hc,quota:core.policy.hostQuota),keys:Self.keys(keys),clock:hc)
                host.close()
                let client = try keys.key(.clientMetadata).use {
                    try DurableClientReceipts(path:f.root+"/client",create:true,
                        environment:ClientEnvironment(rootID:core.clientID,clock:cc,quota:core.policy.clientQuota),metadataKey:$0,clock:cc)
                }
                client.close()
            }))
    }
    func host() throws -> DurableSessionLifecycle {
        let acquired = try fixture.acquire(.host), core = acquired.descriptor.core
        return try .reopen(at:acquired.journal,identity:LifecycleIdentity(incarnation:core.hostID,clock:hostClock,quota:core.policy.hostQuota),
            keys:Self.keys(acquired.keys),clock:hostClock)
    }
    func client() throws -> DurableClientReceipts {
        let acquired = try fixture.acquire(.client), core = acquired.descriptor.core
        return try acquired.keys.key(.clientMetadata).use {
            try .init(path:acquired.journal,create:false,environment:ClientEnvironment(rootID:core.clientID,clock:clientClock,quota:core.policy.clientQuota),metadataKey:$0,clock:clientClock)
        }
    }
}
final class IntegrationTests: XCTestCase {
    func testOriginalTicketAndClientDeadlinesSurviveBootstrapReopen() throws {
        let hc = try FixtureLifecycleClock(id:"s85-host",time:1_000_000_000), cc = try FixtureClientClock(id:"s85-client",time:1_000_000_000)
        let f = try BootstrapTestFixture(policy:.init(boot:RootKeyCodec.boot(),hostClock:hc.policy,clientClock:cc.policy))
        guard let selected = try DurableStoreBootstrap.create(optIn:true,at:f.root,container:f.container,policy:f.policy,
            provider:f.factory,initializeStores:{ core,keys in
                let host = try DurableSessionLifecycle.initialize(at:f.root+"/host",identity:LifecycleIdentity(incarnation:core.hostID,clock:hc,quota:core.policy.hostQuota),keys:ActualEmptyBootstrap.keys(keys),clock:hc)
                host.close()
                let client = try keys.key(.clientMetadata).use { try DurableClientReceipts(path:f.root+"/client",create:true,
                    environment:ClientEnvironment(rootID:core.clientID,clock:cc,quota:core.policy.clientQuota),metadataKey:$0,clock:cc) }
                client.close()
            }) else { throw BootstrapError.disabled }
        func host() throws -> DurableSessionLifecycle {
            let a = try f.acquire(.host)
            return try .reopen(at:a.journal,identity:LifecycleIdentity(incarnation:a.descriptor.core.hostID,clock:hc,quota:f.policy.hostQuota),keys:ActualEmptyBootstrap.keys(a.keys),clock:hc)
        }
        func client() throws -> DurableClientReceipts {
            let a = try f.acquire(.client)
            return try a.keys.key(.clientMetadata).use { try .init(path:a.journal,create:false,
                environment:ClientEnvironment(rootID:a.descriptor.core.clientID,clock:cc,quota:f.policy.clientQuota),metadataKey:$0,clock:cc) }
        }
        let h = try host(), auth = caller(), ticket = try h.issueTicket(authorization:auth,lifetime:1_000_000_000)
        let attachment = try XCTUnwrap(h.begin(ticket:ticket,authorization:auth,generation:"deadline-g",provider:cpuBinding("deadline")).attachment)
        let bytes = try h.exportClientContext(ticket:ticket,authorization:auth,attachment:attachment)
        let authority = try ClientAuthority(HandoffContract.decode(ClientContext.self,bytes,maximum:HandoffContract.context))
        let ca = ClientAuthorization(caller:authority.context.caller), c = try client(), handle = try c.open(authority,authorization:ca)
        let witness = try c.hostWitness(handle,authority:authority,authorization:ca); c.close(); h.close()
        hc.time = authority.context.expires-1; cc.time = hc.time
        let h2 = try host(), c2 = try client(), handle2 = try c2.open(authority,authorization:ca)
        XCTAssertEqual(try c2.hostWitness(handle2,authority:authority,authorization:ca),witness)
        let a2 = try XCTUnwrap(h2.attachClient(ticket:ticket,authorization:auth,generation:"deadline-g",witness:witness,expectedClientRoot:selected.core.clientID).attachment)
        XCTAssertEqual(try h2.exportClientContext(ticket:ticket,authorization:auth,attachment:a2),bytes)
        c2.close(); h2.close(); hc.time = authority.context.expires; cc.time = hc.time
        let h3 = try host(), c3 = try client(); defer { c3.close(); h3.close() }
        XCTAssertThrowsError(try h3.attachClient(ticket:ticket,authorization:auth,generation:"deadline-g",witness:witness,expectedClientRoot:selected.core.clientID))
        XCTAssertThrowsError(try c3.open(authority,authorization:ca))
        XCTAssertTrue(try h3.catalog.load().records.isEmpty); XCTAssertEqual(f.provider.creates,3)
    }
    func testActualEmptyStoresOpenIndependentlyWithOriginalIDs() throws {
        let f = try ActualEmptyBootstrap(), host = try f.host(), client = try f.client()
        defer { client.close(); host.close() }
        XCTAssertEqual(host.catalog.identity.incarnation,f.ready.core.hostID)
        XCTAssertEqual(client.environment.rootID,f.ready.core.clientID)
        XCTAssertEqual(client.environment.quota,f.ready.core.policy.clientQuota)
        XCTAssertGreaterThan(host.ownerEpoch,1); XCTAssertGreaterThan(client.ownerEpoch,1)
        XCTAssertTrue(try host.catalog.load().records.isEmpty)
    }
    func testTicketOnlyReplacementRefusesBeforeActualHostEpochMutation() throws {
        let f = try ActualEmptyBootstrap(), ref = f.ready.core.keys[1], provider = f.fixture.provider
        let before = try f.fixture.bytes("host/current"), id = provider.id(ref), original = try XCTUnwrap(provider.records[id])
        provider.records[id] = (original.0,original.1,try RootKeyCodec.random())
        XCTAssertThrowsError(try f.host())
        XCTAssertEqual(try f.fixture.bytes("host/current"),before)
        let client = try f.client(); client.close()
    }
    func testConsistentlyAlteredClientRootCannotRebindExistingKeys() throws {
        let f = try ActualEmptyBootstrap(), before = try f.fixture.bytes("client/current")
        var changed = f.ready; changed.core.clientID = UUID().uuidString.lowercased()
        try f.fixture.write("intent.json",BootstrapIntent(core:changed.core))
        try f.fixture.write("ready.json",changed)
        XCTAssertThrowsError(try f.client())
        XCTAssertEqual(try f.fixture.bytes("client/current"),before)
    }
}
