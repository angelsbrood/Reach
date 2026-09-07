import XCTest
import Foundation
import Darwin
import LifecycleFixtures
@testable import DurableSessionLifecycle

final class LifecycleRecoveryTests: XCTestCase {
    func testLaterExpiredRetirementPrunesIdentityBeforeFallibleCleanup() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "later-expiry", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
        let binding = try cpuBinding(), ticket = try owner.issueTicket(authorization: auth, lifetime: 1000), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding).attachment)
        owner.fault = { if $0 == .afterPreparing { throw LifecycleError.io("empty child", EIO) } }
        XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("cleanup factory"); throw LifecycleError.invalid("runtime") })
        owner.fault = { if $0 == .afterRetirementIntent { throw LifecycleError.io("intent", EIO) } }
        XCTAssertThrowsError(try owner.cancel(ticket: ticket, authorization: auth, attachment: a))
        XCTAssertNotNil(try owner.catalog.load().records[0].identity)
        clock.time = 1100
        owner.fault = { if $0 == .duringContentDeletion { throw LifecycleError.io("cleanup", EIO) } }
        XCTAssertThrowsError(try owner.maintenance()) { XCTAssertEqual($0 as? LifecycleError, .io("cleanup", EIO)) }
        let pending = try owner.catalog.load().records[0]
        XCTAssertTrue(pending.identity == nil); XCTAssertTrue(pending.work == nil); XCTAssertNotNil(pending.cleanup); XCTAssertEqual(pending.phase, .retiring)
        XCTAssertThrowsError(try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding)) { XCTAssertEqual($0 as? LifecycleError, .expired) }
        let next = try owner.issueTicket(authorization: auth)
        XCTAssertThrowsError(try owner.begin(ticket: next, authorization: auth, generation: "new", provider: cpuBinding("new")))
        XCTAssertTrue(try owner.catalog.load().records[0].identity == nil)
        owner.fault = { _ in }; try owner.maintenance(); try owner.maintenance()
        XCTAssertTrue(try owner.catalog.load().records.isEmpty)
        XCTAssertTrue(try owner.catalog.files.children.names(maximum: 64, allowed: LifecycleFileSystem.childRole).isEmpty)
        XCTAssertTrue(try owner.catalog.files.requests.names(maximum: 65, allowed: LifecycleFileSystem.requestRole).isEmpty)
        XCTAssertThrowsError(try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding))
    }
    func testExpiryDuringIntentSyncRefusesProviderFactory() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "intent-expiry", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
        let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: cpuBinding()).attachment)
        var crossed = false
        owner.fault = { point in
            if point == .afterCatalogRename, !crossed,
               try owner.catalog.load(allowUncertain: true).records[0].work?.times.transitionStartedAt != nil {
                crossed = true; clock.time = 100+LifecycleLimits.inflight
            }
        }
        let result = try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("expiry before factory"); throw LifecycleError.expired }
        owner.fault = { _ in }
        XCTAssertTrue(crossed); XCTAssertEqual(result.phase, .tombstone); XCTAssertNil(result.providerEnding)
        XCTAssertEqual(result.disposition, "inflight-expired"); XCTAssertEqual(result.high, 0)
    }
    func testCatalogRenameUncertaintyAndNoFallback() throws {
        for point in [LifecycleFault.beforeCatalogRename, .afterCatalogRename, .beforeCatalogSync] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "catalog", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock)
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
            owner.fault = { if $0 == point { throw LifecycleError.io("injected catalog IO", EIO) } }
            clock.time = 101
            XCTAssertThrowsError(try owner.issueTicket(authorization: caller()))
            if point != .beforeCatalogRename { XCTAssertTrue(owner.uncertain); XCTAssertThrowsError(try owner.catalog.load()) }
            owner.fault = { _ in }; try owner.maintenance()
            XCTAssertFalse(owner.uncertain); XCTAssertEqual(try owner.catalog.load().lastObserved, 101)
            XCTAssertFalse(try owner.catalog.files.root.exists("prepared")); owner.close()
            let current = URL(fileURLWithPath: path+"/current")
            var bytes = try Data(contentsOf: current); bytes[bytes.count-1] ^= 1; try bytes.write(to: current)
            XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock))
            XCTAssertThrowsError(try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock))
        }
    }
    func testAllocationRetryAndPreparingMissingAuthorityNeverStarts() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "allocate", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); defer { owner.close() }
        let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: cpuBinding()).attachment)
        owner.fault = { if $0 == .afterDirectoryCreated { throw LifecycleError.io("allocation cut", EIO) } }
        XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("allocation invoked runtime"); throw LifecycleError.invalid("runtime") })
        owner.fault = { if $0 == .afterPreparing { throw LifecycleError.io("empty-child cut", EIO) } }
        XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("empty child invoked runtime"); throw LifecycleError.invalid("runtime") })
        owner.fault = { _ in }
        let r = try owner.catalog.load().records[0]
        XCTAssertEqual(r.phase, .preparing)
        owner.closeChildren()
        let child = try owner.catalog.files.childPath(r.work!.child)
        XCTAssertEqual(unlink(child+"/current"), 0)
        try owner.maintenance()
        XCTAssertTrue(try owner.catalog.load().records[0].nonResumable)
        XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("missing preparing authority invoked runtime"); throw LifecycleError.invalid("runtime") })
        let retired = try owner.cancel(ticket: ticket, authorization: auth, attachment: a)
        XCTAssertEqual(retired.phase, .tombstone)
        XCTAssertFalse(FileManager.default.fileExists(atPath: child))
    }
    func testUnsafeRolesRefuseWithoutDeletion() throws {
        for kind in ["unknown", "symlink", "hardlink", "mode", "missing"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "unsafe", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock)
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock); owner.close()
            switch kind {
            case "unknown": FileManager.default.createFile(atPath: path+"/unknown", contents: Data(), attributes: [.posixPermissions: 0o600])
            case "symlink": XCTAssertEqual(unlink(path+"/current"), 0); XCTAssertEqual(symlink("lock", path+"/current"), 0)
            case "hardlink": XCTAssertEqual(link(path+"/current", path+"/prepared"), 0)
            case "mode": XCTAssertEqual(chmod(path+"/current", 0o644), 0)
            default: XCTAssertEqual(unlink(path+"/current"), 0)
            }
            XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock), kind)
            if kind == "unknown" { XCTAssertTrue(FileManager.default.fileExists(atPath: path+"/unknown")) }
        }
    }
    func testDamagedChildRetirementAndDurableKeyRemoval() throws {
        for kind in ["ciphertext", "unsafe"] {
            let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: kind, time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
            defer { try? FileManager.default.removeItem(atPath: path) }
            let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
            let binding = try cpuBinding(), ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding).attachment)
            owner.fault = { if $0 == .afterPreparing { throw LifecycleError.io("empty", EIO) } }
            XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("CPU cleanup factory"); throw LifecycleError.invalid("runtime") })
            owner.fault = { _ in }; owner.closeChildren()
            let record = try owner.catalog.load().records[0], child = try owner.catalog.files.childPath(record.work!.child)
            if kind == "unsafe" {
                let unknown = child+"/unrelated"
                XCTAssertTrue(FileManager.default.createFile(atPath: unknown, contents: Data([1]), attributes: [.posixPermissions: 0o600]))
                XCTAssertThrowsError(try owner.cancel(ticket: ticket, authorization: auth, attachment: a))
                XCTAssertTrue(FileManager.default.fileExists(atPath: unknown)); owner.close()
                continue
            }
            var cipher = try Data(contentsOf: URL(fileURLWithPath: child+"/current")); cipher[cipher.count-1] ^= 1
            try cipher.write(to: URL(fileURLWithPath: child+"/current"))
            try owner.maintenance(); XCTAssertTrue(try owner.catalog.load().records[0].nonResumable)
            owner.fault = { if $0 == .afterRetirementIntent { throw LifecycleError.io("retirement intent", EIO) } }
            XCTAssertThrowsError(try owner.cancel(ticket: ticket, authorization: auth, attachment: a))
            let retiring = try owner.catalog.load().records[0]
            XCTAssertEqual(retiring.phase, .retiring); XCTAssertNil(retiring.work); XCTAssertNotNil(retiring.cleanup)
            XCTAssertFalse(try owner.catalog.files.root.exists("prepared")); owner.close()
            let recovered = try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock); defer { recovered.close() }
            let result = try recovered.begin(ticket: ticket, authorization: auth, generation: "g", provider: binding)
            XCTAssertEqual(result.phase, .tombstone); XCTAssertNil(result.attachment)
            XCTAssertFalse(FileManager.default.fileExists(atPath: child))
            XCTAssertTrue(try recovered.catalog.files.requests.names(maximum: 65, allowed: LifecycleFileSystem.requestRole).isEmpty)
        }
    }
    func testCatalogSchemaEpochOverflowOrphansAndRequestBindingRefusal() throws {
        let path = lifecyclePath(), clock = try FixtureLifecycleClock(id: "schema", time: 100), keys = try lifecycleKeys(), identity = try LifecycleIdentity(clock: clock), auth = caller()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let owner = try DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
        let ticket = try owner.issueTicket(authorization: auth), a = try XCTUnwrap(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: cpuBinding()).attachment)
        let original = try owner.catalog.load()
        for change in ["version", "queue", "epoch", "alias", "keys", "terminal"] {
            var d = original
            switch change {
            case "version": d.version = 2
            case "queue": d.records[0].work!.times.queueUntil += 1
            case "epoch": d.epoch = 0
            case "alias": d.records.append(d.records[0])
            case "keys": d.records[0].work!.keys.content = d.records[0].work!.keys.metadata
            default: d.records[0].work!.times.terminalUntil = 1
            }
            XCTAssertThrowsError(try d.validate(identity), change)
        }
        let orphan = LifecycleFileSystem.requestName(UUID().uuidString.lowercased())
        try owner.catalog.files.requests.writeNew(orphan, bytes: Data([1,2,3]), maximum: LifecycleLimits.request)
        try owner.maintenance(); XCTAssertFalse(try owner.catalog.files.requests.exists(orphan))
        let name = LifecycleFileSystem.requestName(original.records[0].work!.request)
        var cipher = try owner.catalog.files.requests.read(name, maximum: LifecycleLimits.request)
        cipher[cipher.count-1] ^= 1
        try cipher.write(to: URL(fileURLWithPath: path+"/requests/"+name))
        try owner.maintenance(); XCTAssertTrue(try owner.catalog.load().records[0].nonResumable)
        XCTAssertThrowsError(try owner.step(ticket: ticket, authorization: auth, attachment: a) { XCTFail("corrupt request factory"); throw LifecycleError.invalid("runtime") })
        _ = try owner.cancel(ticket: ticket, authorization: auth, attachment: a)
        var epochMax = try owner.catalog.load(); epochMax.epoch = .max
        let bytes = try LifecycleCrypto.seal(lcEncode(epochMax), role: "catalog", record: UUID().uuidString.lowercased(), identity: identity, key: keys.catalog)
        try bytes.write(to: URL(fileURLWithPath: path+"/current")); owner.close()
        XCTAssertThrowsError(try DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock))
    }
}
