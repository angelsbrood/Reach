import XCTest
import Foundation
import Darwin
import StoreFixtures
import ResumableMLXProvider
@testable import DurableHostStore

final class StoreRecoveryTests: XCTestCase {
    func testCommitUncertaintyUsesDiskAuthorityAndExactRetry() throws {
        for cut in [StoreFaultPoint.afterCandidateBlob, .afterReplayBlob, .beforeManifestReplace, .afterManifestReplace, .beforeDirectorySync] {
            let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
            defer { try? FileManager.default.removeItem(atPath: path) }
            let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys), provider = try setup.prepare(owner: store.ownerToken)
            defer { provider.close(); store.close() }
            let c0 = try XCTUnwrap(provider.pendingCandidate())
            store.fault = { if $0 == cut { throw StoreError.io("injected IO failure", EIO) } }
            XCTAssertThrowsError(try store.commit(c0))
            XCTAssertEqual(try provider.pendingCandidate()?.data, c0.data)
            let replaced = cut == .afterManifestReplace || cut == .beforeDirectorySync
            if replaced {
                XCTAssertTrue(store.uncertain)
                XCTAssertThrowsError(try store.replay(after: 0)); XCTAssertThrowsError(try store.reserve())
                XCTAssertEqual(try store.load(allowUncertain: true).candidate?.data, c0.data)
                store.fault = { _ in }
                XCTAssertEqual(try store.commit(c0).candidate?.data, c0.data)
                XCTAssertFalse(store.uncertain)
            } else {
                XCTAssertNil(try store.snapshot().candidate)
                XCTAssertTrue(try store.replay(after: 0).isEmpty)
                store.close()
                let reopened = try DurableHostStore.reopen(at: path, identity: identity, keys: keys)
                XCTAssertNil(try reopened.snapshot().candidate)
                XCTAssertEqual(try reopened.files.scan().count, 2)
                reopened.close()
            }
        }
        // Force an actual renameat failure, rather than only a thrown sync hook.
        let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys), provider = try setup.prepare(owner: store.ownerToken)
        defer { provider.close(); store.close() }
        let c0 = try XCTUnwrap(provider.pendingCandidate())
        store.fault = { point in
            if point == .beforeManifestReplace {
                let temporary = try XCTUnwrap(store.files.scan().keys.first { $0.hasPrefix("t-") })
                XCTAssertEqual(unlinkat(store.files.directory, temporary, 0), 0)
            }
        }
        XCTAssertThrowsError(try store.commit(c0)) { XCTAssertEqual($0 as? StoreError, .io("manifest replacement", ENOENT)) }
        XCTAssertTrue(store.uncertain); XCTAssertThrowsError(try store.replay(after: 0))
        XCTAssertNil(try store.reconcile().candidate)
        XCTAssertFalse(store.uncertain); XCTAssertEqual(try store.files.scan().count, 2)
        store.fault = { _ in }
        XCTAssertEqual(try store.commit(c0).candidate?.data, c0.data)
    }
    func testStaleParentEmptyStepsAndReferencedCorruption() throws {
        let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys), provider = try setup.prepare(owner: store.ownerToken)
        let c0 = try XCTUnwrap(provider.pendingCandidate()); try store.commit(c0); try provider.acceptCommit(c0.commit, owner: store.ownerToken)
        let next = try XCTUnwrap(provider.advance(owner: store.ownerToken, current: c0.commit, credit: ResumableMLXProvider.reservationBytes))
        try store.commit(next); try provider.acceptCommit(next.commit, owner: store.ownerToken)
        XCTAssertNotEqual(c0.checkpointBytes, next.checkpointBytes)
        XCTAssertEqual(try store.commit(next).candidate?.data, next.data)
        XCTAssertThrowsError(try store.commit(c0))
        let loaded = try store.load(), ref = try XCTUnwrap(loaded.manifest.candidate)
        provider.close(); store.close()
        let original = try Data(contentsOf: URL(fileURLWithPath: path+"/"+ref.name))
        for attack in ["missing", "truncated", "tampered", "role"] {
            let url = URL(fileURLWithPath: path+"/"+ref.name)
            try original.write(to: url); XCTAssertEqual(chmod(url.path, 0o600), 0)
            switch attack {
            case "missing": try FileManager.default.removeItem(at: url)
            case "truncated": XCTAssertEqual(truncate(url.path, 90), 0)
            case "tampered": var data = original; data[data.count-1] ^= 1; try data.write(to: url)
            default: try Data(contentsOf: URL(fileURLWithPath: path+"/"+loaded.manifest.replay!.name)).write(to: url)
            }
            XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: identity, keys: keys), attack)
        }
    }
    func testRealAllocatedQuotaPausesBeforeFactory() throws {
        let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys)
        defer { store.close() }
        // Valid encrypted orphan roles, never plaintext filler or a mocked quota.
        for _ in 0..<2 {
            let record = UUID().uuidString.lowercased()
            let cipher = try StoreCrypto.seal(Data(repeating: 0, count: 156*1024*1024), identity: identity, role: "candidate", record: record, epoch: 1, keys: keys)
            try store.files.writeNew("b-"+record+".bin", bytes: cipher)
        }
        XCTAssertGreaterThan(try store.files.scan().values.reduce(0) { $0+$1.allocated }, StoreLimits.allocation-StoreLimits.reservation)
        var runtimeCalls = 0
        XCTAssertThrowsError(try DurableGeneration.start(store: store) { runtimeCalls += 1; return setup.runtime }) { XCTAssertEqual($0 as? StoreError, .full) }
        XCTAssertEqual(runtimeCalls, 0); XCTAssertEqual(setup.factories, 0)
        store.close()
        let recovered = try DurableHostStore.reopen(at: path, identity: identity, keys: keys)
        XCTAssertEqual(try recovered.files.scan().count, 2)
        try recovered.reserve(); recovered.close()
    }
}
