import XCTest
import Foundation
import Darwin
import StoreFixtures
@testable import DurableHostStore

final class StoreTests: XCTestCase {
    func testSelectedRootAndCryptoGate() throws {
        let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys)
        let inode = try store.files.scan()["lock"]!.inode
        XCTAssertNotEqual(fcntl(store.files.lock, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertNotEqual(fcntl(store.files.directory, F_GETFD) & FD_CLOEXEC, 0)
        try store.files.syncDirectory()
        XCTAssertEqual(try store.snapshot().high, 0)
        XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: identity, keys: keys)) { XCTAssertEqual($0 as? StoreError, .busy) }
        let record = UUID().uuidString.lowercased(), data = Data("synthetic ciphertext gate".utf8)
        let cipher = try StoreCrypto.seal(data, identity: identity, role: "replay", record: record, epoch: 1, keys: keys)
        let again = try StoreCrypto.seal(data, identity: identity, role: "replay", record: record, epoch: 1, keys: keys)
        XCTAssertNotEqual(cipher, again)
        XCTAssertEqual(try StoreCrypto.open(cipher, identity: identity, role: "replay", record: record, epoch: 1, keys: keys), data)
        XCTAssertThrowsError(try StoreCrypto.open(cipher, identity: identity, role: "replay", epoch: 1, keys: skeys()))
        for role in ["manifest", "candidate"] { XCTAssertThrowsError(try StoreCrypto.open(cipher, identity: identity, role: role, epoch: 1, keys: keys)) }
        XCTAssertThrowsError(try StoreCrypto.open(cipher, identity: identity, role: "replay", epoch: 2, keys: keys))
        XCTAssertThrowsError(try StoreCrypto.open(cipher, identity: identity, role: "replay", record: UUID().uuidString.lowercased(), epoch: 1, keys: keys))
        var swapped = identity; swapped.storeID = UUID().uuidString.lowercased()
        XCTAssertThrowsError(try StoreCrypto.open(cipher, identity: swapped, role: "replay", epoch: 1, keys: keys))
        var tampered = cipher; tampered[tampered.count-1] ^= 1
        XCTAssertThrowsError(try StoreCrypto.open(tampered, identity: identity, role: "replay", epoch: 1, keys: keys))
        XCTAssertThrowsError(try StoreCrypto.open(cipher.prefix(80), identity: identity, role: "replay", epoch: 1, keys: keys))
        XCTAssertNil(cipher.range(of: data))
        store.close(); XCTAssertThrowsError(try store.snapshot())
        let reopened = try DurableHostStore.reopen(at: path, identity: identity, keys: keys)
        defer { reopened.close() }
        XCTAssertEqual(reopened.ownerEpoch, 2)
        XCTAssertEqual(try reopened.files.scan()["lock"]!.inode, inode)
        XCTAssertEqual(setup.factories, 0); XCTAssertEqual(setup.calls, 0)
    }
    func testUnsafeRolesAndInvalidAuthorityNeverCleanOrInitialize() throws {
        for attack in ["unknown", "symlink", "hardlink", "mode", "missing", "truncated", "tampered", "oversized", "files"] {
            let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
            defer { try? FileManager.default.removeItem(atPath: path) }
            let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys)
            let orphan = "b-" + UUID().uuidString.lowercased() + ".bin"
            try store.files.writeNew(orphan, bytes: StoreCrypto.seal(Data(), identity: identity, role: "replay", record: UUID().uuidString.lowercased(), epoch: 1, keys: keys))
            store.close()
            let current = path + "/current"
            switch attack {
            case "unknown": FileManager.default.createFile(atPath: path+"/unexpected", contents: Data(), attributes: [.posixPermissions: 0o600])
            case "symlink": try FileManager.default.removeItem(atPath: current); XCTAssertEqual(symlink("lock", current), 0)
            case "hardlink": XCTAssertEqual(link(current, path+"/t-"+UUID().uuidString.lowercased()+".bin"), 0)
            case "mode": XCTAssertEqual(chmod(current, 0o644), 0)
            case "missing": try FileManager.default.removeItem(atPath: current)
            case "truncated": XCTAssertEqual(truncate(current, 50), 0)
            case "tampered": var bytes = try Data(contentsOf: URL(fileURLWithPath: current)); bytes[bytes.count-1] ^= 1; try bytes.write(to: URL(fileURLWithPath: current))
            case "oversized": XCTAssertEqual(truncate(current, off_t(StoreLimits.candidate+117)), 0)
            default:
                for _ in 0..<16 { FileManager.default.createFile(atPath: path+"/b-"+UUID().uuidString.lowercased()+".bin", contents: Data(), attributes: [.posixPermissions: 0o600]) }
            }
            XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: identity, keys: keys), attack)
            XCTAssertTrue(FileManager.default.fileExists(atPath: path+"/"+orphan), attack)
            XCTAssertThrowsError(try DurableHostStore.initialize(at: path, identity: identity, keys: keys), attack)
            XCTAssertEqual(setup.factories, 0)
        }
    }
    func testManifestSchemaEpochBootBindingAndKeyRefusal() throws {
        let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys)
        let original = try store.files.read("current", maximum: StoreLimits.manifest)
        var manifest = try store.load().manifest
        store.close()
        var changed = identity; changed.bootID = UUID().uuidString.lowercased()
        XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: changed, keys: keys))
        changed = identity; changed.provider.requestID += "-changed"
        XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: changed, keys: keys))
        XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: identity, keys: skeys()))
        for invalid in ["version", "epoch", "boot", "high"] {
            manifest = try JSONDecoder().decode(StoreManifest.self, from: StoreCrypto.open(original, identity: identity, role: "manifest", epoch: nil, keys: keys))
            switch invalid { case "version": manifest.version = 2; case "epoch": manifest.epoch = .max; case "boot": manifest.bootID = "wrong"; default: manifest.high = UInt64(StoreLimits.events+1) }
            let cipher = try StoreCrypto.seal(storeEncode(manifest), identity: identity, role: "manifest", record: UUID().uuidString.lowercased(), epoch: nil, keys: keys)
            try cipher.write(to: URL(fileURLWithPath: path+"/current"))
            XCTAssertThrowsError(try DurableHostStore.reopen(at: path, identity: identity, keys: keys), invalid)
        }
        XCTAssertEqual(setup.factories, 0)
    }
    func testClosedAndAuthenticatedStaleEpoch() throws {
        let setup = try PFSetup("ordinary"), identity = try StoreIdentity(provider: setup.binding), keys = try skeys(), path = fixturePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try DurableHostStore.initialize(at: path, identity: identity, keys: keys)
        var manifest = try store.load().manifest; manifest.epoch += 1
        let cipher = try StoreCrypto.seal(storeEncode(manifest), identity: identity, role: "manifest", record: UUID().uuidString.lowercased(), epoch: nil, keys: keys)
        try cipher.write(to: URL(fileURLWithPath: path+"/current"))
        XCTAssertThrowsError(try store.reserve()) { XCTAssertEqual($0 as? StoreError, .stale) }
        XCTAssertThrowsError(try store.replay(after: 0)) { XCTAssertEqual($0 as? StoreError, .stale) }
        store.close(); XCTAssertThrowsError(try store.reconcile()) { XCTAssertEqual($0 as? StoreError, .closed) }
        XCTAssertEqual(setup.factories, 0)
    }
    func testBinaryReplayBoundsAndTerminalOrder() throws {
        let bytes = try encoder().encode([ReachWire.WireEvent.finished(.complete)])
        var replay = StoreReplay()
        replay.batches = [.init(first: 1, count: 1, ordinal: 1, commit: String(repeating: "a", count: 64), bytes: bytes)]
        XCTAssertEqual(try replay.encoded().count, 4+88+bytes.count)
        XCTAssertEqual(try StoreReplay(data: replay.encoded()).high, 1)
        for field in ["first", "count", "ordinal", "length", "duplicate", "afterterminal"] {
            var wrong = replay
            switch field {
            case "first": wrong.batches[0].first = .max
            case "count": wrong.batches[0].count = 4097
            case "ordinal": wrong.batches[0].ordinal = 4096
            case "length": wrong.batches[0].bytes = Data("[".utf8)
            case "duplicate": wrong.batches.append(wrong.batches[0])
            default: wrong.batches.append(.init(first: 2, count: 1, ordinal: 2, commit: String(repeating: "b", count: 64), bytes: bytes))
            }
            XCTAssertThrowsError(try StoreReplay(data: wrong.encoded()), field)
        }
        XCTAssertThrowsError(try StoreReplay(data: storeUInt(UInt32.max)))
        XCTAssertThrowsError(try replay.frames(after: 2))
    }
}
import ReachWire
