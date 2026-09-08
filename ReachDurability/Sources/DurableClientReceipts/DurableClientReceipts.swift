import Foundation
import CryptoKit

/// One serial synchronous owner; no concurrent calls or reentrant hooks. Does not execute effects.
public final class DurableClientReceipts {
    let fs: ClientFileSystem, environment: ClientEnvironment, rootKey: SymmetricKey
    let clock: any ClientClock
    var hook: ClientFaultHook
    var observed: UInt64 = 0
    var uncertain = false
    public private(set) var ownerEpoch: UInt64 = 0
    public init(path: String, create: Bool, environment: ClientEnvironment, metadataKey: Data,
                clock: any ClientClock, hook: @escaping ClientFaultHook = { _ in }) throws {
        guard metadataKey.count == 32 else { throw ClientError.unavailable }
        try environment.validate(clock); self.environment = environment; rootKey = SymmetricKey(data: metadataKey)
        self.clock = clock; self.hook = hook; fs = try ClientFileSystem(path: path, create: create)
        do {
            var m: ClientManifest
            if create {
                m = ClientManifest(root: environment.rootID, boot: environment.boot, policy: environment.policy,
                    revision: 1, ownerEpoch: 1, observed: try clock.now())
                m = try commit(m, old: nil)
            } else {
                let old = try refresh(); m = old; m.revision = try crAdd(m.revision, 1); m.ownerEpoch = try crAdd(m.ownerEpoch, 1)
                m = try commit(m, old: old)
            }
            ownerEpoch = m.ownerEpoch
        } catch { fs.close(); throw error }
    }
    deinit { close() }
    public func close() { fs.close() }
    func observe(_ m: ClientManifest) throws -> UInt64 {
        let time = try clock.now()
        guard time > 0, time >= m.observed, time >= observed else { throw ClientError.invalid("clock rollback") }
        observed = time; return time
    }
    func precheck(_ a: ClientAuthority, _ auth: ClientAuthorization) throws {
        try fs.ensure(); let time = try clock.now()
        guard time >= observed else { throw ClientError.invalid("clock rollback") }
        try auth.check(a, now: time)
    }
    func publish(_ a: ClientAuthority, _ auth: ClientAuthorization, _ m: ClientManifest) throws {
        try hook(.beforePublication)
        try auth.check(a, now: observe(m))
    }
    func find(_ handle: ClientHandle, _ a: ClientAuthority, _ m: ClientManifest) throws -> Int {
        guard handle.ownerEpoch == ownerEpoch, m.ownerEpoch == ownerEpoch else { throw ClientError.stale }
        guard let i = m.records.firstIndex(where: { $0.id == handle.record }), let live = m.records[i].live else { throw ClientError.expired }
        guard live.identity == a.identity, live.namespace == a.namespace, live.anchor == a.anchor,
              live.contextDigest == crHash(a.bytes), live.issued == a.context.issued, live.expires == a.context.expires else { throw ClientError.invalid("immutable context") }
        return i
    }
    public func open(_ a: ClientAuthority, authorization auth: ClientAuthorization) throws -> ClientHandle {
        try precheck(a, auth); let old = try refresh(); try auth.check(a, now: observe(old))
        if let i = old.records.firstIndex(where: { $0.live?.identity == a.identity }) {
            let handle = ClientHandle(record: old.records[i].id, ownerEpoch: ownerEpoch)
            _ = try find(handle, a, old)
            guard try snapshot(old.records[i]).context == a.bytes else { throw ClientError.invalid("context bytes") }
            try publish(a, auth, old); return handle
        }
        guard old.records.count < ClientLimits.records else { throw ClientError.full }
        guard !old.records.contains(where: { $0.live?.namespace == a.namespace && $0.live?.anchor != a.anchor }) else { throw ClientError.invalid("original namespace authority") }
        var m = old; m.revision = try crAdd(m.revision, 1)
        let id = UUID().uuidString.lowercased()
        let placeholder = SnapshotReference(name: "s-"+id+".bin", digest: String(repeating: "0", count: 64), revision: m.revision, length: ClientCrypto.overhead)
        m.records.append(.init(id: id, live: .init(identity: a.identity, namespace: a.namespace, anchor: a.anchor,
            contextDigest: crHash(a.bytes), issued: a.context.issued, expires: a.context.expires, key: clientRandomKey(),
            snapshot: placeholder, calls: 0, futureBytes: 8192), cleanup: nil))
        m = try commit(m, old: old, replacement: (m.records.count-1, ClientSnapshot(context: a.bytes)))
        try publish(a, auth, m); return .init(record: id, ownerEpoch: ownerEpoch)
    }
    public func accept(_ frame: ReplayEnvelope, requestedCursor: UInt64, handle: ClientHandle,
                       authority a: ClientAuthority, authorization auth: ClientAuthorization) throws -> DurableReceipt {
        try precheck(a, auth); let old = try refresh(); let i = try find(handle, a, old)
        var s = try snapshot(old.records[i])
        let events = try frame.validate(cursor: requestedCursor, high: s.high)
        if let known = s.batches.first(where: { $0.first == frame.firstSequence }) {
            guard known.matches(frame) else { throw ClientError.invalid("changed batch") }
            try publish(a, auth, old); return s.receipt()
        }
        var m = old; m.revision = try crAdd(m.revision, 1)
        try s.append(frame, events: events, revision: m.revision)
        m = try commit(m, old: old, replacement: (i, s)); try hook(.afterInbox)
        try publish(a, auth, m); return s.receipt()
    }
    public func inbox(_ handle: ClientHandle, authority a: ClientAuthority, authorization auth: ClientAuthorization) throws -> [Data] {
        try precheck(a, auth); let m = try refresh(); let i = try find(handle, a, m); let s = try snapshot(m.records[i])
        try publish(a, auth, m); return s.batches.map(\.bytes)
    }
    public func receipt(_ handle: ClientHandle, authority a: ClientAuthority, authorization auth: ClientAuthorization) throws -> DurableReceipt {
        try precheck(a, auth); let m = try refresh(); let i = try find(handle, a, m); let s = try snapshot(m.records[i])
        try publish(a, auth, m); return s.receipt()
    }
}
