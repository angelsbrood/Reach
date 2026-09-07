import Foundation
import ResumableMLXProvider

public final class DurableHostStore {
    public let identity: StoreIdentity
    public let ownerEpoch: UInt64
    public var ownerToken: String { "s81-owner:" + identity.storeID + ":" + String(ownerEpoch) }
    public private(set) var isClosed = false
    public private(set) var uncertain = false
    let files: StoreFileSystem
    let keys: StoreKeys
    public var fault: StoreFaultHook
    private init(identity: StoreIdentity, keys: StoreKeys, files: StoreFileSystem, epoch: UInt64, fault: @escaping StoreFaultHook) {
        self.identity = identity; self.keys = keys; self.files = files; ownerEpoch = epoch; self.fault = fault
    }
    public static func initialize(at path: String, identity: StoreIdentity, keys: StoreKeys, fault: @escaping StoreFaultHook = { _ in }) throws -> DurableHostStore {
        try identity.validate()
        let files = try StoreFileSystem(path: path, create: true)
        let store = DurableHostStore(identity: identity, keys: keys, files: files, epoch: 1, fault: fault)
        do {
            let manifest = try StoreManifest(storeID: identity.storeID, bootID: identity.bootID, bindingDigest: identity.bindingDigest, epoch: 1)
            try store.replace(manifest); _ = try store.load(); return store
        } catch { store.close(); throw error }
    }
    public static func reopen(at path: String, identity: StoreIdentity, keys: StoreKeys, fault: @escaping StoreFaultHook = { _ in }) throws -> DurableHostStore {
        try identity.validate()
        let files = try StoreFileSystem(path: path, create: false)
        do {
            let prior = try Self.readAuthority(files: files, identity: identity, keys: keys)
            let next = prior.manifest.epoch.addingReportingOverflow(1)
            guard !next.overflow else { throw StoreError.invalid("owner epoch overflow") }
            let store = DurableHostStore(identity: identity, keys: keys, files: files, epoch: next.partialValue, fault: fault)
            try store.cleanup(prior)
            var manifest = prior.manifest; manifest.epoch = next.partialValue
            try store.replace(manifest); _ = try store.load(); return store
        } catch { files.close(); throw error }
    }
    deinit { close() }
    public func close() { isClosed = true; files.close() }
    func load(allowUncertain: Bool = false) throws -> StoreLoaded {
        guard !isClosed else { throw StoreError.closed }
        guard allowUncertain || !uncertain else { throw StoreError.uncertain }
        try files.ensure()
        let result = try Self.readAuthority(files: files, identity: identity, keys: keys)
        guard result.manifest.epoch == ownerEpoch else { throw StoreError.stale }
        return result
    }
    static func readAuthority(files: StoreFileSystem, identity: StoreIdentity, keys: StoreKeys) throws -> StoreLoaded {
        _ = try files.scan()
        let encrypted = try files.read("current", maximum: StoreLimits.manifest+StoreCrypto.overhead)
        let plain = try StoreCrypto.open(encrypted, identity: identity, role: "manifest", epoch: nil, keys: keys)
        let m = try JSONDecoder().decode(StoreManifest.self, from: plain)
        guard m.version == 1, m.storeID == identity.storeID, m.bootID == identity.bootID,
              m.bindingDigest == (try identity.bindingDigest), m.epoch > 0,
              m.high <= UInt64(StoreLimits.events), (0...StoreLimits.commits).contains(m.batches),
              try storeEncode(m) == plain else { throw StoreError.invalid("authenticated manifest declaration") }
        guard let commit = m.commit else {
            guard m.candidate == nil, m.replay == nil, m.high == 0, m.batches == 0, m.terminal == nil else { throw StoreError.invalid("empty generation manifest") }
            return .init(manifest: m, candidate: nil, replay: .init())
        }
        guard let candidateRef = m.candidate, let replayRef = m.replay, candidateRef.record != replayRef.record else { throw StoreError.invalid("committed blob references") }
        func blob(_ ref: StoreBlobReference, _ role: String) throws -> Data {
            try ref.validate(epoch: m.epoch, role: role)
            let data = try files.read(ref.name, maximum: ref.cipherBytes)
            guard data.count == ref.cipherBytes, storeHash(data) == ref.cipherDigest else { throw StoreError.invalid("referenced ciphertext length/digest") }
            return try StoreCrypto.open(data, identity: identity, role: role, record: ref.record, epoch: ref.epoch, keys: keys)
        }
        let candidate = try ProviderCandidate(data: blob(candidateRef, "candidate")), projection = try StoreCommitProjection(candidate, identity: identity)
        let replay = try StoreReplay(data: blob(replayRef, "replay"))
        guard candidate.commit.data == commit, m.high == replay.high, m.batches == replay.batches.count,
              try storeEncode(m.terminal) == storeEncode(projection.terminal), try storeEncode(replay.terminal()) == storeEncode(m.terminal) else { throw StoreError.invalid("committed candidate/replay/terminal join") }
        let count = try StoreReplay.events(candidate.eventBytes).count
        if count > 0 {
            guard let last = replay.batches.last, last.commit == candidate.commit.identity, last.ordinal == projection.ordinal,
                  last.count == count, last.bytes == candidate.eventBytes else { throw StoreError.invalid("newest replay batch join") }
        } else if let last = replay.batches.last {
            guard last.ordinal < projection.ordinal, last.commit != candidate.commit.identity else { throw StoreError.invalid("empty step replay join") }
        }
        return .init(manifest: m, candidate: candidate, replay: replay)
    }
    public func snapshot() throws -> StoreSnapshot { try load().snapshot }
    public func replay(after cursor: UInt64) throws -> [StoreReplayFrame] { try load().replay.frames(after: cursor) }
    /// Actual selected-root usage plus conservative full-next-set reservation.
    public func reserve() throws {
        let current = try load(), usage = try files.scan()
        let allocated = usage.values.reduce(0) { $0 + $1.allocated }
        guard usage.count <= StoreLimits.files-3, allocated <= StoreLimits.allocation-StoreLimits.reservation,
              current.replay.high <= UInt64(StoreLimits.events-4096),
              current.replay.encodedSize <= StoreLimits.replay-ProviderCandidate.maximumControlBytes-StoreReplay.headerBytes else { throw StoreError.full }
        if let candidate = current.candidate {
            let projection = try StoreCommitProjection(candidate, identity: identity)
            guard projection.ordinal < UInt64(StoreLimits.commits-1) else { throw StoreError.full }
        }
    }
    @discardableResult public func commit(_ candidate: ProviderCandidate) throws -> StoreSnapshot {
        let current = try load(allowUncertain: true), projection = try StoreCommitProjection(candidate, identity: identity)
        if current.candidate?.commit == candidate.commit {
            guard current.candidate?.data == candidate.data else { throw StoreError.invalid("current retry bytes") }
            try files.syncDirectory(); uncertain = false; try cleanup(current); return current.snapshot
        }
        guard !uncertain else { throw StoreError.uncertain }
        try reserve()
        if let parent = current.candidate {
            let previous = try StoreCommitProjection(parent, identity: identity)
            guard current.manifest.terminal == nil, projection.ordinal == previous.ordinal+1,
                  projection.previousID == parent.commit.identity else { throw StoreError.invalid("stale/skipped provider parent") }
        } else {
            guard projection.ordinal == 0, projection.previousID == nil else { throw StoreError.invalid("initial C0 parent") }
        }
        let replay = try current.replay.appending(candidate, projection: projection)
        func prepareBlob(_ bytes: Data, role: String) throws -> StoreBlobReference {
            let record = UUID().uuidString.lowercased()
            let cipher = try StoreCrypto.seal(bytes, identity: identity, role: role, record: record, epoch: ownerEpoch, keys: keys)
            let reference = StoreBlobReference(record: record, epoch: ownerEpoch, cipherBytes: cipher.count, cipherDigest: storeHash(cipher))
            try files.writeNew(reference.name, bytes: cipher)
            let actual = try files.read(reference.name, maximum: cipher.count)
            guard actual == cipher else { throw StoreError.invalid("prepared ciphertext verification") }
            return reference
        }
        let candidateRef = try prepareBlob(candidate.data, role: "candidate"); try fault(.afterCandidateBlob)
        let replayRef = try prepareBlob(replay.encoded(), role: "replay"); try fault(.afterReplayBlob)
        var next = current.manifest
        next.commit = candidate.commit.data; next.candidate = candidateRef; next.replay = replayRef
        next.high = replay.high; next.batches = replay.batches.count; next.terminal = projection.terminal
        try replace(next)
        let authoritative = try load(); try cleanup(authoritative); return authoritative.snapshot
    }
    @discardableResult public func reconcile() throws -> StoreSnapshot {
        let authority = try load(allowUncertain: true)
        try files.syncDirectory(); uncertain = false; try cleanup(authority); return authority.snapshot
    }
    private func replace(_ manifest: StoreManifest) throws {
        let plain = try storeEncode(manifest)
        guard plain.count <= StoreLimits.manifest else { throw StoreError.full }
        let record = UUID().uuidString.lowercased(), temporary = "t-" + UUID().uuidString.lowercased() + ".bin"
        let cipher = try StoreCrypto.seal(plain, identity: identity, role: "manifest", record: record, epoch: nil, keys: keys)
        try files.writeNew(temporary, bytes: cipher)
        guard try files.read(temporary, maximum: cipher.count) == cipher else { throw StoreError.invalid("prepared manifest bytes") }
        try fault(.beforeManifestReplace)
        // Mark the whole rename attempt uncertain, including an error return.
        // Disk authority decides whether selection happened; a missing reply
        // cannot license the old parent or publication before reconciliation.
        uncertain = true
        try files.replaceCurrent(with: temporary)
        do {
            try fault(.afterManifestReplace); try fault(.beforeDirectorySync); try files.syncDirectory(); uncertain = false
        } catch { throw error }
    }
    private func cleanup(_ authority: StoreLoaded) throws {
        let referenced = Set(["current", "lock"] + [authority.manifest.candidate?.name, authority.manifest.replay?.name].compactMap { $0 })
        // Called only after full current authority validation, under the stable lock.
        let roles = try files.scan().keys.filter { !referenced.contains($0) }
        try files.removeUnreferenced(Array(roles))
    }
}
