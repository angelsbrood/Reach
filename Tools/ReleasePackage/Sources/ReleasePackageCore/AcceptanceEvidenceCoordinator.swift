import Darwin
import Foundation

public struct AcceptanceAbsenceInventory: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let runID: String
  public let kind: String
  public let pathCount: Int
  public let teardownAuthoritySHA256: String
  public let verdict: String

  public init(
    runID: String, kind: String, pathCount: Int,
    teardownAuthoritySHA256: String
  ) {
    schemaVersion = 1
    self.runID = runID
    self.kind = kind
    self.pathCount = pathCount
    self.teardownAuthoritySHA256 = teardownAuthoritySHA256
    verdict = "pass"
  }

  public func validate() throws {
    guard schemaVersion == 1, UUID(uuidString: runID) != nil,
      ["credentials", "tooling"].contains(kind), pathCount > 0,
      teardownAuthoritySHA256.range(
        of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      verdict == "pass"
    else {
      throw ReleasePackageError.verification("teardown absence inventory is malformed")
    }
  }
}

public struct AcceptanceTeardownAuthority: Codable, Equatable, Sendable {
  public struct Path: Codable, Equatable, Sendable {
    public let role: String
    public let path: String
    public let kind: String
    public let device: UInt64
    public let inode: UInt64
    public let mode: UInt32
    public let size: UInt64
    public let sha256: String?

    public init(
      role: String, path: String, kind: String, device: UInt64, inode: UInt64,
      mode: UInt32, size: UInt64, sha256: String?
    ) {
      self.role = role
      self.path = path
      self.kind = kind
      self.device = device
      self.inode = inode
      self.mode = mode
      self.size = size
      self.sha256 = sha256
    }
  }

  public let schemaVersion: Int
  public let runID: String
  public let rigJournalSHA256: String
  public let credentials: [Path]
  public let tooling: [Path]

  public init(
    runID: String, rigJournalSHA256: String,
    credentials: [Path], tooling: [Path]
  ) {
    schemaVersion = 1
    self.runID = runID
    self.rigJournalSHA256 = rigJournalSHA256
    self.credentials = credentials
    self.tooling = tooling
  }

  public func validate() throws {
    let all = credentials + tooling
    guard schemaVersion == 1, UUID(uuidString: runID) != nil,
      rigJournalSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      credentials.count == 2, !tooling.isEmpty,
      all.count == Set(all.map(\.path)).count,
      credentials == credentials.sorted(by: Self.less),
      tooling == tooling.sorted(by: Self.less),
      all.allSatisfy({
        $0.path.hasPrefix("/") && $0.path != "/" && !$0.path.contains("..")
          && !$0.path.contains("//") && ["file", "directory"].contains($0.kind)
          && $0.device > 0 && $0.inode > 0
          && ($0.kind == "directory"
            ? ($0.mode == 0o700 && $0.size == 0 && $0.sha256 == nil)
            : ([UInt32(0o600), UInt32(0o700)].contains($0.mode)
              && $0.sha256?.range(
                of: "^[0-9a-f]{64}$", options: .regularExpression) != nil))
      }),
      Set(credentials.map(\.role)) == Set(["ssh-identity", "ssh-known-hosts"]),
      credentials.allSatisfy({ $0.kind == "file" && $0.mode == 0o600 }),
      tooling.first?.role == "tooling-root",
      tooling.dropFirst().allSatisfy({ $0.role == "tooling-member" }),
      credentials.allSatisfy({
        guard let root = tooling.first?.path else { return false }
        return !Self.contains(root: root, path: $0.path)
      })
    else {
      throw ReleasePackageError.verification(
        "pre-teardown authority is malformed or incomplete")
    }
  }

  private static func less(_ lhs: Path, _ rhs: Path) -> Bool {
    lhs.path.utf8.lexicographicallyPrecedes(rhs.path.utf8)
  }

  private static func contains(root: String, path: String) -> Bool {
    path == root || path.hasPrefix(root + "/")
  }
}

public struct AcceptanceEvidenceCoordinator {
  public typealias Timestamp = () -> String

  private let evidenceStore: AcceptanceEvidenceJournalStore
  private let rigStore: AcceptanceRigJournalStore
  private let timestamp: Timestamp

  public init(
    evidenceStore: AcceptanceEvidenceJournalStore,
    rigStore: AcceptanceRigJournalStore,
    timestamp: @escaping Timestamp = Self.currentTimestamp
  ) {
    self.evidenceStore = evidenceStore
    self.rigStore = rigStore
    self.timestamp = timestamp
  }

  public func begin() throws -> AcceptanceEvidenceJournal {
    try evidenceStore.withExclusiveLock {
      guard try evidenceStore.load() == nil else {
        throw ReleasePackageError.verification("evidence journal already exists")
      }
      let rig = try requireRig()
      guard rig.phase != .failed, rig.phase != .complete else {
        throw ReleasePackageError.verification("evidence cannot begin from a closed rig")
      }
      let now = timestamp()
      let value = AcceptanceEvidenceJournal(
        runID: rig.runID,
        rigJournalSHA256: try digestFile(rigStore.url, label: "rig journal"),
        createdAtUTC: now, updatedAtUTC: now)
      try evidenceStore.create(value)
      return value
    }
  }

  public func record(
    cell: AcceptanceCell,
    verdict: AcceptanceEvidenceVerdict,
    privateEvidence: URL,
    redactedSummary: URL,
    guestJournal: URL? = nil
  ) throws -> AcceptanceEvidenceJournal {
    try evidenceStore.withExclusiveLock {
      guard var journal = try evidenceStore.load(), journal.phase == .collecting else {
        throw ReleasePackageError.verification("evidence is not collecting")
      }
      let rig = try requireRig(runID: journal.runID)
      guard rig.phase != .failed, rig.phase != .complete else {
        throw ReleasePackageError.verification("cell evidence cannot outlive its rig")
      }
      let record = AcceptanceCellEvidence(
        cell: cell,
        attempt: journal.records.filter { $0.cell == cell }.count + 1,
        verdict: verdict,
        privateEvidenceSHA256: try digestPrivateFile(
          privateEvidence, label: "private cell evidence"),
        redactedSummarySHA256: try digestPrivateFile(
          redactedSummary, label: "redacted cell summary"),
        guestJournalSHA256: try guestJournal.map {
          try digestPrivateFile($0, label: "guest transaction journal")
        })
      journal = try journal.recording(record, at: timestamp())
      try evidenceStore.write(journal)
      return journal
    }
  }

  public func seal(
    outcome: AcceptanceCloseoutOutcome,
    pack: URL
  ) throws -> AcceptanceEvidenceJournal {
    try evidenceStore.withExclusiveLock {
      guard var journal = try evidenceStore.load(), journal.phase == .collecting else {
        throw ReleasePackageError.verification("evidence is not collecting")
      }
      _ = try requireRig(runID: journal.runID)
      let packResult = try verifyPack(pack)
      journal = try journal.sealing(
        outcome: outcome, packManifestSHA256: packResult.manifestSHA256,
        packFileCount: packResult.fileCount, at: timestamp())
      try evidenceStore.write(journal)
      return journal
    }
  }

  public func freezeTeardownAuthority(
    hostAuthority: URL,
    output: URL
  ) throws -> AcceptanceTeardownAuthority {
    try evidenceStore.withExclusiveLock {
      guard var journal = try evidenceStore.load(), journal.phase == .sealed else {
        throw ReleasePackageError.verification(
          "teardown authority must be frozen immediately after evidence sealing")
      }
      let rig = try requireRig(runID: journal.runID)
      guard ![.cloneDeleted, .baseDeleted, .complete, .failed].contains(rig.phase) else {
        throw ReleasePackageError.verification(
          "teardown authority was frozen after destructive rig teardown")
      }
      let hostData = try Self.privateFileData(
        hostAuthority, label: "S36 host authority")
      let host = try JSONDecoder().decode(AcceptanceHostAuthority.self, from: hostData)
      guard hostData == (try CanonicalJSON.encode(host)) else {
        throw ReleasePackageError.verification("S36 host authority is not canonical")
      }
      try host.validate()
      let hostDigest = Digests.sha256(hostData)
      guard host.runID == journal.runID, rig.hostAuthoritySHA256 == hostDigest else {
        throw ReleasePackageError.verification(
          "teardown inputs are not the rig-bound pinned-SSH/tooling authority")
      }
      try host.verifyCredentials(
        identity: URL(fileURLWithPath: host.identity.path),
        knownHosts: URL(fileURLWithPath: host.knownHosts.path))
      try host.verifyToolingRoot()
      let credentials = try [
        Self.teardownRecord(host.identity, role: "ssh-identity"),
        Self.teardownRecord(host.knownHosts, role: "ssh-known-hosts"),
      ].sorted(by: Self.less)
      let tooling = try Self.toolingRecords(
        root: URL(fileURLWithPath: host.toolingRoot.path))
      guard let toolingRoot = tooling.first,
        toolingRoot.path.utf8.elementsEqual(host.toolingRoot.path.utf8),
        toolingRoot.kind == host.toolingRoot.kind,
        toolingRoot.device == host.toolingRoot.device,
        toolingRoot.inode == host.toolingRoot.inode
      else {
        throw ReleasePackageError.verification(
          "tooling root changed while freezing teardown authority")
      }
      let value = AcceptanceTeardownAuthority(
        runID: journal.runID,
        rigJournalSHA256: try digestFile(rigStore.url, label: "rig journal"),
        credentials: credentials, tooling: tooling)
      try value.validate()
      for record in credentials + tooling {
        _ = try Self.requireFrozen(record, allowAbsent: false)
      }
      try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: output)
      let digest = try digestPrivateFile(output, label: "pre-teardown authority")
      journal = try journal.bindingTeardownAuthority(
        sha256: digest, at: timestamp())
      try evidenceStore.write(journal)
      return value
    }
  }

  public func advanceRigTeardown(
    to phase: AcceptanceEvidencePhase
  ) throws -> AcceptanceEvidenceJournal {
    try evidenceStore.withExclusiveLock {
      guard var journal = try evidenceStore.load() else {
        throw ReleasePackageError.verification("evidence journal is absent")
      }
      let rig = try requireRig(runID: journal.runID)
      let expectedRig: AcceptanceRigPhase
      switch phase {
      case .cloneDeleted: expectedRig = .cloneDeleted
      case .baseDeleted: expectedRig = .baseDeleted
      default:
        throw ReleasePackageError.invalidArgument("this teardown phase is not rig-owned")
      }
      guard rig.phase == expectedRig, let inventory = rig.latestInventorySHA256 else {
        throw ReleasePackageError.verification("rig teardown authority is not at the same phase")
      }
      journal = try journal.advancingTeardown(
        to: phase, inventorySHA256: inventory, at: timestamp())
      try evidenceStore.write(journal)
      return journal
    }
  }

  public func destroyAuthority(
    kind: String,
    authority: URL,
    inventory: URL,
    output: URL
  ) throws -> AcceptanceEvidenceJournal {
    try evidenceStore.withExclusiveLock {
      guard var journal = try evidenceStore.load() else {
        throw ReleasePackageError.verification("evidence journal is absent")
      }
      let data = try Self.privateFileData(
        authority, label: "pre-teardown authority")
      let frozen = try JSONDecoder().decode(AcceptanceTeardownAuthority.self, from: data)
      guard data == (try CanonicalJSON.encode(frozen)) else {
        throw ReleasePackageError.verification(
          "pre-teardown authority is not canonical")
      }
      try frozen.validate()
      let digest = Digests.sha256(data)
      guard frozen.runID == journal.runID,
        digest == journal.teardownAuthoritySHA256
      else {
        throw ReleasePackageError.verification(
          "pre-teardown authority is not bound to this run")
      }
      let paths: [AcceptanceTeardownAuthority.Path]
      let starting: AcceptanceEvidencePhase
      let destroying: AcceptanceEvidencePhase
      let claimed: AcceptanceEvidencePhase
      let finished: AcceptanceEvidencePhase
      switch kind {
      case "credentials":
        paths = frozen.credentials
        starting = .baseDeleted
        destroying = .credentialsDestroying
        claimed = .credentialsClaimed
        finished = .credentialsDestroyed
      case "tooling":
        paths = frozen.tooling
        starting = .credentialsDestroyed
        destroying = .toolingRemoving
        claimed = .toolingClaimed
        finished = .toolingRemoved
      default:
        throw ReleasePackageError.invalidArgument("unknown teardown authority kind")
      }
      let tombstones = try Self.claimedPaths(
        records: paths, kind: kind, runID: journal.runID)
      let allAuthorityPaths = frozen.credentials + frozen.tooling
      let allTombstones =
        try Self.claimedPaths(
          records: frozen.credentials, kind: "credentials", runID: journal.runID)
        + Self.claimedPaths(
          records: frozen.tooling, kind: "tooling", runID: journal.runID)
      let protectedPaths = [evidenceStore.url, rigStore.url, authority, inventory, output]
      guard Set(protectedPaths.map(\URL.path)).count == protectedPaths.count else {
        throw ReleasePackageError.unsafePath(
          "teardown output, inventory, journals, and authority must be distinct")
      }
      for protected in protectedPaths {
        guard
          !(allAuthorityPaths + allTombstones).contains(where: {
            Self.contains(root: $0.path, path: protected.path)
              || Self.contains(root: protected.path, path: $0.path)
          })
        else {
          throw ReleasePackageError.unsafePath(
            "teardown authority overlaps protected output or journal authority")
        }
      }
      if journal.phase == starting {
        for record in paths { try Self.requireFrozen(record, allowAbsent: false) }
        journal = try journal.beginningAuthorityDestruction(
          to: destroying, at: timestamp())
        try evidenceStore.write(journal)
      } else if journal.phase != destroying {
        guard journal.phase == claimed else {
          throw ReleasePackageError.verification(
            "authority destruction is not at its recoverable phase")
        }
      }

      if journal.phase == destroying {
        try Self.claimAuthority(
          original: paths, tombstones: tombstones, kind: kind)
        journal = try journal.recordingAuthorityClaim(
          to: claimed, pathCount: tombstones.count, at: timestamp())
        try evidenceStore.write(journal)
      }

      let ordered = tombstones.sorted(by: Self.deletionOrder)
      let alreadyDeleted: Int
      let claimedPathCount: Int
      switch kind {
      case "credentials":
        alreadyDeleted = journal.credentialDeletionCount ?? -1
        claimedPathCount = journal.credentialClaimedPathCount ?? -1
      case "tooling":
        alreadyDeleted = journal.toolingDeletionCount ?? -1
        claimedPathCount = journal.toolingClaimedPathCount ?? -1
      default: preconditionFailure("validated teardown kind changed")
      }
      guard claimedPathCount == ordered.count,
        (0...ordered.count).contains(alreadyDeleted)
      else {
        throw ReleasePackageError.verification(
          "claimed-vnode deletion progress is malformed")
      }
      for (index, record) in ordered.enumerated() {
        if index < alreadyDeleted {
          try Self.requireAbsent(
            record.path, label: "durably deleted claimed teardown vnode")
          continue
        }
        try Self.deleteClaimed(record)
        journal = try journal.recordingAuthorityDeletion(
          kind: kind, deletedCount: index + 1, at: timestamp())
        try evidenceStore.write(journal)
      }
      for record in paths + tombstones {
        try Self.requireAbsent(record.path, label: "teardown authority")
      }
      let value = AcceptanceAbsenceInventory(
        runID: journal.runID, kind: kind, pathCount: paths.count,
        teardownAuthoritySHA256: digest)
      try value.validate()
      let encoded = try CanonicalJSON.encode(value)
      try SecureFiles.atomicWrite(encoded, to: inventory)
      journal = try journal.advancingTeardown(
        to: finished, inventorySHA256: Digests.sha256(encoded), at: timestamp())
      try evidenceStore.write(journal)
      return journal
    }
  }

  public func complete(runtimeParity: URL) throws -> AcceptanceEvidenceJournal {
    try evidenceStore.withExclusiveLock {
      guard var journal = try evidenceStore.load() else {
        throw ReleasePackageError.verification("evidence journal is absent")
      }
      let rig = try requireRig(runID: journal.runID)
      guard rig.phase == .complete, let inventory = rig.latestInventorySHA256 else {
        throw ReleasePackageError.verification("rig is not durably complete")
      }
      journal = try journal.advancingTeardown(
        to: .complete, inventorySHA256: inventory,
        runtimeParitySHA256: try digestPrivateFile(
          runtimeParity, label: "runtime parity report"),
        at: timestamp())
      try evidenceStore.write(journal)
      return journal
    }
  }

  private func requireRig(runID: String? = nil) throws -> AcceptanceRigJournal {
    try rigStore.withExclusiveLock {
      guard let rig = try rigStore.load(), runID == nil || rig.runID == runID else {
        throw ReleasePackageError.verification("evidence and rig authority do not match")
      }
      return rig
    }
  }

  private static func toolingRecords(
    root: URL
  ) throws -> [AcceptanceTeardownAuthority.Path] {
    let urls = [root] + (try SecureFiles.enumerateTree(root))
    return try urls.map { url in
      try captureTeardownPath(
        url,
        role: url.path.utf8.elementsEqual(root.path.utf8)
          ? "tooling-root" : "tooling-member")
    }.sorted(by: less)
  }

  private static func teardownRecord(
    _ record: AcceptanceHostAuthority.Record, role: String
  ) throws -> AcceptanceTeardownAuthority.Path {
    guard record.role == role else {
      throw ReleasePackageError.verification("host authority role changed")
    }
    let captured = try captureTeardownPath(
      URL(fileURLWithPath: record.path), role: role)
    guard captured.path.utf8.elementsEqual(record.path.utf8),
      captured.kind == record.kind, captured.device == record.device,
      captured.inode == record.inode, captured.sha256 == record.sha256
    else {
      throw ReleasePackageError.verification(
        "host credential changed while freezing teardown authority")
    }
    return captured
  }

  private static func captureTeardownPath(
    _ url: URL, role: String
  ) throws -> AcceptanceTeardownAuthority.Path {
    let physical = try ReleasePathAuthority.absoluteURL(url.path, label: role)
    guard physical.path.utf8.elementsEqual(url.path.utf8), url.path != "/" else {
      throw ReleasePackageError.unsafePath("teardown path lacks exact physical spelling")
    }
    var info = stat()
    guard lstat(url.path, &info) == 0, info.st_uid == getuid() else {
      throw ReleasePackageError.verification("teardown path is absent or unowned")
    }
    let mode = UInt32(info.st_mode & 0o7777)
    switch info.st_mode & S_IFMT {
    case S_IFDIR:
      guard mode == 0o700 else {
        throw ReleasePackageError.unsafePath("teardown directory is not mode 0700")
      }
      return .init(
        role: role, path: url.path, kind: "directory",
        device: UInt64(info.st_dev), inode: UInt64(info.st_ino),
        mode: mode, size: 0, sha256: nil)
    case S_IFREG:
      guard info.st_nlink == 1, [UInt32(0o600), UInt32(0o700)].contains(mode) else {
        throw ReleasePackageError.unsafePath("teardown file is not owner-private")
      }
      return .init(
        role: role, path: url.path, kind: "file",
        device: UInt64(info.st_dev), inode: UInt64(info.st_ino),
        mode: mode, size: UInt64(info.st_size), sha256: try Digests.sha256(file: url))
    default:
      throw ReleasePackageError.unsafePath(
        "teardown authority contains a link or special file")
    }
  }

  @discardableResult
  private static func requireFrozen(
    _ record: AcceptanceTeardownAuthority.Path, allowAbsent: Bool
  ) throws -> Bool {
    guard let descriptor = try openFrozenDescriptor(record, allowAbsent: allowAbsent) else {
      return false
    }
    close(descriptor)
    return true
  }

  private static func openFrozenDescriptor(
    _ record: AcceptanceTeardownAuthority.Path, allowAbsent: Bool
  ) throws -> Int32? {
    let flags = O_RDONLY | O_NOFOLLOW | (record.kind == "directory" ? O_DIRECTORY : 0)
    let descriptor = open(record.path, flags)
    guard descriptor >= 0 else {
      if errno == ENOENT, allowAbsent { return nil }
      throw ReleasePackageError.verification("frozen teardown path disappeared before deletion")
    }
    do {
      var info = stat()
      guard fstat(descriptor, &info) == 0 else {
        throw ReleasePackageError.verification("cannot inspect frozen teardown vnode")
      }
      let kind =
        (info.st_mode & S_IFMT) == S_IFREG
        ? "file"
        : (info.st_mode & S_IFMT) == S_IFDIR ? "directory" : "special"
      guard kind == record.kind, info.st_uid == getuid(),
        UInt64(info.st_dev) == record.device, UInt64(info.st_ino) == record.inode,
        UInt32(info.st_mode & 0o7777) == record.mode
      else {
        throw ReleasePackageError.verification(
          "frozen teardown vnode or metadata changed before deletion")
      }
      if kind == "file" {
        guard info.st_nlink == 1, UInt64(info.st_size) == record.size else {
          throw ReleasePackageError.verification(
            "frozen teardown file metadata changed before deletion")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let data = try handle.readToEnd() ?? Data()
        guard data.count == Int(info.st_size), Digests.sha256(data) == record.sha256 else {
          throw ReleasePackageError.verification(
            "frozen teardown file contents changed before deletion")
        }
      }
      return descriptor
    } catch {
      close(descriptor)
      throw error
    }
  }

  static func claimedPaths(
    records: [AcceptanceTeardownAuthority.Path],
    kind: String,
    runID: String
  ) throws -> [AcceptanceTeardownAuthority.Path] {
    guard UUID(uuidString: runID) != nil, !records.isEmpty,
      ["credentials", "tooling"].contains(kind)
    else {
      throw ReleasePackageError.verification("teardown tombstone authority is malformed")
    }
    func tombstone(_ root: String) -> String {
      let digest = Digests.sha256(Data((runID + "\0" + kind + "\0" + root).utf8))
      let parent = URL(fileURLWithPath: root).deletingLastPathComponent()
      return parent.appendingPathComponent(
        ".reach-s36-" + kind + "-" + digest.prefix(24) + ".claimed"
      ).path
    }
    func replacing(
      _ record: AcceptanceTeardownAuthority.Path, path: String
    ) -> AcceptanceTeardownAuthority.Path {
      .init(
        role: record.role, path: path, kind: record.kind,
        device: record.device, inode: record.inode, mode: record.mode,
        size: record.size, sha256: record.sha256)
    }
    switch kind {
    case "credentials":
      return records.map { replacing($0, path: tombstone($0.path)) }
    case "tooling":
      guard let root = records.first, root.role == "tooling-root",
        records.allSatisfy({ contains(root: root.path, path: $0.path) })
      else {
        throw ReleasePackageError.verification("tooling tombstone lacks one frozen root")
      }
      let claimedRoot = tombstone(root.path)
      return records.map { record in
        let suffix = String(record.path.dropFirst(root.path.count))
        return replacing(record, path: claimedRoot + suffix)
      }
    default:
      preconditionFailure("validated teardown kind changed")
    }
  }

  private static func claimAuthority(
    original: [AcceptanceTeardownAuthority.Path],
    tombstones: [AcceptanceTeardownAuthority.Path],
    kind: String
  ) throws {
    guard original.count == tombstones.count else {
      throw ReleasePackageError.verification("teardown tombstone cardinality changed")
    }
    switch kind {
    case "credentials":
      for (source, tombstone) in zip(original, tombstones) {
        try claimUnit(
          original: [source], tombstones: [tombstone],
          sourceRoot: source, tombstoneRoot: tombstone)
      }
    case "tooling":
      guard let sourceRoot = original.first, let tombstoneRoot = tombstones.first else {
        throw ReleasePackageError.verification("tooling tombstone root is absent")
      }
      try claimUnit(
        original: original, tombstones: tombstones,
        sourceRoot: sourceRoot, tombstoneRoot: tombstoneRoot)
    default:
      throw ReleasePackageError.invalidArgument("unknown teardown authority kind")
    }
  }

  private static func claimUnit(
    original: [AcceptanceTeardownAuthority.Path],
    tombstones: [AcceptanceTeardownAuthority.Path],
    sourceRoot: AcceptanceTeardownAuthority.Path,
    tombstoneRoot: AcceptanceTeardownAuthority.Path
  ) throws {
    let sourcePresent = try pathExists(sourceRoot.path)
    let tombstonePresent = try pathExists(tombstoneRoot.path)
    guard sourcePresent != tombstonePresent else {
      throw ReleasePackageError.verification(
        "teardown claim requires exactly one original or tombstone vnode")
    }
    if sourcePresent {
      for record in original { _ = try requireFrozen(record, allowAbsent: false) }
      for record in tombstones {
        try requireAbsent(record.path, label: "unclaimed teardown tombstone")
      }
      guard let descriptor = try openFrozenDescriptor(sourceRoot, allowAbsent: false) else {
        preconditionFailure("required frozen source returned no descriptor")
      }
      defer { close(descriptor) }
      guard renamex_np(sourceRoot.path, tombstoneRoot.path, UInt32(RENAME_EXCL)) == 0 else {
        throw ReleasePackageError.processFailure(
          "cannot atomically claim exact teardown authority")
      }
      try syncParent(of: tombstoneRoot.path)
      var retained = stat()
      guard fstat(descriptor, &retained) == 0,
        UInt64(retained.st_dev) == sourceRoot.device,
        UInt64(retained.st_ino) == sourceRoot.inode
      else {
        throw ReleasePackageError.verification(
          "claimed teardown descriptor changed during rename")
      }
    }
    for record in original {
      try requireAbsent(record.path, label: "claimed teardown source")
    }
    for record in tombstones {
      _ = try requireFrozen(record, allowAbsent: false)
    }
  }

  private static func deleteClaimed(
    _ record: AcceptanceTeardownAuthority.Path
  ) throws {
    guard let descriptor = try openFrozenDescriptor(record, allowAbsent: false) else {
      preconditionFailure("required claimed vnode returned no descriptor")
    }
    defer { close(descriptor) }
    let result = record.kind == "file" ? unlink(record.path) : rmdir(record.path)
    guard result == 0 else {
      throw ReleasePackageError.processFailure(
        "cannot delete exact claimed " + record.role)
    }
    var retained = stat()
    guard fstat(descriptor, &retained) == 0,
      UInt64(retained.st_dev) == record.device,
      UInt64(retained.st_ino) == record.inode,
      record.kind != "file" || retained.st_nlink == 0
    else {
      throw ReleasePackageError.verification(
        "claimed teardown vnode was not the deleted authority")
    }
    try requireAbsent(record.path, label: "deleted claimed teardown vnode")
    try syncParent(of: record.path)
  }

  private static func pathExists(_ path: String) throws -> Bool {
    var info = stat()
    if lstat(path, &info) == 0 { return true }
    if errno == ENOENT { return false }
    throw ReleasePackageError.verification("cannot inspect teardown pathname")
  }

  private static func requireAbsent(_ path: String, label: String) throws {
    var info = stat()
    guard lstat(path, &info) != 0, errno == ENOENT else {
      throw ReleasePackageError.verification(label + " is not absent")
    }
  }

  private static func syncParent(of path: String) throws {
    let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
    try SecureFiles.syncDirectory(parent)
  }

  private static func less(
    _ lhs: AcceptanceTeardownAuthority.Path,
    _ rhs: AcceptanceTeardownAuthority.Path
  ) -> Bool {
    lhs.path.utf8.lexicographicallyPrecedes(rhs.path.utf8)
  }

  private static func deletionOrder(
    _ lhs: AcceptanceTeardownAuthority.Path,
    _ rhs: AcceptanceTeardownAuthority.Path
  ) -> Bool {
    let leftDepth = lhs.path.split(separator: "/").count
    let rightDepth = rhs.path.split(separator: "/").count
    if leftDepth != rightDepth { return leftDepth > rightDepth }
    return rhs.path.utf8.lexicographicallyPrecedes(lhs.path.utf8)
  }

  private static func contains(
    root: String, path: String
  ) -> Bool {
    path == root || path.hasPrefix(root + "/")
  }

  private static func syncSurvivingParents(
    of paths: [AcceptanceTeardownAuthority.Path]
  ) throws {
    let removed = Set(paths.map(\.path))
    let parents = Set(
      paths.compactMap { record -> String? in
        let parent = URL(fileURLWithPath: record.path).deletingLastPathComponent().path
        return removed.contains(parent) ? nil : parent
      })
    for path in parents.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
      let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
      guard descriptor >= 0 else {
        throw ReleasePackageError.processFailure(
          "cannot open surviving teardown parent for synchronization")
      }
      defer { close(descriptor) }
      guard fsync(descriptor) == 0 else {
        throw ReleasePackageError.processFailure(
          "cannot synchronize surviving teardown parent")
      }
    }
  }

  private func verifyPack(_ root: URL) throws -> (manifestSHA256: String, fileCount: Int) {
    let physical = try ReleasePathAuthority.absoluteURL(root.path, label: "evidence pack")
    var rootInfo = stat()
    guard lstat(physical.path, &rootInfo) == 0, (rootInfo.st_mode & S_IFMT) == S_IFDIR,
      rootInfo.st_uid == getuid(), (rootInfo.st_mode & 0o7777) == 0o700
    else {
      throw ReleasePackageError.unsafePath("evidence pack must be an owner-private directory")
    }
    let entries = try SecureFiles.enumerateTree(physical).sorted { $0.path < $1.path }
    var files: [String: URL] = [:]
    var bytes: UInt64 = 0
    for url in entries {
      var info = stat()
      guard lstat(url.path, &info) == 0, info.st_uid == getuid() else {
        throw ReleasePackageError.unsafePath("evidence pack contains unowned authority")
      }
      let relative = String(url.path.dropFirst(physical.path.count + 1))
      try SecureFiles.validateRelativePath(relative)
      switch info.st_mode & S_IFMT {
      case S_IFDIR:
        guard (info.st_mode & 0o7777) == 0o700 else {
          throw ReleasePackageError.unsafePath("evidence directory mode changed")
        }
      case S_IFREG:
        guard info.st_nlink == 1, (info.st_mode & 0o7777) == 0o600,
          relative == "SHA256SUMS"
            || ["json", "md", "txt"].contains(url.pathExtension.lowercased())
        else {
          throw ReleasePackageError.unsafePath("evidence file type or mode changed")
        }
        bytes += UInt64(info.st_size)
        files[relative] = url
      default:
        throw ReleasePackageError.unsafePath("evidence pack contains a link or special file")
      }
    }
    guard files.count <= 256, bytes <= 50 * 1_024 * 1_024,
      let manifest = files["SHA256SUMS"]
    else {
      throw ReleasePackageError.verification("evidence pack exceeds its bounded authority")
    }
    let manifestData = try Self.privateFileData(
      manifest, label: "evidence SHA256SUMS")
    let lines = String(decoding: manifestData, as: UTF8.self)
      .split(separator: "\n", omittingEmptySubsequences: false)
    guard lines.last == "" else {
      throw ReleasePackageError.verification("evidence SHA256SUMS lacks final newline")
    }
    var named: [String] = []
    for line in lines.dropLast() {
      let fields = line.split(separator: " ", omittingEmptySubsequences: false)
      guard fields.count == 3, fields[1].isEmpty,
        fields[0].range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
      else {
        throw ReleasePackageError.verification("evidence SHA256SUMS is malformed")
      }
      let name = String(fields[2])
      try SecureFiles.validateRelativePath(name)
      guard name != "SHA256SUMS", let url = files[name],
        try Digests.sha256(file: url) == String(fields[0])
      else {
        throw ReleasePackageError.verification("evidence SHA256SUMS does not match its file")
      }
      named.append(name)
    }
    guard named == named.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }),
      named.count == Set(named).count,
      Set(named) == Set(files.keys).subtracting(["SHA256SUMS"])
    else {
      throw ReleasePackageError.verification("evidence SHA256SUMS authority is incomplete")
    }
    try privacyScan(files: files.filter { $0.key != "SHA256SUMS" })
    return (Digests.sha256(manifestData), files.count)
  }

  private func privacyScan(files: [String: URL]) throws {
    let forbidden = [
      #"/Users/"#, #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#,
      #"(?i)(apple[- ]id|app[- ]specific password|notarytool profile)"#,
      #"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"#,
    ]
    for url in files.values {
      let data = try Self.privateFileData(url, label: "evidence member")
      guard let text = String(data: data, encoding: .utf8),
        !forbidden.contains(where: {
          text.range(of: $0, options: .regularExpression) != nil
        })
      else {
        throw ReleasePackageError.verification("evidence pack failed its privacy boundary")
      }
    }
  }

  private func digestFile(_ url: URL, label: String) throws -> String {
    Digests.sha256(try Self.privateFileData(url, label: label))
  }

  private func digestPrivateFile(_ url: URL, label: String) throws -> String {
    try digestFile(url, label: label)
  }

  private static func privateFileData(_ url: URL, label: String) throws -> Data {
    let physical = try ReleasePathAuthority.absoluteURL(url.path, label: label)
    let descriptor = open(physical.path, O_RDONLY | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open " + label)
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    var info = stat()
    guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, info.st_uid == getuid(), (info.st_mode & 0o7777) == 0o600
    else {
      try? handle.close()
      throw ReleasePackageError.unsafePath(label + " must be one owner-private file")
    }
    let data = try handle.readToEnd() ?? Data()
    try handle.close()
    guard data.count == Int(info.st_size) else {
      throw ReleasePackageError.verification(label + " changed while reading")
    }
    return data
  }

  public static func currentTimestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
  }
}
