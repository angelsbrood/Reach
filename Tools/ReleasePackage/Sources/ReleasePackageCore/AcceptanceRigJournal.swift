import Darwin
import Foundation

public enum AcceptanceRigPhase: String, Codable, Sendable {
  case prepared
  case imageVerified = "image-verified"
  case baseCreated = "base-created"
  case baseProvisioning = "base-provisioning"
  case baseSealed = "base-sealed"
  case cloneCreated = "clone-created"
  case cloneRunning = "clone-running"
  case cloneStopped = "clone-stopped"
  case cloneDeleted = "clone-deleted"
  case baseDeleted = "base-deleted"
  case complete
  case failed
}

/// Durable VM authority is deliberately separate from release artifacts,
/// guest package transactions, and the evidence/teardown journal. It records
/// only hashes and bounded counts; VM paths, guest credentials, IP addresses,
/// host keys, and package bytes never enter this file.
public struct AcceptanceRigJournal: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let runID: String
  public let tartExecutableSHA256: String
  public let phase: AcceptanceRigPhase
  public let transitionIndex: UInt32
  public let cloneEpoch: UInt32
  public let bootEpoch: UInt32
  public let restoreImageAuthoritySHA256: String?
  public let baseConfigurationSHA256: String?
  public let baseProvisioningSHA256: String?
  public let baseSealSHA256: String?
  public let hostAuthoritySHA256: String?
  public let latestInventorySHA256: String?
  public let createdAtUTC: String
  public let updatedAtUTC: String
  public let failureCode: String?

  public init(
    runID: String,
    tartExecutableSHA256: String,
    createdAtUTC: String,
    updatedAtUTC: String
  ) {
    schemaVersion = 1
    self.runID = runID
    self.tartExecutableSHA256 = tartExecutableSHA256
    phase = .prepared
    transitionIndex = 0
    cloneEpoch = 0
    bootEpoch = 0
    restoreImageAuthoritySHA256 = nil
    baseConfigurationSHA256 = nil
    baseProvisioningSHA256 = nil
    baseSealSHA256 = nil
    hostAuthoritySHA256 = nil
    latestInventorySHA256 = nil
    self.createdAtUTC = createdAtUTC
    self.updatedAtUTC = updatedAtUTC
    failureCode = nil
  }

  private init(
    copying current: Self,
    phase: AcceptanceRigPhase,
    cloneEpoch: UInt32? = nil,
    bootEpoch: UInt32? = nil,
    restoreImageAuthoritySHA256: String? = nil,
    baseConfigurationSHA256: String? = nil,
    baseProvisioningSHA256: String? = nil,
    baseSealSHA256: String? = nil,
    hostAuthoritySHA256: String? = nil,
    latestInventorySHA256: String? = nil,
    updatedAtUTC: String,
    failureCode: String? = nil
  ) {
    schemaVersion = current.schemaVersion
    runID = current.runID
    tartExecutableSHA256 = current.tartExecutableSHA256
    self.phase = phase
    transitionIndex = current.transitionIndex + 1
    self.cloneEpoch = cloneEpoch ?? current.cloneEpoch
    self.bootEpoch = bootEpoch ?? current.bootEpoch
    self.restoreImageAuthoritySHA256 =
      restoreImageAuthoritySHA256 ?? current.restoreImageAuthoritySHA256
    self.baseConfigurationSHA256 = baseConfigurationSHA256 ?? current.baseConfigurationSHA256
    self.baseProvisioningSHA256 = baseProvisioningSHA256 ?? current.baseProvisioningSHA256
    self.baseSealSHA256 = baseSealSHA256 ?? current.baseSealSHA256
    self.hostAuthoritySHA256 = hostAuthoritySHA256 ?? current.hostAuthoritySHA256
    self.latestInventorySHA256 = latestInventorySHA256 ?? current.latestInventorySHA256
    createdAtUTC = current.createdAtUTC
    self.updatedAtUTC = updatedAtUTC
    self.failureCode = failureCode
  }

  public func validate() throws {
    let digests = [
      tartExecutableSHA256, restoreImageAuthoritySHA256, baseConfigurationSHA256,
      baseProvisioningSHA256, baseSealSHA256, hostAuthoritySHA256,
      latestInventorySHA256,
    ].compactMap { $0 }
    guard schemaVersion == 1, UUID(uuidString: runID) != nil,
      digests.allSatisfy(Self.validSHA256), !createdAtUTC.isEmpty, !updatedAtUTC.isEmpty,
      (phase == .failed) == (failureCode != nil),
      failureCode == nil
        || failureCode!.range(of: "^[a-z0-9-]{1,64}$", options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("acceptance rig journal is malformed")
    }
    switch phase {
    case .prepared:
      guard restoreImageAuthoritySHA256 == nil, cloneEpoch == 0, bootEpoch == 0 else {
        throw ReleasePackageError.verification("prepared rig already claims image authority")
      }
    case .imageVerified:
      guard restoreImageAuthoritySHA256 != nil else {
        throw ReleasePackageError.verification("verified rig image authority is absent")
      }
    case .baseCreated, .baseProvisioning:
      guard restoreImageAuthoritySHA256 != nil, baseConfigurationSHA256 != nil else {
        throw ReleasePackageError.verification("created base authority is incomplete")
      }
    case .baseSealed, .cloneCreated, .cloneRunning, .cloneStopped, .cloneDeleted,
      .baseDeleted, .complete:
      guard restoreImageAuthoritySHA256 != nil, baseConfigurationSHA256 != nil,
        baseProvisioningSHA256 != nil, baseSealSHA256 != nil
      else {
        throw ReleasePackageError.verification("sealed base authority is incomplete")
      }
    case .failed:
      break
    }
    if [.cloneCreated, .cloneRunning, .cloneStopped, .cloneDeleted].contains(phase) {
      guard cloneEpoch > 0 else {
        throw ReleasePackageError.verification("clone phase lacks a clone epoch")
      }
    }
    if [.cloneRunning, .cloneStopped].contains(phase) {
      guard bootEpoch > 0 else {
        throw ReleasePackageError.verification("running clone phase lacks a boot epoch")
      }
    }
    if [
      .prepared, .imageVerified, .baseCreated, .baseProvisioning, .baseSealed,
    ].contains(phase) {
      guard hostAuthoritySHA256 == nil else {
        throw ReleasePackageError.verification(
          "rig bound host authority before the acceptance clone was running")
      }
    }
    if phase == .cloneCreated, cloneEpoch == 1, hostAuthoritySHA256 != nil {
      throw ReleasePackageError.verification(
        "first clone bound host authority before it was running")
    }
    if hostAuthoritySHA256 != nil {
      guard cloneEpoch > 0,
        bootEpoch > 0 || (phase == .cloneCreated && cloneEpoch > 1)
      else {
        throw ReleasePackageError.verification(
          "rig host authority lacks its clone and boot epoch")
      }
    }
  }

  public func imageVerified(
    authoritySHA256: String, inventorySHA256: String, at timestamp: String
  ) throws -> Self {
    try transition(
      from: [.prepared], to: .imageVerified,
      restoreImageAuthoritySHA256: authoritySHA256,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func baseCreated(
    configurationSHA256: String, inventorySHA256: String, at timestamp: String
  ) throws -> Self {
    try transition(
      from: [.imageVerified], to: .baseCreated,
      baseConfigurationSHA256: configurationSHA256,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func baseProvisioningStarted(
    inventorySHA256: String, at timestamp: String
  ) throws -> Self {
    try transition(
      from: [.baseCreated], to: .baseProvisioning,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func baseSealed(
    provisioningSHA256: String,
    sealSHA256: String,
    inventorySHA256: String,
    at timestamp: String
  ) throws -> Self {
    try transition(
      from: [.baseProvisioning], to: .baseSealed,
      baseProvisioningSHA256: provisioningSHA256,
      baseSealSHA256: sealSHA256,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func cloneCreated(inventorySHA256: String, at timestamp: String) throws -> Self {
    let nextEpoch = cloneEpoch.addingReportingOverflow(1)
    guard !nextEpoch.overflow else {
      throw ReleasePackageError.verification("clone epoch overflowed")
    }
    return try transition(
      from: [.baseSealed, .cloneDeleted], to: .cloneCreated,
      cloneEpoch: nextEpoch.partialValue,
      bootEpoch: 0,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func cloneRunning(inventorySHA256: String, at timestamp: String) throws -> Self {
    let nextEpoch = bootEpoch.addingReportingOverflow(1)
    guard !nextEpoch.overflow else {
      throw ReleasePackageError.verification("clone boot epoch overflowed")
    }
    return try transition(
      from: [.cloneCreated, .cloneStopped], to: .cloneRunning,
      bootEpoch: nextEpoch.partialValue,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func cloneStopped(inventorySHA256: String, at timestamp: String) throws -> Self {
    try transition(
      from: [.cloneRunning], to: .cloneStopped,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func bindingHostAuthority(
    sha256: String, at timestamp: String
  ) throws -> Self {
    try validate()
    guard phase == .cloneRunning, hostAuthoritySHA256 == nil,
      Self.validSHA256(sha256), !timestamp.isEmpty
    else {
      throw ReleasePackageError.verification(
        "host authority must bind once while the acceptance clone is running")
    }
    let value = Self(
      copying: self, phase: phase, hostAuthoritySHA256: sha256,
      updatedAtUTC: timestamp)
    try value.validate()
    return value
  }

  public func cloneDeleted(inventorySHA256: String, at timestamp: String) throws -> Self {
    try transition(
      from: [.cloneStopped, .cloneCreated], to: .cloneDeleted,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func baseDeleted(inventorySHA256: String, at timestamp: String) throws -> Self {
    try transition(
      from: [.baseSealed, .cloneDeleted], to: .baseDeleted,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func completed(inventorySHA256: String, at timestamp: String) throws -> Self {
    try transition(
      from: [.baseDeleted], to: .complete,
      latestInventorySHA256: inventorySHA256, at: timestamp)
  }

  public func failing(code: String, inventorySHA256: String, at timestamp: String) throws -> Self {
    try validate()
    guard phase != .complete, phase != .failed, Self.validSHA256(inventorySHA256),
      !timestamp.isEmpty,
      code.range(of: "^[a-z0-9-]{1,64}$", options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("rig failure is malformed")
    }
    let value = Self(
      copying: self, phase: .failed, latestInventorySHA256: inventorySHA256,
      updatedAtUTC: timestamp, failureCode: code)
    try value.validate()
    return value
  }

  private func transition(
    from allowed: Set<AcceptanceRigPhase>,
    to next: AcceptanceRigPhase,
    cloneEpoch: UInt32? = nil,
    bootEpoch: UInt32? = nil,
    restoreImageAuthoritySHA256: String? = nil,
    baseConfigurationSHA256: String? = nil,
    baseProvisioningSHA256: String? = nil,
    baseSealSHA256: String? = nil,
    latestInventorySHA256: String,
    at timestamp: String
  ) throws -> Self {
    try validate()
    let provided = [
      restoreImageAuthoritySHA256, baseConfigurationSHA256, baseProvisioningSHA256,
      baseSealSHA256, latestInventorySHA256,
    ].compactMap { $0 }
    guard allowed.contains(phase), !timestamp.isEmpty,
      provided.allSatisfy(Self.validSHA256)
    else {
      throw ReleasePackageError.verification("rig transition is invalid")
    }
    let value = Self(
      copying: self, phase: next, cloneEpoch: cloneEpoch, bootEpoch: bootEpoch,
      restoreImageAuthoritySHA256: restoreImageAuthoritySHA256,
      baseConfigurationSHA256: baseConfigurationSHA256,
      baseProvisioningSHA256: baseProvisioningSHA256,
      baseSealSHA256: baseSealSHA256,
      latestInventorySHA256: latestInventorySHA256, updatedAtUTC: timestamp)
    try value.validate()
    return value
  }

  private static func validSHA256(_ value: String) -> Bool {
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  }
}

public struct AcceptanceRigJournalStore {
  public let url: URL

  public init(url: URL) { self.url = url }

  public func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
    try SecureFiles.createPrivateDirectory(url.deletingLastPathComponent())
    let lockURL = URL(fileURLWithPath: url.path + ".lock")
    let descriptor = open(lockURL.path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else {
      throw ReleasePackageError.verification("cannot open rig journal lock")
    }
    defer { close(descriptor) }
    guard fchmod(descriptor, 0o600) == 0, flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      throw ReleasePackageError.verification("rig journal is already in use")
    }
    defer { _ = flock(descriptor, LOCK_UN) }
    return try body()
  }

  public func load() throws -> AcceptanceRigJournal? {
    var info = stat()
    guard lstat(url.path, &info) == 0 else {
      if errno == ENOENT { return nil }
      throw ReleasePackageError.verification("cannot inspect rig journal")
    }
    guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1,
      (info.st_mode & 0o7777) == 0o600
    else {
      throw ReleasePackageError.unsafePath(
        "rig journal must be a mode-0600 single-link file")
    }
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(AcceptanceRigJournal.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("rig journal is not canonical JSON")
    }
    try value.validate()
    return value
  }

  public func create(_ value: AcceptanceRigJournal) throws {
    try value.validate()
    guard try load() == nil else {
      throw ReleasePackageError.verification("rig journal already exists")
    }
    try write(value)
  }

  public func write(_ value: AcceptanceRigJournal) throws {
    try value.validate()
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(value), to: url)
  }
}
