import Darwin
import Foundation

public struct GuestStaticTrustReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let packageSHA256: String
  public let normalizedSemanticSHA256: String
  public let quarantinedCopySHA256: String
  public let quarantineAuthoritySHA256: String
  public let hostFiles: Int
  public let helperFiles: Int
  public let stapleValidated: Bool
  public let localAssessmentPassed: Bool
  public let verdict: String
}

public struct GuestMandatoryInstallReport: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let release: ReleaseVersionMap
  public let packageSHA256: String
  public let choiceDocumentSHA256: String
  public let receiptCount: Int
  public let immutablePathCount: Int
  public let helperRuntime: InstalledHelperRequirement
  public let verdict: String
}

enum MandatoryChoiceDocument {
  static let relativeName = "helper-deselection.plist"

  static func data() -> Data {
    Data(
      """
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <array>
      <dict>
      <key>attributeSetting</key>
      <integer>0</integer>
      <key>choiceAttribute</key>
      <string>selected</string>
      <key>choiceIdentifier</key>
      <string>systems.reach.meshd</string>
      </dict>
      </array>
      </plist>

      """.utf8)
  }

  static func validate(_ data: Data) throws {
    guard data == self.data(),
      let value = try PropertyListSerialization.propertyList(from: data, format: nil)
        as? [[String: Any]], value.count == 1,
      let record = value.first,
      Set(record.keys)
        == ["attributeSetting", "choiceAttribute", "choiceIdentifier"],
      record["attributeSetting"] as? Int == 0,
      record["choiceAttribute"] as? String == "selected",
      record["choiceIdentifier"] as? String == "systems.reach.meshd"
    else {
      throw ReleasePackageError.verification("mandatory-choice document authority changed")
    }
  }
}

/// Executes only the guest cells that are not ordinary package transactions:
/// the quarantined P5 trust join and the explicit helper-deselection attempt.
/// The remaining lifecycle cells use the durable transaction/rig journals.
public struct MacOSGuestAcceptanceCells {
  private let runner: ProcessRunner

  public init(runner: ProcessRunner = .init()) { self.runner = runner }

  public func verifyStaticTrust(
    retainedAuthority: URL,
    scratch: URL,
    output: URL
  ) throws -> GuestStaticTrustReport {
    let entry = try RetainedReleaseCatalogEntry(root: retainedAuthority)
    try SecureFiles.createPrivateDirectory(scratch)
    let package = try entry.packageURL()
    let packageSHA256 = try Digests.sha256(file: package)
    let verified = try SignedReleaseVerifier(runner: runner).verify(
      package: package,
      provenanceURL: retainedAuthority.appendingPathComponent("release-provenance.json"),
      unsignedToolSource: retainedAuthority.appendingPathComponent("unsigned-tool-source"),
      finalizerToolSource: retainedAuthority.appendingPathComponent("finalizer-tool-source"),
      configurationURL: retainedAuthority.appendingPathComponent("release.json"),
      noticeAuthorityURL: retainedAuthority.appendingPathComponent("notices.json"),
      dependencyDepot: retainedAuthority.appendingPathComponent("dependency-depot"),
      scratch: scratch.appendingPathComponent("independent-verification"))
    guard verified.stage == "P5", verified.packageSHA256 == packageSHA256,
      verified.hostFiles == 50, verified.helperFiles == 6,
      !verified.scriptsPresent, !verified.resourcesPresent,
      verified.stapleValidated, verified.localAssessmentPassed
    else {
      throw ReleasePackageError.verification("guest static trust did not verify complete P5")
    }

    let quarantined = scratch.appendingPathComponent("quarantined-reach.pkg")
    guard !FileManager.default.fileExists(atPath: quarantined.path) else {
      throw ReleasePackageError.unsafePath("quarantined package copy already exists")
    }
    try SecureFiles.atomicWrite(
      Data(contentsOf: package, options: [.mappedIfSafe]), to: quarantined)
    let quarantine = "0081;00000000;Reach-S36;https://example.invalid/reach-s36"
    try setQuarantine(quarantine, on: quarantined)
    guard try readQuarantine(from: quarantined).utf8.elementsEqual(quarantine.utf8),
      try Digests.sha256(file: quarantined) == packageSHA256
    else {
      throw ReleasePackageError.verification("quarantine changed package bytes or metadata")
    }
    _ = try runner.run(
      "/usr/sbin/pkgutil", ["--check-signature", quarantined.path],
      timeout: 60, logURL: scratch.appendingPathComponent("pkgutil-signature.log"))
    _ = try runner.run(
      "/usr/bin/xcrun", ["stapler", "validate", quarantined.path],
      timeout: 60, logURL: scratch.appendingPathComponent("stapler-validate.log"))
    _ = try runner.run(
      "/usr/sbin/spctl",
      ["--assess", "--type", "install", "--verbose=4", quarantined.path],
      timeout: 60, logURL: scratch.appendingPathComponent("gatekeeper-assessment.log"))

    let report = GuestStaticTrustReport(
      schemaVersion: 1, release: entry.reference.versions,
      packageSHA256: packageSHA256,
      normalizedSemanticSHA256: verified.normalizedSemanticSHA256,
      quarantinedCopySHA256: try Digests.sha256(file: quarantined),
      quarantineAuthoritySHA256: Digests.sha256(Data(quarantine.utf8)),
      hostFiles: verified.hostFiles, helperFiles: verified.helperFiles,
      stapleValidated: true, localAssessmentPassed: true, verdict: "pass")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: output)
    return report
  }

  public func installWithHelperDeselection(
    retainedAuthority: URL,
    ownerUID: UInt32,
    ownerHome: URL,
    scratch: URL,
    output: URL
  ) throws -> GuestMandatoryInstallReport {
    guard ownerUID != 0, ownerHome.path.hasPrefix("/Users/"),
      ownerHome.path.split(separator: "/").count == 2
    else {
      throw ReleasePackageError.invalidArgument("mandatory-choice owner is invalid")
    }
    let entry = try RetainedReleaseCatalogEntry(root: retainedAuthority)
    try SecureFiles.createPrivateDirectory(scratch)
    let choice = scratch.appendingPathComponent(MandatoryChoiceDocument.relativeName)
    let choiceData = MandatoryChoiceDocument.data()
    try MandatoryChoiceDocument.validate(choiceData)
    try SecureFiles.atomicWrite(choiceData, to: choice)
    _ = try runner.run(
      "/usr/sbin/installer",
      [
        "-applyChoiceChangesXML", choice.path,
        "-pkg", try entry.packageURL().path, "-target", "/",
      ], timeout: 300, logURL: scratch.appendingPathComponent("choice-installer.log"))

    let collector = MacOSInstalledStateCollector(runner: runner)
    let requirements: [InstalledHelperRequirement] = [.absent, .unconfigured]
    var accepted: (InstalledReleaseSnapshot, InstalledHelperRequirement)?
    var refusals: [String] = []
    for requirement in requirements {
      let attempt = scratch.appendingPathComponent("verify-" + requirement.rawValue)
      do {
        let snapshot = try collector.collect(
          retainedAuthority: retainedAuthority,
          policy: .init(
            selectedOwnerUID: ownerUID, selectedOwnerHome: ownerHome.path, host: .unbound,
            helper: requirement, retainedState: .absent),
          ownerHome: ownerHome,
          scratch: attempt.appendingPathComponent("scratch"),
          output: attempt.appendingPathComponent("snapshot.json"))
        accepted = (snapshot, requirement)
        break
      } catch {
        refusals.append(String(describing: error))
      }
    }
    guard let (snapshot, helper) = accepted else {
      throw ReleasePackageError.verification(
        "MANDATORY-CHOICE: explicit helper deselection omitted or changed required authority; "
          + refusals.joined(separator: " | "))
    }
    let report = GuestMandatoryInstallReport(
      schemaVersion: 1, release: entry.reference.versions,
      packageSHA256: entry.reference.p5SHA256,
      choiceDocumentSHA256: Digests.sha256(choiceData),
      receiptCount: snapshot.receipts.count,
      immutablePathCount: snapshot.files.count,
      helperRuntime: helper, verdict: "pass")
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(report), to: output)
    return report
  }

  private func setQuarantine(_ value: String, on url: URL) throws {
    let result = value.utf8CString.withUnsafeBytes { bytes in
      setxattr(
        url.path, "com.apple.quarantine", bytes.baseAddress,
        max(0, bytes.count - 1), 0, XATTR_NOFOLLOW)
    }
    guard result == 0 else {
      throw ReleasePackageError.verification("cannot apply the synthetic quarantine attribute")
    }
  }

  private func readQuarantine(from url: URL) throws -> String {
    let size = getxattr(url.path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW)
    guard size > 0, size <= 1_024 else {
      throw ReleasePackageError.verification("synthetic quarantine attribute is absent")
    }
    var buffer = [UInt8](repeating: 0, count: size)
    let count = buffer.withUnsafeMutableBytes {
      getxattr(url.path, "com.apple.quarantine", $0.baseAddress, size, 0, XATTR_NOFOLLOW)
    }
    guard count == size else {
      throw ReleasePackageError.verification("synthetic quarantine attribute changed")
    }
    return String(decoding: buffer, as: UTF8.self)
  }
}
