import CryptoKit
import Darwin
import Foundation
import Security

struct CodeSignatureInspector {
  private let runner: ProcessRunner

  init(runner: ProcessRunner) {
    self.runner = runner
  }

  func inspectLeaf(
    _ executable: URL,
    relativePath: String,
    expectedIdentifier: String,
    expectedCertificate: SigningCertificateAuthority,
    logDirectory: URL
  ) throws -> SignedLeafAuthority {
    _ = try runner.run(
      "/usr/bin/codesign", ["--verify", "--strict", "--verbose=4", executable.path],
      logURL: logDirectory.appendingPathComponent("codesign-verify-\(expectedIdentifier).log"))
    var staticCode: SecStaticCode?
    guard
      SecStaticCodeCreateWithPath(
        executable as CFURL, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
      let staticCode
    else {
      throw ReleasePackageError.verification("cannot inspect signed code \(expectedIdentifier)")
    }
    let validityFlags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
    guard SecStaticCodeCheckValidity(staticCode, validityFlags, nil) == errSecSuccess else {
      throw ReleasePackageError.verification("strict signed-code validity failed")
    }
    var information: CFDictionary?
    let informationFlags = SecCSFlags(
      rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    guard
      SecCodeCopySigningInformation(staticCode, informationFlags, &information) == errSecSuccess,
      let values = information as? [CFString: Any]
    else {
      throw ReleasePackageError.verification("signed-code metadata is unavailable")
    }
    guard let identifier = values[kSecCodeInfoIdentifier] as? String,
      identifier == expectedIdentifier,
      let teamID = values[kSecCodeInfoTeamIdentifier] as? String,
      teamID == expectedCertificate.teamID,
      let flags = values[kSecCodeInfoFlags] as? NSNumber,
      (flags.uint32Value & 0x0001_0000) != 0,
      let timestamp = values[kSecCodeInfoTimestamp] as? Date,
      let cdHash = values[kSecCodeInfoUnique] as? Data,
      let certificates = values[kSecCodeInfoCertificates] as? [SecCertificate],
      !certificates.isEmpty
    else {
      throw ReleasePackageError.verification(
        "signed leaf lacks identifier, team, runtime, timestamp, CDHash, or chain")
    }
    let certificateData = certificates.map { SecCertificateCopyData($0) as Data }
    let leafSHA1 = sha1(certificateData[0])
    guard leafSHA1 == expectedCertificate.certificateSHA1,
      Self.certificateChainMatches(
        certificateData, expectedSHA256: expectedCertificate.chainSHA256)
    else {
      throw ReleasePackageError.verification(
        "signed leaf used the wrong Developer ID certificate chain")
    }
    let entitlements = values[kSecCodeInfoEntitlementsDict] as? [String: Any]
    guard entitlements == nil || entitlements?.isEmpty == true else {
      throw ReleasePackageError.verification("signed leaf contains forbidden entitlements")
    }
    guard let requirementValue = values[kSecCodeInfoDesignatedRequirement] else {
      throw ReleasePackageError.verification("signed leaf has no designated requirement")
    }
    let requirementObject = requirementValue as CFTypeRef
    guard CFGetTypeID(requirementObject) == SecRequirementGetTypeID() else {
      throw ReleasePackageError.verification("signed leaf designated requirement is malformed")
    }
    let requirement = unsafeDowncast(requirementObject, to: SecRequirement.self)
    var requirementText: CFString?
    guard
      SecRequirementCopyString(requirement, SecCSFlags(rawValue: 0), &requirementText)
        == errSecSuccess,
      let designatedRequirement = requirementText as String?
    else {
      throw ReleasePackageError.verification("designated requirement cannot be rendered")
    }
    guard
      Self.designatedRequirementIsBound(
        designatedRequirement,
        identifier: expectedIdentifier,
        teamID: teamID,
        policyOID: expectedCertificate.policyOID)
    else {
      throw ReleasePackageError.verification("designated requirement authority changed")
    }
    let file = try runner.run(
      "/usr/bin/file", [executable.path],
      logURL: logDirectory.appendingPathComponent("file-\(expectedIdentifier).log"))
    guard file.output.contains("Mach-O 64-bit executable arm64"),
      !file.output.contains("universal"),
      !file.output.contains("x86_64")
    else {
      throw ReleasePackageError.verification("signed leaf is not arm64-only")
    }
    return SignedLeafAuthority(
      path: relativePath,
      artifact: try artifact(relativePath, executable),
      identifier: identifier,
      architecture: "arm64",
      cdHash: cdHash.map { String(format: "%02x", $0) }.joined(),
      designatedRequirement: designatedRequirement,
      teamID: teamID,
      certificateSHA1: leafSHA1,
      secureTimestampUTC: timestampUTC(timestamp),
      runtime: true,
      entitlementsSHA256: SignedReleaseContract.emptyEntitlementsSHA256
    )
  }

  func inspectInstallerPackage(
    _ package: URL,
    expectedCertificate: SigningCertificateAuthority,
    logDirectory: URL
  ) throws -> String {
    let result = try runner.run(
      "/usr/sbin/pkgutil", ["--check-signature", package.path],
      logURL: logDirectory.appendingPathComponent("pkgutil-check-signature.log"))
    let detail = result.output + result.errorOutput
    guard Self.hasTrustedInstallerStatus(detail),
      detail.contains("Developer ID Installer"),
      detail.contains(expectedCertificate.teamID)
    else {
      throw ReleasePackageError.verification("Installer signature chain is not trusted")
    }
    let toc = logDirectory.appendingPathComponent("signed-package-toc.xml")
    _ = try runner.run(
      "/usr/bin/xar", ["--dump-toc=\(toc.path)", "-f", package.path],
      logURL: logDirectory.appendingPathComponent("xar-signed-toc.log"))
    let tocText = String(decoding: try Data(contentsOf: toc), as: UTF8.self)
    let certificates = try Self.certificateDER(fromXARTOC: tocText)
    guard let leaf = certificates.first,
      sha1(leaf) == expectedCertificate.certificateSHA1,
      Self.embeddedCertificateChainsMatch(
        certificates, expectedSHA256: expectedCertificate.chainSHA256)
    else {
      throw ReleasePackageError.verification(
        "Installer package used the wrong certificate chain")
    }
    return try Self.trustedInstallerTimestampUTC(from: detail)
  }

  static func trustedInstallerTimestampUTC(from value: String) throws -> String {
    let prefix = "Signed with a trusted timestamp on: "
    let lines = value.split(separator: "\n").map {
      String($0).trimmingCharacters(in: .whitespacesAndNewlines)
    }
    guard let line = lines.first(where: { $0.hasPrefix(prefix) }) else {
      throw ReleasePackageError.verification("Installer package lacks a secure timestamp")
    }
    let timestamp = String(line.dropFirst(prefix.count))
    guard
      timestamp.range(
        of: "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}$",
        options: .regularExpression) != nil
    else {
      throw ReleasePackageError.verification("Installer package timestamp is malformed")
    }
    let input = DateFormatter()
    input.calendar = Calendar(identifier: .gregorian)
    input.locale = Locale(identifier: "en_US_POSIX")
    input.timeZone = TimeZone(secondsFromGMT: 0)
    input.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
    guard let date = input.date(from: timestamp) else {
      throw ReleasePackageError.verification("Installer package timestamp is malformed")
    }
    let output = ISO8601DateFormatter()
    output.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    output.timeZone = TimeZone(secondsFromGMT: 0)
    return output.string(from: date)
  }

  static func certificateDER(fromXARTOC text: String) throws -> [Data] {
    let expression = try NSRegularExpression(
      pattern: "<X509Certificate>([^<]+)</X509Certificate>", options: [])
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    let matches = expression.matches(in: text, range: range)
    var values: [Data] = []
    values.reserveCapacity(matches.count)
    for match in matches {
      guard let valueRange = Range(match.range(at: 1), in: text) else {
        throw ReleasePackageError.verification("Installer package certificate XML is malformed")
      }
      let encoded = text[valueRange].utf8.filter { byte in
        byte != 0x09 && byte != 0x0A && byte != 0x0D && byte != 0x20
      }
      guard !encoded.isEmpty,
        let certificate = Data(base64Encoded: String(decoding: encoded, as: UTF8.self))
      else {
        throw ReleasePackageError.verification("Installer package certificate is malformed")
      }
      values.append(certificate)
    }
    guard !values.isEmpty else {
      throw ReleasePackageError.verification("Installer package certificate chain is absent")
    }
    return values
  }

  static func certificateChainMatches(_ certificates: [Data], expectedSHA256: [String]) -> Bool {
    certificates.map(Digests.sha256) == expectedSHA256
  }

  static func embeddedCertificateChainsMatch(
    _ certificates: [Data],
    expectedSHA256: [String]
  ) -> Bool {
    guard !expectedSHA256.isEmpty,
      !certificates.isEmpty,
      certificates.count.isMultiple(of: expectedSHA256.count)
    else { return false }
    let hashes = certificates.map(Digests.sha256)
    return stride(from: 0, to: hashes.count, by: expectedSHA256.count).allSatisfy { start in
      Array(hashes[start..<(start + expectedSHA256.count)]) == expectedSHA256
    }
  }

  private func artifact(_ path: String, _ file: URL) throws -> ReleaseProvenance.Artifact {
    var info = stat()
    guard lstat(file.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1
    else {
      throw ReleasePackageError.unsafePath("signed artifact must be a single-link regular file")
    }
    return .init(
      path: path,
      size: UInt64(info.st_size),
      sha256: try Digests.sha256(file: file))
  }

  private func sha1(_ data: Data) -> String {
    Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private func timestampUTC(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
  }

  static func designatedRequirementIsBound(
    _ value: String,
    identifier: String,
    teamID: String,
    policyOID: String
  ) -> Bool {
    let escapedIdentifier = NSRegularExpression.escapedPattern(for: identifier)
    let escapedTeam = NSRegularExpression.escapedPattern(for: teamID)
    let identifierPattern = "(?:^|\\s)identifier\\s+\"?\(escapedIdentifier)\"?(?:\\s|$)"
    let teamPattern =
      "certificate\\s+leaf\\[subject\\.OU\\]\\s*=\\s*\"?\(escapedTeam)\"?(?:\\s|$)"
    return value.range(of: identifierPattern, options: .regularExpression) != nil
      && value.contains("anchor apple generic")
      && value.contains("certificate 1[field.1.2.840.113635.100.6.2.6]")
      && value.contains("certificate leaf[field.\(policyOID)]")
      && value.range(of: teamPattern, options: .regularExpression) != nil
  }

  static func hasTrustedInstallerStatus(_ value: String) -> Bool {
    let status = value.split(separator: "\n").map {
      $0.trimmingCharacters(in: .whitespaces)
    }.first { $0.hasPrefix("Status:") }
    return status == "Status: signed by a certificate trusted by macOS"
      || status == "Status: signed by a developer certificate issued by Apple for distribution"
  }
}
