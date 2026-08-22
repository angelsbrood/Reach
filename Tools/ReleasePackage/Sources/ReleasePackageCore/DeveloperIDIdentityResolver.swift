import CryptoKit
import Foundation
import LocalAuthentication
import Security

@_silgen_name("SecKeychainCopyDomainDefault")
private func reachSecKeychainCopyDomainDefault(
  _ domain: Int32,
  _ keychain: UnsafeMutablePointer<SecKeychain?>
) -> OSStatus

@_silgen_name("SecKeychainGetPath")
private func reachSecKeychainGetPath(
  _ keychain: SecKeychain?,
  _ pathLength: UnsafeMutablePointer<UInt32>,
  _ path: UnsafeMutablePointer<CChar>
) -> OSStatus

private let userKeychainPreferencesDomain: Int32 = 0  // kSecPreferencesDomainUser

struct DeveloperIDIdentityCandidate: Equatable, Sendable {
  let authority: SigningCertificateAuthority
  let trusted: Bool
  let hasPrivateKey: Bool
  let expectedG2Chain: Bool
}

enum DeveloperIDTrustPolicy: Equatable, Sendable {
  case appleCodeSigning
  case basicX509
}

extension DeveloperIDClass {
  var trustPolicy: DeveloperIDTrustPolicy {
    switch self {
    case .application: .appleCodeSigning
    case .installer: .basicX509
    }
  }
}

public struct DeveloperIDIdentityPair: Equatable, Sendable {
  public let application: SigningCertificateAuthority
  public let installer: SigningCertificateAuthority

  public init(
    application: SigningCertificateAuthority,
    installer: SigningCertificateAuthority
  ) {
    self.application = application
    self.installer = installer
  }
}

struct DeveloperIDIdentityInventory: Sendable {
  let candidates: [DeveloperIDIdentityCandidate]
  let loginKeychainPath: String
}

struct DeveloperIDSigningContext: Sendable {
  let identities: DeveloperIDIdentityPair
  let loginKeychainPath: String
}

protocol DeveloperIDIdentityProviding {
  func inventory() throws -> DeveloperIDIdentityInventory
}

struct SecurityDeveloperIDIdentityProvider: DeveloperIDIdentityProviding {
  func inventory() throws -> DeveloperIDIdentityInventory {
    // The typed declaration is deprecated, but Security has no modern API
    // that narrows an identity query to the user's default login Keychain.
    // Bind the stable C symbol directly so this release boundary neither
    // searches every configured keychain nor selects by a display name.
    var loginKeychain: SecKeychain?
    let defaultStatus = reachSecKeychainCopyDomainDefault(
      userKeychainPreferencesDomain, &loginKeychain)
    guard defaultStatus == errSecSuccess, let loginKeychain else {
      throw ReleasePackageError.verification(
        "default login Keychain lookup failed with status \(defaultStatus)")
    }
    let loginKeychainPath = try canonicalPath(loginKeychain)
    let authentication = LAContext()
    authentication.interactionNotAllowed = true
    let query: [CFString: Any] = [
      kSecClass: kSecClassIdentity,
      kSecMatchLimit: kSecMatchLimitAll,
      kSecMatchSearchList: [loginKeychain],
      kSecReturnRef: true,
      kSecAttrSynchronizable: kCFBooleanFalse as Any,
      kSecUseAuthenticationContext: authentication,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return DeveloperIDIdentityInventory(candidates: [], loginKeychainPath: loginKeychainPath)
    }
    guard status == errSecSuccess else {
      throw ReleasePackageError.verification(
        "login Keychain identity query failed with status \(status)")
    }
    guard let identities = result as? [SecIdentity] else {
      throw ReleasePackageError.verification("login Keychain returned malformed identities")
    }
    return try DeveloperIDIdentityInventory(
      candidates: identities.compactMap(inspect),
      loginKeychainPath: loginKeychainPath
    )
  }

  private func canonicalPath(_ keychain: SecKeychain) throws -> String {
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    var length = UInt32(buffer.count)
    let status = buffer.withUnsafeMutableBufferPointer {
      reachSecKeychainGetPath(keychain, &length, $0.baseAddress!)
    }
    guard status == errSecSuccess, length > 0, length < buffer.count else {
      throw ReleasePackageError.verification(
        "default login Keychain path lookup failed with status \(status)")
    }
    let path = try decodePath(buffer, length: Int(length))
    guard path.hasPrefix("/") else {
      throw ReleasePackageError.verification("default login Keychain path is malformed")
    }
    var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard realpath(path, &resolved) != nil else {
      throw ReleasePackageError.verification("default login Keychain path cannot be resolved")
    }
    guard let terminator = resolved.firstIndex(of: 0) else {
      throw ReleasePackageError.verification("resolved login Keychain path is malformed")
    }
    let physical = try decodePath(resolved, length: terminator)
    guard physical.utf8.elementsEqual(path.utf8) else {
      throw ReleasePackageError.verification(
        "default login Keychain path is not in its physical canonical spelling")
    }
    return physical
  }

  private func decodePath(_ buffer: [CChar], length: Int) throws -> String {
    guard buffer.indices.contains(length) else {
      throw ReleasePackageError.verification("default login Keychain path length is unsafe")
    }
    let bytes = buffer.prefix(length).map { UInt8(bitPattern: $0) }
    guard let value = String(bytes: bytes, encoding: .utf8), !value.contains("\0") else {
      throw ReleasePackageError.verification("default login Keychain path is not UTF-8")
    }
    return value
  }

  private func inspect(_ identity: SecIdentity) throws -> DeveloperIDIdentityCandidate? {
    var certificate: SecCertificate?
    guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
      let certificate
    else {
      throw ReleasePackageError.verification("Developer ID identity has no certificate")
    }
    let certificateData = SecCertificateCopyData(certificate) as Data
    let policyOIDs = try DERObjectIdentifiers.values(in: certificateData)
    let classes = try DeveloperIDClass.allCases.filter {
      policyOIDs.contains(try DERObjectIdentifiers.encode($0.policyOID))
    }
    guard !classes.isEmpty else { return nil }
    guard classes.count == 1, let certificateClass = classes.first else {
      throw ReleasePackageError.verification("Developer ID certificate class is ambiguous")
    }

    let teamIDs = organizationalUnits(certificate).filter {
      $0.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil
    }
    guard Set(teamIDs).count == 1, let teamID = teamIDs.first else {
      throw ReleasePackageError.verification("Developer ID certificate Team ID is ambiguous")
    }
    var privateKey: SecKey?
    let hasPrivateKey = SecIdentityCopyPrivateKey(identity, &privateKey) == errSecSuccess

    // Developer ID Application certificates are executable-signing
    // identities, while Developer ID Installer certificates are package-
    // signing identities. Security exposes a public executable policy but no
    // corresponding public Installer-package policy. The exact Apple policy
    // OID above establishes the Installer class; basic X.509 evaluation then
    // establishes its current trusted chain without misclassifying it as an
    // executable certificate.
    let policy: SecPolicy? =
      switch certificateClass.trustPolicy {
      case .appleCodeSigning:
        SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, nil)
      case .basicX509:
        SecPolicyCreateBasicX509()
      }
    guard let policy else {
      throw ReleasePackageError.verification(
        "Developer ID trust policy could not be constructed")
    }
    var trust: SecTrust?
    guard SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess,
      let trust
    else {
      throw ReleasePackageError.verification("Developer ID trust could not be constructed")
    }
    SecTrustSetNetworkFetchAllowed(trust, false)
    let trusted = SecTrustEvaluateWithError(trust, nil)
    let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
    let expectedG2 = Self.hasExactDeveloperIDG2Chain(
      subjectSummaries: chain.map {
        (SecCertificateCopySubjectSummary($0) as String?) ?? ""
      },
      organizationalUnits: chain.map(organizationalUnits))
    let chainHashes = chain.map { value in
      Digests.sha256(SecCertificateCopyData(value) as Data)
    }
    guard let notBefore = SecCertificateCopyNotValidBeforeDate(certificate) as Date?,
      let notAfter = SecCertificateCopyNotValidAfterDate(certificate) as Date?
    else {
      throw ReleasePackageError.verification("Developer ID validity interval is unavailable")
    }
    let authority = SigningCertificateAuthority(
      certificateClass: certificateClass,
      policyOID: certificateClass.policyOID,
      certificateSHA1: sha1(SecCertificateCopyData(certificate) as Data),
      teamID: teamID,
      notBeforeUTC: timestamp(notBefore),
      notAfterUTC: timestamp(notAfter),
      chainSHA256: chainHashes
    )
    try authority.validate()
    return .init(
      authority: authority,
      trusted: trusted,
      hasPrivateKey: hasPrivateKey,
      expectedG2Chain: expectedG2
    )
  }

  private func organizationalUnits(_ certificate: SecCertificate) -> [String] {
    guard
      let values = SecCertificateCopyValues(
        certificate, [kSecOIDX509V1SubjectName] as CFArray, nil) as? [AnyHashable: Any]
    else { return [] }
    var result: [String] = []
    collectOrganizationalUnits(values, into: &result)
    return result
  }

  static func hasExactDeveloperIDG2Chain(
    subjectSummaries: [String],
    organizationalUnits: [[String]]
  ) -> Bool {
    guard subjectSummaries.count == 3, organizationalUnits.count == 3 else { return false }
    return subjectSummaries[1] == "Developer ID Certification Authority"
      && organizationalUnits[1] == ["G2"]
      && subjectSummaries[2] == "Apple Root CA"
      && organizationalUnits[2] == ["Apple Certification Authority"]
  }

  private func collectOrganizationalUnits(_ value: Any, into result: inout [String]) {
    if let dictionary = value as? [AnyHashable: Any] {
      let label = dictionary[kSecPropertyKeyLabel] as? String
      if label == "Organizational Unit" || label == "2.5.4.11",
        let unit = dictionary[kSecPropertyKeyValue] as? String
      {
        result.append(unit)
      }
      for child in dictionary.values { collectOrganizationalUnits(child, into: &result) }
    } else if let array = value as? [Any] {
      for child in array { collectOrganizationalUnits(child, into: &result) }
    }
  }

  private func sha1(_ data: Data) -> String {
    Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private func timestamp(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: date)
  }
}

enum DERObjectIdentifiers {
  static func values(in data: Data) throws -> Set<Data> {
    var result = Set<Data>()
    try walk(data, range: data.startIndex..<data.endIndex, result: &result)
    return result
  }

  static func encode(_ value: String) throws -> Data {
    let pieces = value.split(separator: ".")
    guard pieces.count >= 2,
      let first = UInt64(pieces[0]),
      let second = UInt64(pieces[1]),
      first <= 2,
      first == 2 || second <= 39
    else {
      throw ReleasePackageError.verification("Developer ID policy OID is malformed")
    }
    var bytes = encodeArc(first * 40 + second)
    for piece in pieces.dropFirst(2) {
      guard let arc = UInt64(piece) else {
        throw ReleasePackageError.verification("Developer ID policy OID is malformed")
      }
      bytes.append(contentsOf: encodeArc(arc))
    }
    return Data(bytes)
  }

  private static func walk(
    _ data: Data,
    range: Range<Data.Index>,
    result: inout Set<Data>
  ) throws {
    var cursor = range.lowerBound
    while cursor < range.upperBound {
      let tag = data[cursor]
      cursor += 1
      let length = try readLength(data, cursor: &cursor, limit: range.upperBound)
      guard length <= range.upperBound - cursor else {
        throw ReleasePackageError.verification("Developer ID certificate DER is truncated")
      }
      let valueRange = cursor..<(cursor + length)
      if tag == 0x06 {
        result.insert(data.subdata(in: valueRange))
      } else if tag & 0x20 != 0 {
        try walk(data, range: valueRange, result: &result)
      }
      cursor = valueRange.upperBound
    }
  }

  private static func readLength(
    _ data: Data,
    cursor: inout Data.Index,
    limit: Data.Index
  ) throws -> Int {
    guard cursor < limit else {
      throw ReleasePackageError.verification("Developer ID certificate DER has no length")
    }
    let first = data[cursor]
    cursor += 1
    if first & 0x80 == 0 { return Int(first) }
    let count = Int(first & 0x7f)
    guard count > 0, count <= MemoryLayout<Int>.size, count <= limit - cursor else {
      throw ReleasePackageError.verification("Developer ID certificate DER length is unsafe")
    }
    var value = 0
    for _ in 0..<count {
      guard value <= (Int.max >> 8) else {
        throw ReleasePackageError.verification("Developer ID certificate DER length overflowed")
      }
      value = (value << 8) | Int(data[cursor])
      cursor += 1
    }
    return value
  }

  private static func encodeArc(_ value: UInt64) -> [UInt8] {
    if value == 0 { return [0] }
    var value = value
    var bytes: [UInt8] = []
    while value > 0 {
      bytes.append(UInt8(value & 0x7f))
      value >>= 7
    }
    bytes.reverse()
    if bytes.count > 1 {
      for index in bytes.indices.dropLast() { bytes[index] |= 0x80 }
    }
    return bytes
  }
}

public struct DeveloperIDIdentityResolver {
  private let provider: any DeveloperIDIdentityProviding

  public init() {
    provider = SecurityDeveloperIDIdentityProvider()
  }

  init(provider: any DeveloperIDIdentityProviding) {
    self.provider = provider
  }

  public func resolve() throws -> DeveloperIDIdentityPair {
    try Self.select(provider.inventory().candidates, at: Date())
  }

  func resolveSigningContext() throws -> DeveloperIDSigningContext {
    let inventory = try provider.inventory()
    return try DeveloperIDSigningContext(
      identities: Self.select(inventory.candidates, at: Date()),
      loginKeychainPath: inventory.loginKeychainPath
    )
  }

  static func select(_ candidates: [DeveloperIDIdentityCandidate], at date: Date = Date()) throws
    -> DeveloperIDIdentityPair
  {
    let usable = candidates.filter { candidate in
      candidate.trusted && candidate.hasPrivateKey && candidate.expectedG2Chain
        && candidate.authority.isValid(at: date)
    }
    let applications = usable.filter { $0.authority.certificateClass == .application }
    let installers = usable.filter { $0.authority.certificateClass == .installer }
    guard applications.count == 1 else {
      throw ReleasePackageError.verification(
        "expected exactly one valid Developer ID Application identity; found \(applications.count)")
    }
    guard installers.count == 1 else {
      throw ReleasePackageError.verification(
        "expected exactly one valid Developer ID Installer identity; found \(installers.count)")
    }
    let application = applications[0].authority
    let installer = installers[0].authority
    guard application.teamID == installer.teamID else {
      throw ReleasePackageError.verification("Developer ID identity classes have different teams")
    }
    return DeveloperIDIdentityPair(application: application, installer: installer)
  }
}
