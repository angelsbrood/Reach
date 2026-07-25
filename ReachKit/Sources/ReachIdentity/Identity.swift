import Foundation
import Security

public enum IdentityError: Error, Sendable {
    case pkcs12ImportFailed(OSStatus)
    case malformedCertificate
    case importFailed(String)
    case keychainAddFailed(OSStatus)
    case identityNotFound(OSStatus)
}

/// Loading and assembling Security-framework identity objects. Phase 1
/// provisions identities by hand (`reachd ca issue-client` → PKCS#12); the
/// ceremony replaces this with SecureEnclave keys and issued certificates.
public enum IdentityStore {
    /// `SecPKCS12Import` is not safe to call concurrently: two imports in
    /// flight at once return `errSecPkcs12VerifyFailure` on material that
    /// verifies perfectly alone, or — worse — `errSecSuccess` with an empty
    /// item list, which reads like a malformed archive rather than a race.
    /// Imports are rare (one per identity materialized), so a lock costs
    /// nothing and removes a failure that looks like bad key material.
    private static let importLock = NSLock()

    public static func identity(fromPKCS12 data: Data, passphrase: String) throws -> SecIdentity {
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: passphrase] as CFDictionary
        importLock.lock()
        let status = SecPKCS12Import(data as CFData, options, &items)
        importLock.unlock()
        guard status == errSecSuccess,
              let array = items as? [[String: Any]],
              let first = array.first,
              let identityRef = first[kSecImportItemIdentity as String]
        else {
            throw IdentityError.pkcs12ImportFailed(status)
        }
        return identityRef as! SecIdentity
    }

    public static func certificate(fromDER data: Data) throws -> SecCertificate {
        guard let certificate = SecCertificateCreateWithData(nil, data as CFData) else {
            throw IdentityError.malformedCertificate
        }
        return certificate
    }

    public static func der(of certificate: SecCertificate) -> Data {
        SecCertificateCopyData(certificate) as Data
    }
}
