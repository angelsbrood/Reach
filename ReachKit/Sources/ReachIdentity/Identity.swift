import Foundation
import Security

public enum IdentityError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case pkcs12ImportFailed(OSStatus)
    case malformedCertificate
    case importFailed(String)
    case keychainAddFailed(OSStatus)
    case identityNotFound(OSStatus)

    public var description: String {
        switch self {
        case .pkcs12ImportFailed(let status):
            "the PKCS#12 archive would not import: \(Self.name(for: status))"
        case .malformedCertificate:
            "the certificate bytes are not a certificate this platform will parse"
        case .importFailed(let detail):
            "could not assemble an identity from the issued material: \(detail)"
        case .keychainAddFailed(let status):
            "the keychain refused the key or certificate: \(Self.name(for: status))"
        case .identityNotFound(let status):
            "no identity is stored under that label: \(Self.name(for: status))"
        }
    }

    /// An `OSStatus` printed as a bare number is a number to go and look up.
    /// `SecCopyErrorMessageString` knows most of them by name.
    private static func name(for status: OSStatus) -> String {
        guard let text = SecCopyErrorMessageString(status, nil) as String? else {
            return "OSStatus \(status)"
        }
        return "\(text) (OSStatus \(status))"
    }

    public var errorDescription: String? { description }
}

/// One lock for every keychain touch in the process.
///
/// The Security framework does not tolerate concurrent access to the same
/// keychain from one process. `SecPKCS12Import` is the loudest offender —
/// two at once return `errSecPkcs12VerifyFailure` on material that verifies
/// perfectly alone, or `errSecSuccess` with an *empty item list*, which reads
/// like a malformed archive rather than a race — but it is not the only one.
/// An import also fails that way when a `SecItemDelete` lands underneath it,
/// so serializing imports against each other and leaving deletes free still
/// leaves a window: narrower, and therefore harder to attribute.
///
/// Scope this to every entry point rather than to the call that happens to
/// appear in the error, and the whole class goes away. Recursive because
/// the composed operations nest — `store` calls `find` — and each of these
/// is a synchronous call chain, so re-entry is on the same thread.
public enum KeychainLock {
    private static let lock = NSRecursiveLock()

    public static func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    /// For call sites that want the whole function body held: pair with
    /// `defer { KeychainLock.release() }` on the following line.
    public static func acquire() { lock.lock() }
    public static func release() { lock.unlock() }
}

/// Loading and assembling Security-framework identity objects. Phase 1
/// provisions identities by hand (`reachd ca issue-client` → PKCS#12); the
/// ceremony replaces this with SecureEnclave keys and issued certificates.
public enum IdentityStore {
    public static func identity(fromPKCS12 data: Data, passphrase: String) throws -> SecIdentity {
        // One attempt. Retrying was measured (three attempts, 20 runs) and
        // never once recovered: when this fails it fails identically on the
        // same bytes, so a retry buys nothing but three times the work at the
        // worst moment. What IS known about the failure is recorded on
        // `KeychainLock` and in PLAN.md; it is not concurrency and it is not
        // the archive being malformed.
        try importOnce(data, passphrase: passphrase)
    }

    private static func importOnce(_ data: Data, passphrase: String) throws -> SecIdentity {
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: passphrase] as CFDictionary
        let status = KeychainLock.withLock { SecPKCS12Import(data as CFData, options, &items) }
        // Four different failures used to arrive as pkcs12ImportFailed(0),
        // which reads as "bad archive" and is not what any of them mean.
        // Separated because the error value is the diagnosis: a non-zero
        // status is the archive or the passphrase; success with nothing in it
        // is the framework, and says so.
        guard status == errSecSuccess else {
            throw IdentityError.pkcs12ImportFailed(status)
        }
        guard let array = items as? [[String: Any]] else {
            throw IdentityError.importFailed(
                "SecPKCS12Import returned errSecSuccess with \(items == nil ? "no item array at all" : "an item array of an unexpected shape") (\(data.count) bytes in)"
            )
        }
        guard let first = array.first else {
            throw IdentityError.importFailed(
                "SecPKCS12Import returned errSecSuccess and an EMPTY item list (\(data.count) bytes in)"
            )
        }
        guard let identityRef = first[kSecImportItemIdentity as String] else {
            throw IdentityError.importFailed(
                "SecPKCS12Import returned an item carrying no identity; keys present: \(first.keys.sorted().joined(separator: ", "))"
            )
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
