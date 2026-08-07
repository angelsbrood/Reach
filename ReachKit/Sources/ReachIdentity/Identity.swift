import Foundation
import Security

public enum IdentityError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case pkcs12ImportFailed(OSStatus)
    case malformedCertificate
    case importFailed(String)
    case keychainAddFailed(OSStatus)
    case identityNotFound(OSStatus)
    case roadsUnreadable(OSStatus)
    /// `SecPKCS12Import` reporting success and handing back nothing.
    ///
    /// Its own case, and the only error in this file allowed more than one
    /// sentence, because of who reads it and when. This is the dominant
    /// failure mode of the whole test tree — measured at three red runs in
    /// nine full `reachd` runs, roughly 0.40% per materialization — and it
    /// arrives as a throw out of a fixture, so the suite it is attributed to
    /// is whichever one lost the coin flip. Under `importFailed` it read as
    /// a plain assembly failure and every red run cost someone a diagnosis
    /// of a test that had nothing to do with it.
    ///
    /// So the error says what it is. It is not retried — three attempts over
    /// twenty runs recovered zero times, and a run that goes quiet is not a
    /// run that got fixed.
    case pkcs12EmptyItemList(bytes: Int)

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
        case .roadsUnreadable(let status):
            // Not `identityNotFound`, which is what the mesh key borrows for
            // its own miss and which would be plainly false here — there is no
            // identity in question, and the roads are stored, they just will
            // not read back.
            "the cluster roads this app kept will not read back: \(Self.name(for: status))"
        case .pkcs12EmptyItemList(let bytes):
            "the private scalar lost its leading zero byte on the way into the archive, so SecPKCS12Import returned success and an empty item list for \(bytes) bytes — one octet short of the width the field needs, and no identity can be assembled from it. Not the framework, and not a malformed archive: LibreSSL writes it and reads it back quite happily. Re-running will not help, because the same key produces the same short bytes every time. Whatever reached this point was minted with a bare P256.Signing.PrivateKey() instead of SigningKey.mint(), or was written to disk before that guard existed; find the mint site."
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
        // One attempt, and the reason is now mechanical rather than empirical.
        // `pkcs12EmptyItemList` is a private scalar that lost its leading zero
        // byte on the way into the archive — 31 octets where the SEC1 field
        // wants 32 — so the bytes are short, and short bytes fail identically
        // however many times they are re-read. That is why retrying was
        // measured (three attempts, 20 runs) and never once recovered.
        //
        // The retry that would have worked is not here: it is not minting the
        // key in the first place. See `SigningKey`, which is where the defect
        // is actually closed.
        try importOnce(data, passphrase: passphrase)
    }

    private static func importOnce(_ data: Data, passphrase: String) throws -> SecIdentity {
        var items: CFArray?
        // ⚠️ `kSecImportToMemoryOnly` is load-bearing, and its absence was a
        // defect a person met rather than a tidiness point.
        //
        // On macOS `SecPKCS12Import` writes the key into the login keychain as
        // a side effect — labelled "Imported Private Key", because the archive
        // carries no friendlyName — with an access list naming the importing
        // binary. `reachd` is ad-hoc signed, so there is no stable designated
        // requirement to record and macOS can only pin one build's CDHash.
        // Every use of the key then raised
        //
        //     reachd wants to sign using key "Imported Private Key"
        //
        // on the operator's Mac, at the *first client connection* rather than
        // at start — so the log read `serving`, `doctor` passed every check,
        // and the cluster was unreachable to anyone not sitting at the machine.
        // "Always Allow" wrote a hash the next build invalidated, so it could
        // never stick however many times it was clicked.
        //
        // The keychain was never wanted here. This identity is re-derived from
        // `ca/server-key.raw` on every start and needs to live exactly as long
        // as the process. Memory-only also ends the accumulation the comment on
        // `KeychainIdentity.remove` describes: a login keychain that had
        // collected hundreds of these, 36 under "localhost" from one
        // afternoon's test runs alone.
        //
        // Already the default on iOS; on macOS it must be asked for.
        let options = [
            kSecImportExportPassphrase as String: passphrase,
            kSecImportToMemoryOnly as String: kCFBooleanTrue as Any,
        ] as CFDictionary
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
            // `nil` is the characterized defect wearing its other face — the
            // framework hands back no array at all rather than an empty one.
            // An array of the wrong shape has never been seen and would be
            // something else, so it stays a plain assembly failure.
            if items == nil {
                throw IdentityError.pkcs12EmptyItemList(bytes: data.count)
            }
            throw IdentityError.importFailed(
                "SecPKCS12Import returned errSecSuccess with an item array of an unexpected shape (\(data.count) bytes in)"
            )
        }
        guard let first = array.first else {
            throw IdentityError.pkcs12EmptyItemList(bytes: data.count)
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

    /// The certificate's subject summary. For a Reach cluster CA that is the
    /// cluster's name **as of the day the CA was minted**
    /// (`ClusterCA.create(commonName: config.clusterName)`) — the API itself
    /// promises only "something human-readable about the subject", so this is a
    /// fact about our own certificates rather than about X.509.
    ///
    /// It matters because it is the only place a consumer app can recover the
    /// cluster's name after a relaunch: nothing else persists it, and the pinned
    /// CA outlives app installs the way every keychain item does.
    ///
    /// ⚠️ **It is not necessarily the cluster's name now.** This once read as
    /// though the two could not diverge; they can, and they did. The CA is
    /// minted once and nothing re-mints it, so a `config.json` that is renamed
    /// — or regenerated, and therefore quietly returned to the default
    /// "Reach Cluster" — leaves every issued certificate saying the old name
    /// while the daemon advertises the new one. A granted app then names a
    /// cluster nobody calls that any more, and is not wrong to: this is the
    /// name it pinned. `reachd doctor` reports the drift; resolving it means
    /// agreeing with the CA, because re-minting invalidates every enrolled
    /// device.
    public static func commonName(of certificate: SecCertificate) -> String? {
        SecCertificateCopySubjectSummary(certificate) as String?
    }
}
