import Crypto
import Foundation
import ReachIdentity
import Security
import X509

/// Turns issued key+cert material into a `SecIdentity`.
///
/// ⚠️ **The keychain branch below is not the path anything here actually
/// takes**, and believing otherwise cost an afternoon. `SecItemAdd` needs a
/// keychain-access entitlement that a plain SwiftPM executable does not
/// carry, so `reachd` — and every `swift test` bundle, and any scratch
/// script — gets `errSecMissingEntitlement` and lands in `viaPKCS12`. The
/// openssl route is not a fallback for CI; **it is the production path**, on
/// the daemon, on every start.
///
/// Two things follow, both of which have bitten:
///
/// 1. The PKCS#12 defect `IdentityError.pkcs12EmptyItemList` describes is not
///    an unlucky corner — every identity in this project is minted through the
///    call that exhibits it, which is why it dominates red runs.
/// 2. `SecPKCS12Import` used to leave the key in the login keychain, where its
///    access list could never match an ad-hoc signed binary. That produced a
///    password dialog on the operator's Mac at the first client connection,
///    invisible to the log and to `doctor`. `kSecImportToMemoryOnly` in
///    `IdentityStore.importOnce` is what stops it; the account is there.
///
/// The keychain branch is kept because an entitled host — a signed app bundle
/// rather than a bare executable — would take it, and the ceremony on device
/// does store into the keychain directly.
public enum IdentityMaterializer {
    /// Materializing an identity is several Security-framework calls in a
    /// row — a keychain add, or an openssl subprocess and a PKCS#12 import —
    /// and they do not tolerate being interleaved with anything else touching
    /// the keychain. This used to hold a lock of its own, which serialized
    /// materializations against each other and against nothing else: a
    /// `SecItemDelete` from a teardown, or a lookup, could still land in the
    /// middle of one. `KeychainLock` is the single lock every entry point in
    /// `ReachIdentity` takes, so the composition nests inside the same one
    /// its parts use (recursive, and these are synchronous call chains).

    public static func materialize(_ issued: ClusterCA.Issued, label: String) throws -> SecIdentity {
        try materialize(
            certificateDER: try issued.certificateDER(),
            privateKey: issued.privateKey,
            label: label
        )
    }

    /// The client-held-key variant: certificate as issued over the wire,
    /// key as the enrolling side minted it (tests standing in for keepers
    /// and apps use this; on devices the ceremony stores into the keychain
    /// directly).
    public static func materialize(certificateDER: Data, privateKey: P256.Signing.PrivateKey, label: String) throws -> SecIdentity {
        KeychainLock.acquire()
        defer { KeychainLock.release() }
        do {
            return try KeychainIdentity.store(
                privateKeyX963: privateKey.x963Representation,
                certificateDER: certificateDER,
                label: label
            )
        } catch IdentityError.keychainAddFailed(let status) where status == errSecMissingEntitlement {
            return try viaPKCS12(
                keyPEM: privateKey.pemRepresentation,
                certPEM: try Certificate(derEncoded: Array(certificateDER)).serializeAsPEM().pemString
            )
        }
    }

    private static func viaPKCS12(keyPEM: String, certPEM: String) throws -> SecIdentity {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-id-\(UUID().uuidString)", isDirectory: true)
        // Kept on failure: the archive IS the evidence, and it was being
        // deleted on the way out of the one path that could explain this.
        var succeeded = false
        defer { if succeeded { try? FileManager.default.removeItem(at: dir) } }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let keyURL = dir.appendingPathComponent("key.pem")
        let certURL = dir.appendingPathComponent("cert.pem")
        let p12URL = dir.appendingPathComponent("identity.p12")
        try keyPEM.write(to: keyURL, atomically: true, encoding: .utf8)
        try certPEM.write(to: certURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        // Defaults, deliberately. `/usr/bin/openssl` is LibreSSL 3.3.6, which
        // writes the certificate bag with pbeWithSHA1And40BitRC2-CBC — old,
        // and the thing Homebrew's OpenSSL 3 refuses to read, which makes it
        // a misleading tool for inspecting these archives. Naming modern
        // ciphers instead (`-certpbe/-keypbe AES-256-CBC -macalg sha256`) was
        // tried and is WORSE: LibreSSL accepts the flags and emits an archive
        // whose algorithms it cannot itself name, and macOS then rejects it
        // outright with -26275 on every run rather than intermittently.
        process.arguments = [
            "pkcs12", "-export",
            "-inkey", keyURL.path, "-in", certURL.path,
            "-out", p12URL.path, "-passout", "pass:reach-materialize",
        ]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw IdentityError.importFailed("openssl pkcs12 exited \(process.terminationStatus)")
        }
        do {
            let identity = try IdentityStore.identity(
                fromPKCS12: Data(contentsOf: p12URL),
                passphrase: "reach-materialize"
            )
            succeeded = true
            return identity
        } catch {
            FileHandle.standardError.write(Data("[reach] PKCS#12 import failed; archive kept at \(p12URL.path)\n".utf8))
            throw error
        }
    }
}
