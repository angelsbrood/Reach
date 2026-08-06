import Crypto
import Foundation
import ReachIdentity
import Security
import X509

/// Turns issued key+cert material into a `SecIdentity`. The keychain is
/// the production path; when the process lacks keychain access
/// (errSecMissingEntitlement — CI/harness sandboxes), falls back to an
/// openssl-assembled PKCS#12, which `SecPKCS12Import` accepts everywhere.
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

    /// The listener identity, re-derived on every start and made usable
    /// without a password dialog.
    ///
    /// `serve` stores this under a fixed label, so the item outlives every
    /// binary that ever ran — and the keychain's default ACL trusts exactly
    /// the binary that created it. `reachd` is **ad-hoc signed**, so "that
    /// binary" means the CDHash of one build: every rebuild made the running
    /// daemon a stranger to its own key, and the dialog appeared at the first
    /// client handshake rather than at start, so the log read `serving` while
    /// the cluster was unreachable to anyone who was not sitting at the Mac.
    /// "Always Allow" recorded a hash the next build invalidated, which is
    /// why it never stuck.
    ///
    /// **The fix is the removal, not a wider ACL.** An item's access is fixed
    /// when it is created, and the creator is whoever called `SecItemAdd` — so
    /// deleting the predecessor and letting *this* build make a fresh one
    /// leaves the default ACL pointing at the program that is actually going
    /// to use the key. Nothing is widened, nothing is shared, and the key
    /// stays restricted to one binary; it is simply the right one now.
    ///
    /// The obvious alternative — keep the item and widen its ACL to any
    /// application — was tried first and abandoned: `kSecAttrAccess` is a
    /// legacy file-keychain attribute that `SecItemAdd` rejects with
    /// `errSecParam` when the key is supplied by reference, and it would have
    /// meant four deprecated `SecKeychain` calls to weaken a guarantee this
    /// does not need to weaken at all.
    ///
    /// ⚠️ **No test holds this, and none can from `swift test`.** The test
    /// bundle has no keychain entitlement — `SecItemAdd` returns
    /// `errSecMissingEntitlement` (-34018) — so every identity a test
    /// materializes takes the openssl/PKCS#12 fallback below and the keychain
    /// branch above is never executed. A test written against this passes on
    /// the fallback and proves nothing about the path the daemon uses, which
    /// is rule 6 with extra steps. The verification is on the host: reinstall,
    /// connect a client, and watch for the absence of a password dialog.
    ///
    /// The same fact is worth knowing on its own — **the production identity
    /// path has no automated coverage at all**, and the PKCS#12 defect that
    /// dominates red runs is dominant partly because tests reach it every
    /// single time.
    public static func materializeListener(_ issued: ClusterCA.Issued, label: String) throws -> SecIdentity {
        KeychainIdentity.remove(label: label)
        return try materialize(issued, label: label)
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
