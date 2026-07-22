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
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let keyURL = dir.appendingPathComponent("key.pem")
        let certURL = dir.appendingPathComponent("cert.pem")
        let p12URL = dir.appendingPathComponent("identity.p12")
        try keyPEM.write(to: keyURL, atomically: true, encoding: .utf8)
        try certPEM.write(to: certURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
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
        return try IdentityStore.identity(
            fromPKCS12: Data(contentsOf: p12URL),
            passphrase: "reach-materialize"
        )
    }
}
