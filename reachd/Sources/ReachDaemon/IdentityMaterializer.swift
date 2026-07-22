import Foundation
import ReachIdentity
import Security

/// Turns issued key+cert material into a `SecIdentity`. The keychain is
/// the production path; when the process lacks keychain access
/// (errSecMissingEntitlement — CI/harness sandboxes), falls back to an
/// openssl-assembled PKCS#12, which `SecPKCS12Import` accepts everywhere.
public enum IdentityMaterializer {
    public static func materialize(_ issued: ClusterCA.Issued, label: String) throws -> SecIdentity {
        do {
            return try KeychainIdentity.store(
                privateKeyX963: issued.privateKeyX963,
                certificateDER: try issued.certificateDER(),
                label: label
            )
        } catch IdentityError.keychainAddFailed(let status) where status == errSecMissingEntitlement {
            return try viaPKCS12(issued)
        }
    }

    private static func viaPKCS12(_ issued: ClusterCA.Issued) throws -> SecIdentity {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-id-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let keyURL = dir.appendingPathComponent("key.pem")
        let certURL = dir.appendingPathComponent("cert.pem")
        let p12URL = dir.appendingPathComponent("identity.p12")
        try issued.privateKey.pemRepresentation.write(to: keyURL, atomically: true, encoding: .utf8)
        try issued.certificate.serializeAsPEM().pemString.write(to: certURL, atomically: true, encoding: .utf8)

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
