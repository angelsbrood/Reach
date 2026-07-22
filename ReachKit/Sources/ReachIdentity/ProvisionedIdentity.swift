import Foundation
import Security

/// The hand-provisioning bundle Phase 1 uses to move an issued identity to
/// a client: CA root + leaf + key in one JSON file. The ceremony replaces
/// this file with SecureEnclave keys and the enrollment channel; nothing
/// here survives into that phase.
public struct ProvisionedIdentity: Codable, Sendable {
    public var clusterName: String
    public var caCertificateDER: Data
    public var certificateDER: Data
    public var privateKeyX963: Data

    public init(clusterName: String, caCertificateDER: Data, certificateDER: Data, privateKeyX963: Data) {
        self.clusterName = clusterName
        self.caCertificateDER = caCertificateDER
        self.certificateDER = certificateDER
        self.privateKeyX963 = privateKeyX963
    }

    public static func load(from url: URL) throws -> ProvisionedIdentity {
        try JSONDecoder().decode(ProvisionedIdentity.self, from: Data(contentsOf: url))
    }

    public func write(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: url, options: [.completeFileProtection])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Installs into the keychain and returns what the TLS layer needs.
    public func install(label: String) throws -> (identity: SecIdentity, caCertificate: SecCertificate) {
        let identity = try KeychainIdentity.store(
            privateKeyX963: privateKeyX963,
            certificateDER: certificateDER,
            label: label
        )
        let ca = try IdentityStore.certificate(fromDER: caCertificateDER)
        return (identity, ca)
    }
}
