import Crypto
import Foundation
import SwiftASN1
import X509

public enum CAError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case stateExists(String)
    case stateMissing(String)

    public var description: String {
        switch self {
        case .stateExists(let path):
            "a cluster CA already exists at \(path); re-initializing would orphan every certificate it has issued"
        // Two callers outside the CA borrow this case for the wg host key
        // and the wg conf, and one of them passes a sentence rather than a
        // path. So the wording has to carry either — worth its own error
        // type eventually, but a diagnostic that reads correctly today
        // beats a rename that touches the ceremony.
        case .stateMissing(let what):
            "required state is missing or will not read: \(what)"
        }
    }

    public var errorDescription: String? { description }
}

/// The cluster's own certificate authority: one P-256 keypair, self-signed
/// root, issuing device and server certificates. Phase 1 issues by hand
/// (`reachd ca …`); the ceremony automates issuance over the enrollment
/// channel. Key material lives under the daemon's state directory (0700)
/// and never enters any repository.
public struct ClusterCA: Sendable {
    public let certificate: Certificate
    private let key: P256.Signing.PrivateKey

    // MARK: Creation and persistence

    public static func create(commonName: String) throws -> ClusterCA {
        let key = P256.Signing.PrivateKey()
        let caKey = Certificate.PrivateKey(key)
        let subject = try DistinguishedName {
            CommonName(commonName)
        }
        let now = Date()
        let extensions = try Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
            Critical(KeyUsage(keyCertSign: true))
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: caKey.publicKey,
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(2 * 365 * 24 * 3600),
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: caKey
        )
        return ClusterCA(certificate: certificate, key: key)
    }

    init(certificate: Certificate, key: P256.Signing.PrivateKey) {
        self.certificate = certificate
        self.key = key
    }

    public func save(to directory: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try certificateDER().write(to: directory.appendingPathComponent("ca.der"))
        try key.rawRepresentation.write(to: directory.appendingPathComponent("ca-key.raw"), options: [.completeFileProtection])
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: directory.appendingPathComponent("ca-key.raw").path)
    }

    public static func load(from directory: URL) throws -> ClusterCA {
        let certURL = directory.appendingPathComponent("ca.der")
        let keyURL = directory.appendingPathComponent("ca-key.raw")
        guard FileManager.default.fileExists(atPath: certURL.path),
              FileManager.default.fileExists(atPath: keyURL.path)
        else {
            throw CAError.stateMissing(directory.path)
        }
        let certificate = try Certificate(derEncoded: Array(Data(contentsOf: certURL)))
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(contentsOf: keyURL))
        return ClusterCA(certificate: certificate, key: key)
    }

    // MARK: Issuance

    public struct Issued: Sendable {
        public let certificate: Certificate
        public let privateKey: P256.Signing.PrivateKey

        public func certificateDER() throws -> Data {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return Data(serializer.serializedBytes)
        }

        /// X9.63 representation, the form `SecKeyCreateWithData` expects.
        public var privateKeyX963: Data { privateKey.x963Representation }
    }

    /// Issues a serverAuth leaf for the daemon's listener.
    public func issueServer(
        commonName: String,
        dnsNames: [String],
        ipAddresses: [[UInt8]],
        days: Int = 365
    ) throws -> Issued {
        var names: [GeneralName] = dnsNames.map { .dnsName($0) }
        names.append(contentsOf: ipAddresses.map { .ipAddress(ASN1OctetString(contentBytes: ArraySlice($0))) })
        let extensions = try Certificate.Extensions {
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.serverAuth])
            SubjectAlternativeNames(names)
        }
        return try issue(commonName: commonName, days: days, extensions: extensions)
    }

    /// The daemon's own listener leaf, minted once and kept beside the CA.
    ///
    /// `reachd serve` used to issue this fresh on every start, and the
    /// reason recorded for that was that the leaf carried "the current
    /// addresses". It does carry them, and nothing ever reads them: every
    /// verify block in the tree runs `SecPolicyCreateSSL(_, nil)` — a nil
    /// host — so SANs are never matched, which is exactly why dialing a mesh
    /// address against a LAN-SAN certificate works at all (S1b, S5). The
    /// reissue bought nothing and cost something. `KeychainIdentity.store`
    /// adds with `SecItemAdd`; fresh material is never a duplicate, so every
    /// start added a key and a certificate that nothing ever removed. The
    /// development machine's login keychain held **13 certificates under
    /// this common name, one per start, all of them from production** — no
    /// test issues under it.
    ///
    /// Identical material presented again *is* a duplicate, which `store`
    /// already tolerates, so reusing it makes the accumulation stop by
    /// construction rather than by remembering to clean up after it.
    /// Rotation survives: the leaf is reissued once it comes within
    /// `renewWithin` of expiring, and the stored pair is replaced.
    ///
    /// The private key lands beside `ca-key.raw`, at the same 0600 in the
    /// same 0700 directory. That directory already holds the key that signs
    /// every identity in the cluster, so a listener key is not a new kind of
    /// secret in a new kind of place.
    public func serverLeaf(
        in directory: URL,
        commonName: String,
        dnsNames: [String],
        ipAddresses: [[UInt8]],
        days: Int = 30,
        renewWithin: TimeInterval = 24 * 3600,
        now: Date = Date()
    ) throws -> Issued {
        let certURL = directory.appendingPathComponent("server.der")
        let keyURL = directory.appendingPathComponent("server-key.raw")

        if let certData = try? Data(contentsOf: certURL),
           let keyData = try? Data(contentsOf: keyURL),
           let certificate = try? Certificate(derEncoded: Array(certData)),
           let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: keyData),
           certificate.notValidAfter.timeIntervalSince(now) > renewWithin
        {
            return Issued(certificate: certificate, privateKey: privateKey)
        }

        let issued = try issueServer(
            commonName: commonName,
            dnsNames: dnsNames,
            ipAddresses: ipAddresses,
            days: days
        )
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try issued.certificateDER().write(to: certURL, options: [.atomic])
        try issued.privateKey.rawRepresentation.write(to: keyURL, options: [.atomic, .completeFileProtection])
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        return issued
    }

    /// Issues a clientAuth leaf for a key the client minted and proved
    /// possession of — the ceremony's issuance path, for devices
    /// (`reach://device/…`) and granted apps (`reach://app/…`) alike. The
    /// private key never leaves the enrolling side.
    public func issueClientLeaf(
        publicKeyX963: Data,
        commonName: String,
        uri: String,
        days: Int = 365
    ) throws -> Certificate {
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        let extensions = try Certificate.Extensions {
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.clientAuth])
            SubjectAlternativeNames([.uniformResourceIdentifier(uri)])
        }
        let now = Date()
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(publicKey),
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(TimeInterval(days) * 24 * 3600),
            issuer: certificate.subject,
            subject: try DistinguishedName { CommonName(commonName) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
    }

    /// Issues a clientAuth leaf for a device or app identity.
    public func issueClient(
        commonName: String,
        uri: String,
        days: Int = 365
    ) throws -> Issued {
        let extensions = try Certificate.Extensions {
            Critical(KeyUsage(digitalSignature: true))
            try ExtendedKeyUsage([.clientAuth])
            SubjectAlternativeNames([.uniformResourceIdentifier(uri)])
        }
        return try issue(commonName: commonName, days: days, extensions: extensions)
    }

    private func issue(
        commonName: String,
        days: Int,
        extensions: Certificate.Extensions
    ) throws -> Issued {
        let leafKey = P256.Signing.PrivateKey()
        let now = Date()
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(leafKey.publicKey),
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(TimeInterval(days) * 24 * 3600),
            issuer: certificate.subject,
            subject: try DistinguishedName { CommonName(commonName) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(key)
        )
        return Issued(certificate: certificate, privateKey: leafKey)
    }

    public func certificateDER() throws -> Data {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }
}
