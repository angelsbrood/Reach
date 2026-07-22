import Crypto
import Foundation
import SwiftASN1
import X509

public enum CAError: Error, Sendable {
    case stateExists(String)
    case stateMissing(String)
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
