import Foundation
import Darwin
import Network
import Security
import ReachDaemon
import ReachIdentity
import ReachTransport
import RequestPreparationContract
import DurableRootKeys
@testable import ReachDurableRuntime

/// TLS-only test fixture: one CA, two admitted leaves and one same-CA negative.
/// All imports use the production memory-only path. No Keychain is created here.
final class TransportTLSFixtures: @unchecked Sendable {
    let root: String, host: TransportIdentity, client: TransportIdentity, other: TransportIdentity
    let ca: SecCertificate
    init() throws {
        let fixtureRoot = try ArtifactFixtures.base() + "/tls-" + UUID().uuidString.lowercased()
        root = fixtureRoot
        try LocalFiles.createDirectory(fixtureRoot)
        var complete = false
        defer { if !complete { try? FileManager.default.removeItem(atPath: fixtureRoot) } }
        let issuer = try ClusterCA.create(commonName: "S94 TLS tests")
        let server = try issuer.issueServer(commonName: "host", dnsNames: [], ipAddresses: [[127,0,0,1]], days: 1)
        let accepted = try issuer.issueClient(commonName: "client", uri: "s94:client", days: 1)
        let wrong = try issuer.issueClient(commonName: "other", uri: "s94:other", days: 1)
        let pins = try TransportPins(.init(caDER: issuer.certificateDER(), hostDER: server.certificateDER(), clientDER: accepted.certificateDER()))
        ca = try IdentityStore.certificate(fromDER: pins.caDER)
        let descriptor = try LocalDurableRuntime.withCPU { try SelectedArtifactProfile(at: ArtifactFixtures.artifacts()).preparer.policy.descriptor }
        let digest = PreparationEncoding.hash(Data([1]))
        func identity(_ leaf: ClusterCA.Issued, _ path: String, _ role: TransportRole, negative: Bool = false) throws -> TransportIdentity {
            try LocalFiles.createDirectory(path); try LocalFiles.createDirectory(path + "/" + role.rawValue)
            let directory = path + "/" + role.rawValue
            let bytes = try Self.archive(leaf, directory: directory)
            let ownPins = negative ? try TransportPins(.init(caDER: pins.caDER, hostDER: server.certificateDER(), clientDER: leaf.certificateDER())) : pins
            let selection = try TransportSelectionBinding(revision: TransportContract.revision, role: role, bootstrap: digest, profileDigest: digest, archiveDigest: PreparationEncoding.hash(bytes), executable: FrozenWorker(path: fixtureRoot + "/unused", sha256: digest), descriptor: descriptor, pins: ownPins, port: 54394)
            return try TransportIdentity(root: path, selection: selection, audit: TransportRoleAudit(role))
        }
        host = try identity(server, root + "/server", .host)
        client = try identity(accepted, root + "/accepted", .client)
        other = try identity(wrong, root + "/other", .client, negative: true)
        complete = true
    }
    private static func archive(_ leaf: ClusterCA.Issued, directory: String) throws -> Data {
        let key = directory + "/key.pem", cert = directory + "/cert.pem", p12 = directory + "/identity.p12"
        defer { try? FileManager.default.removeItem(atPath: key); try? FileManager.default.removeItem(atPath: cert) }
        try LocalFiles.writeNew(Data(leaf.privateKey.pemRepresentation.utf8), to: key)
        let der = try leaf.certificateDER().base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        try LocalFiles.writeNew(Data(("-----BEGIN CERTIFICATE-----\n" + der + "\n-----END CERTIFICATE-----\n").utf8), to: cert)
        try LocalFiles.writeNew(Data(), to: p12)
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["pkcs12", "-export", "-inkey", key, "-in", cert, "-out", p12, "-passout", "pass:" + TransportContract.archivePassphrase]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw TransportRuntimeError.invalid }
        return try LocalFiles.read(p12, maximum: 1 << 20)
    }
    func close() throws { try FileManager.default.removeItem(atPath: root) }
}
