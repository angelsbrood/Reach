import Foundation
import Darwin
import ReachDaemon
import ReachDurableRuntime

/// Initialization-only issuer. No default Keychain materializer or identity
/// installation is involved; each worker later imports its own archive in memory.
enum DurableTransportIdentity {
    static func provision(_ root: String) throws -> TransportTLSProvision { try provision(root, application: TransportContract.application) }
    static func provision(_ root: String, application: String) throws -> TransportTLSProvision {
        let ca = try ClusterCA.create(commonName: "Reach disposable loopback")
        let host = try ca.issueServer(commonName: "Reach loopback host", dnsNames: [], ipAddresses: [[127, 0, 0, 1]], days: 1)
        let client = try ca.issueClient(commonName: "Reach loopback client", uri: application, days: 1)
        try archive(host, directory: root + "/host")
        try archive(client, directory: root + "/client")
        return try .init(caDER: ca.certificateDER(), hostDER: host.certificateDER(), clientDER: client.certificateDER())
    }
    private static func archive(_ leaf: ClusterCA.Issued, directory: String) throws {
        let key = directory + "/key.pem", cert = directory + "/cert.pem", output = directory + "/identity.p12"
        defer { try? FileManager.default.removeItem(atPath: key); try? FileManager.default.removeItem(atPath: cert) }
        try TransportRootOwner.writePrivate(Data(leaf.privateKey.pemRepresentation.utf8), to: key)
        let der = try leaf.certificateDER().base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        try TransportRootOwner.writePrivate(Data(("-----BEGIN CERTIFICATE-----\n" + der + "\n-----END CERTIFICATE-----\n").utf8), to: cert)
        // Exclusive creation fixes permissions before OpenSSL opens the file.
        try TransportRootOwner.writePrivate(Data(), to: output)
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["pkcs12", "-export", "-inkey", key, "-in", cert, "-out", output, "-passout", "pass:" + TransportContract.archivePassphrase]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else { throw TransportRuntimeError.invalid }
    }
}
