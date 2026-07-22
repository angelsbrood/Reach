import ArgumentParser
import Foundation
import ReachDaemon
import ReachIdentity

struct CA: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ca",
        abstract: "The cluster certificate authority (Phase 1 hand-provisioning).",
        subcommands: [CAInit.self, IssueClient.self]
    )
}

struct CAInit: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "init",
        abstract: "Create the cluster CA if it does not exist."
    )

    @Option(name: .long) var name: String = "Reach Cluster"

    func run() async throws {
        let directory = DaemonInfo.stateDirectory.appendingPathComponent("ca", isDirectory: true)
        if let existing = try? ClusterCA.load(from: directory) {
            print("CA already present: \(existing.certificate.subject)")
            return
        }
        let ca = try ClusterCA.create(commonName: name)
        try ca.save(to: directory)
        print("CA created at \(directory.path)")
    }
}

struct IssueClient: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "issue-client",
        abstract: "Issue a client identity and write a provisioning bundle."
    )

    @Option(name: .long) var name: String
    @Option(name: .long, help: "Output path for the .reachidentity bundle.")
    var out: String?

    func run() async throws {
        let caDirectory = DaemonInfo.stateDirectory.appendingPathComponent("ca", isDirectory: true)
        let ca = try ClusterCA.load(from: caDirectory)
        let issued = try ca.issueClient(
            commonName: name,
            uri: "reach://device/\(UUID().uuidString.lowercased())"
        )
        let bundle = ProvisionedIdentity(
            clusterName: "\(ca.certificate.subject)",
            caCertificateDER: try ca.certificateDER(),
            certificateDER: try issued.certificateDER(),
            privateKeyX963: issued.privateKeyX963
        )
        let identityDirectory = DaemonInfo.stateDirectory.appendingPathComponent("identities", isDirectory: true)
        try FileManager.default.createDirectory(at: identityDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let url = out.map { URL(fileURLWithPath: $0) }
            ?? identityDirectory.appendingPathComponent("\(name).reachidentity")
        try bundle.write(to: url)
        print("client identity written: \(url.path)")
    }
}
