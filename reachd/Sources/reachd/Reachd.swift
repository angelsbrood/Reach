import ArgumentParser
import Foundation
import ReachDaemon
import ReachIdentity

@main
struct Reachd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "reachd",
        abstract: "The Reach serving daemon: a slot host fronting self-hosted open weights with the Foundation Models framework's native semantics.",
        subcommands: [Serve.self, Status.self, CA.self]
    )
}

struct Serve: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Advertise on the local network and serve sessions."
    )

    @Option(name: .long, help: "Override the model id from config.")
    var model: String?

    @Flag(name: .long, help: "Skip Bonjour advertisement.")
    var noAdvertise = false

    func run() async throws {
        var config = DaemonConfig.load()
        if let model {
            config.modelID = model
        }
        try? config.save()

        // The identity organ: CA auto-initializes on first serve; the
        // server leaf is issued fresh per start for the current addresses.
        let caDirectory = DaemonInfo.stateDirectory.appendingPathComponent("ca", isDirectory: true)
        let ca: ClusterCA
        if let loaded = try? ClusterCA.load(from: caDirectory) {
            ca = loaded
        } else {
            ca = try ClusterCA.create(commonName: config.clusterName)
            try ca.save(to: caDirectory)
            print("[reachd] cluster CA created")
        }
        let addresses = LocalAddresses.ipv4()
        let server = try ca.issueServer(
            commonName: "reachd",
            dnsNames: ["localhost"],
            ipAddresses: addresses,
            days: 30
        )
        let identity = try IdentityMaterializer.materialize(server, label: "reachd-server")
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        let filling = MLXFilling(modelID: config.modelID)
        let daemon = Daemon(
            config: config,
            filling: filling,
            identity: Daemon.ListenerIdentity(identity: identity, caCertificate: caCert)
        )
        try await daemon.start(advertise: !noAdvertise)
        print("[reachd] \(config.clusterName) serving \(config.modelID) on :\(config.port) (\(addresses.map { $0.map(String.init).joined(separator: ".") }.joined(separator: ", ")))")

        let prewarm = Task {
            do {
                try await filling.prewarm()
                print("[reachd] model prewarmed")
            } catch {
                print("[reachd] prewarm failed: \(error)")
            }
        }
        _ = prewarm

        while true {
            try await Task.sleep(for: .seconds(3600))
        }
    }
}

struct Status: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Report daemon state."
    )

    func run() async throws {
        let config = DaemonConfig.load()
        print("reachd \(DaemonInfo.version) — cluster \"\(config.clusterName)\", model \(config.modelID), port \(config.port)")
        print("state: \(DaemonInfo.stateDirectory.path)")
    }
}
