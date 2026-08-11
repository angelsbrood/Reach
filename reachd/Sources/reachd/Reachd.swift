import ArgumentParser
import Foundation
import ReachDaemon
import ReachIdentity

struct Reachd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "reachd",
        abstract: "The Reach serving daemon: a slot host fronting self-hosted open weights with the Foundation Models framework's native semantics.",
        subcommands: [Serve.self, Pair.self, Status.self, Doctor.self, CA.self, Selftest.self, Service.self]
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
        // This is the first operation with authority over cluster state.
        // Root's implicit Application Support path is /var/root, where the
        // ordinary first-run path would mint a second CA before an operator
        // saw the mistake. An explicit absolute REACH_STATE_DIR is the one
        // allowed scratch/system-context escape hatch.
        try LoginOwnedHost.authorizeServe(
            effectiveUID: geteuid(),
            environment: ProcessInfo.processInfo.environment
        )
        // stdout to a *file* is block-buffered, and a daemon that prints four
        // lines at startup never fills a 4 KB buffer — so under launchd,
        // where `StandardOutPath` is the only way to read those lines at all,
        // the log stayed empty for as long as the daemon was healthy and
        // filled only when it died and flushed. A log you can read after the
        // crash and not before is the wrong way round. `Log.error` already
        // goes to stderr, which is unbuffered; this puts `Log.info` on equal
        // footing.
        setvbuf(stdout, nil, _IOLBF, 0)
        // A config read successfully is left exactly as the operator wrote it.
        // Write only to materialize a first run, or to record a --model
        // override — rewriting on every start is how a typo gets erased before
        // anyone can see it.
        let isFirstRun = !DaemonConfig.exists()
        var config = try DaemonConfig.load()
        if let model {
            config.modelID = model
        }
        if isFirstRun || model != nil {
            try config.save()
        }

        // The identity organ: CA auto-initializes on first serve; the
        // server leaf is minted once and kept beside it, reissued only near
        // expiry. It used to be reissued per start "for the current
        // addresses" — addresses no verify block reads, since they all run
        // nil-host — and every start left another key and certificate in the
        // login keychain. See ClusterCA.serverLeaf.
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
        let server = try ca.serverLeaf(
            in: caDirectory,
            commonName: "reachd",
            dnsNames: ["localhost"],
            ipAddresses: addresses,
            days: 30
        )
        let identity = try IdentityMaterializer.materialize(server, label: "reachd-server")
        let caCert = try IdentityStore.certificate(fromDER: ca.certificateDER())

        let filling = MLXFilling(modelID: config.modelID)
        let reachability = ReachabilityCoordinator(
            sessionPort: config.port,
            stateDirectory: DaemonInfo.stateDirectory
        )
        // One device registry and one grant desk, shared between the organ
        // that parks app requests and the organ that lets keepers rule them.
        let devices = DeviceRegistry()
        let desk = GrantDesk()
        let daemon = Daemon(
            config: config,
            filling: filling,
            identity: Daemon.ListenerIdentity(identity: identity, caCertificate: caCert),
            grants: Daemon.GrantWiring(desk: desk, devices: devices),
            reachability: reachability
        )
        try await daemon.start(advertise: !noAdvertise)
        let mesh = MeshEndpoint.resolve(
            config: config,
            mapped: reachability.meshEndpoint,
            addresses: addresses
        )
        // The startup line reports what the endpoint is now; the grant reads
        // it again when it grants. Re-pinning meshEndpoint — which is what
        // arriving at a venue means — must reach the next phone paired
        // without a restart, because nothing in the ceremony would show that
        // it hadn't: the QR carries no endpoint, and on the LAN a stale one
        // works perfectly right up until the walk-out.
        let wgHost = try WireGuardHost {
            MeshEndpoint.resolve(
                config: try DaemonConfig.load(),
                mapped: reachability.meshEndpoint,
                addresses: LocalAddresses.ipv4()
            ).endpoint
        }
        let enrollment = EnrollmentService(
            ca: ca,
            tokens: TokenStore(),
            devices: devices,
            wgHost: wgHost,
            desk: desk
        )
        try await daemon.startEnrollment(service: enrollment, advertise: !noAdvertise)
        print("[reachd] enrollment listening on :\(config.enrollPort), \(mesh.summary)")
        print("[reachd] grant desk open — app approvals surface on the keeper")
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
        // Status reports; it does not refuse. A broken config is exactly the
        // thing you ran status to find out about.
        do {
            let config = try DaemonConfig.load()
            print("reachd \(DaemonInfo.version) — cluster \"\(config.clusterName)\", model \(config.modelID), port \(config.port)")
        } catch {
            print("reachd \(DaemonInfo.version) — config unreadable:\n\(error)")
        }
        print("state: \(DaemonInfo.stateDirectory.path)")
    }
}
