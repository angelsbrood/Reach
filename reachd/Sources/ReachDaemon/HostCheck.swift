import Crypto
import Darwin
import Foundation
import ReachIdentity
import ReachWire

/// Everything about this host that the away leg depends on, examined in one
/// pass instead of remembered in order.
///
/// Each of these has failed silently at least once, and silence is the whole
/// problem: a daemon with a reverted endpoint, a mesh that was never brought
/// up, a config that a previous run overwrote all come up looking healthy and
/// present as a routing fault an hour later, somewhere with worse lighting.
///
/// This lives in the library rather than in the `doctor` subcommand because a
/// check nothing can assert is a check that drifts. It did: a remediation line
/// here went on naming a reason that had been retired days earlier, and no test
/// could have caught it, because the executable target is one the test target
/// cannot import. `HostCheck` decides; `doctor` prints.
public enum HostCheck {
    /// Four levels, because the exit code was being asked two questions at
    /// once and could only answer one.
    ///
    /// A cold rig used to exit non-zero — the mesh interface is down before
    /// `wg-quick up`, which is the runbook working, not a fault — while a
    /// derived endpoint, the silent failure this whole command exists to
    /// catch, warned and exited zero. So the runbook carried a note telling
    /// the operator to disregard the tool's own verdict, which is the point
    /// at which the verdict has stopped being worth printing.
    ///
    /// `wait` is the separation: a step that has not been taken yet, where
    /// taking it fixes this. `fail` is reserved for what starting up will
    /// not fix. Only `fail` gates the exit status.
    public enum Level: String, Sendable, Equatable {
        case pass = "PASS"
        case warn = "WARN"
        /// A runbook step has not been run yet, AND running it resolves this.
        /// Never a permanent condition — if starting the rig would leave the
        /// finding standing, it is not a `wait`.
        case wait = "WAIT"
        case fail = "FAIL"
    }

    public struct Finding: Sendable, Equatable {
        public let level: Level
        public let title: String
        public let detail: String
        public let action: String?

        public init(level: Level, title: String, detail: String, action: String? = nil) {
            self.level = level
            self.title = title
            self.detail = detail
            self.action = action
        }
    }

    public struct Report: Sendable, Equatable {
        public let findings: [Finding]

        public init(findings: [Finding]) {
            self.findings = findings
        }

        public func count(_ level: Level) -> Int {
            findings.count { $0.level == level }
        }

        /// The one question the exit code answers.
        public var isSound: Bool {
            !findings.contains { $0.level == .fail }
        }
    }

    /// The one wg-quick config this rig writes and the operator edits. The
    /// daemon writes exactly one, and an edit to any other file fails silently,
    /// so the path has a single name here rather than a literal per caller.
    public static let defaultWireGuardConf = "/opt/homebrew/etc/wireguard/reach0.conf"

    /// Asking the cluster to answer, rather than inferring that it would.
    ///
    /// Off by default and opt-in at the command line, because every other
    /// check here is read-only and this one opens a real session with a real
    /// certificate. `nil` means the report stays the report it has always
    /// been.
    public struct Dial: Sendable {
        /// The road to dial, or nil for loopback. A chosen road is how this
        /// doubles as the away instrument.
        public var via: String?
        public var budget: Duration
        public var supervision: ClusterDial.Supervision

        public init(
            via: String? = nil,
            budget: Duration = .seconds(10),
            supervision: ClusterDial.Supervision = .launchAgent
        ) {
            self.via = via
            self.budget = budget
            self.supervision = supervision
        }
    }

    /// `wireGuardConf` and `addresses` are required rather than defaulted on
    /// purpose. A default would let a test read the developer's live conf and
    /// live interface list without saying so, which is how a suite becomes
    /// green-on-one-machine. The defaults belong on `doctor`'s own options,
    /// where they read as documentation instead of as a trap.
    public static func examine(
        stateDirectory: URL,
        wireGuardConf: String,
        addresses: [[UInt8]],
        portIsHeld: @Sendable (UInt16) -> Bool = HostCheck.probePort,
        dial: Dial? = nil
    ) async -> Report {
        var findings: [Finding] = []

        findings.append(checkStateDirectory(stateDirectory))

        // The config gates the endpoint check: with no config there is no
        // pinned endpoint to judge, and saying so beats guessing.
        var config: DaemonConfig?
        let configExists = DaemonConfig.exists(in: stateDirectory)
        do {
            config = try DaemonConfig.load(from: stateDirectory)
            findings.append(Finding(
                level: .pass,
                title: "config.json",
                detail: configExists
                    ? "parses; cluster \"\(config!.clusterName)\", model \(config!.modelID), ports \(config!.port)/\(config!.enrollPort)"
                    : "absent — defaults in use (first run)"
            ))
        } catch {
            findings.append(Finding(
                level: .fail,
                title: "config.json",
                detail: "\(error)",
                action: "Fix the JSON or move the file aside. serve and pair refuse to run against it."
            ))
        }

        // The ports are probed before they are printed, because whether a
        // daemon is up changes what a missing mesh interface MEANS. Down with
        // nothing running is the next step in the runbook; down with a daemon
        // already serving is a rig that will stream on the LAN and have
        // nothing to fall to at the walk-out. Same condition, two verdicts,
        // and the difference is one boolean this function already has.
        let portFindings = checkPorts(config: config, isHeld: portIsHeld)
        let daemonUp = portFindings.contains { $0.level == .pass }

        findings.append(contentsOf: checkMeshEndpoint(config: config, configExists: configExists, addresses: addresses))
        findings.append(checkMeshInterface(addresses, daemonUp: daemonUp))
        findings.append(checkClusterCA(in: stateDirectory, config: config))
        let wireGuard = checkWireGuard(in: stateDirectory, conf: wireGuardConf)
        findings.append(contentsOf: wireGuard.findings)
        findings.append(await checkDevices(in: stateDirectory, peers: wireGuard.peers))
        findings.append(contentsOf: portFindings)
        findings.append(contentsOf: checkReachability(in: stateDirectory, daemonUp: daemonUp))
        findings.append(checkSupervision(daemonUp: daemonUp))

        // Last, and deliberately: everything above says the host is dressed,
        // and this says whether the cluster answers. When the two disagree,
        // reading them in that order is what makes the disagreement legible.
        if let dial {
            findings.append(contentsOf: await checkDial(
                dial,
                stateDirectory: stateDirectory,
                config: config,
                daemonUp: daemonUp,
                addresses: addresses
            ))
        }

        return Report(findings: findings)
    }

    /// Reads the daemon's diagnostic mapping evidence. This file never feeds
    /// the wire or a grant; it exists so an absent router capability and a
    /// moving endpoint do not both collapse into "away does not work".
    static func checkReachability(
        in stateDirectory: URL,
        daemonUp: Bool,
        processIsAlive: @Sendable (Int32) -> Bool = HostCheck.processIsAlive
    ) -> [Finding] {
        let url = stateDirectory.appendingPathComponent(ReachabilityCoordinator.statusFileName)
        guard let data = try? Data(contentsOf: url) else {
            let level: Level = daemonUp ? .warn : .wait
            let detail = daemonUp
                ? "no reachability.json — this running daemon has not recorded mapping state"
                : "not probing — mappings start with the daemon"
            return [
                Finding(level: level, title: "session mapping", detail: detail),
                Finding(level: level, title: "mesh mapping", detail: detail),
            ]
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let runtime = try? decoder.decode(ReachabilityRuntime.self, from: data) else {
            return [
                Finding(level: .warn, title: "session mapping", detail: "reachability.json is unreadable", action: "Restart reachd; the file is runtime evidence and will be replaced."),
                Finding(level: .warn, title: "mesh mapping", detail: "reachability.json is unreadable", action: "Restart reachd; the file is runtime evidence and will be replaced."),
            ]
        }

        if !processIsAlive(runtime.processID),
           runtime.session.state != .stopped || runtime.mesh.state != .stopped {
            let age = max(0, Date().timeIntervalSince(runtime.updatedAt))
            let detail = "stale runtime state from process \(runtime.processID), updated \(Int(age)) s ago"
            return [
                Finding(level: .warn, title: "session mapping", detail: detail, action: "Start or restart reachd; stale endpoints are not advertised."),
                Finding(level: .warn, title: "mesh mapping", detail: detail, action: "Start or restart reachd; stale endpoints are not used in grants."),
            ]
        }

        return [mappingFinding(runtime.session), mappingFinding(runtime.mesh)]
    }

    static func mappingFinding(_ mapping: PortMappingRuntime) -> Finding {
        let title = "\(mapping.kind.rawValue) mapping"
        let change = mapping.changeCount > 0
            ? "; changed \(mapping.changeCount) time(s)"
                + (mapping.previousEndpoint.map { ", replacing \($0.host):\($0.port)" } ?? "")
            : ""

        switch mapping.state {
        case .active:
            guard let endpoint = mapping.endpoint else {
                return Finding(level: .warn, title: title, detail: "broker reported active without an endpoint")
            }
            let addressKind = MeshEndpoint.classify(endpoint.host)
            let ttl = mapping.ttl.map { ", TTL \($0) s" } ?? ""
            if mapping.doubleNAT || addressKind == .privateNetwork || addressKind == .sharedAddressSpace {
                return Finding(
                    level: .warn,
                    title: title,
                    detail: "active private outer mapping \(endpoint.host):\(endpoint.port) (double NAT)\(ttl)\(change)",
                    action: "Use it only from that outer network. A private or CGNAT outer address is not a public-internet road."
                )
            }
            return Finding(
                level: .pass,
                title: title,
                detail: "active public mapping \(endpoint.host):\(endpoint.port)\(ttl)\(change)"
            )

        case .probing:
            return Finding(level: .wait, title: title, detail: "probing the current router")
        case .unsupported:
            return Finding(level: .warn, title: title, detail: mapping.error ?? "automatic mapping is unsupported", action: "Local and pinned roads are unchanged; configure a router forward or explicit meshEndpoint if away access is required.")
        case .disabled:
            return Finding(level: .warn, title: title, detail: mapping.error ?? "automatic mapping is disabled at the router", action: "Enable PCP, NAT-PMP, or restricted UPnP on the router, or keep using local and pinned roads.")
        case .noRouter:
            return Finding(level: .warn, title: title, detail: mapping.error ?? "no router is available", action: "Mapping will be retried automatically when the primary network changes.")
        case .unavailable:
            return Finding(level: .warn, title: title, detail: mapping.error ?? "the broker returned no usable endpoint", action: "Local and explicitly pinned behavior is unchanged.")
        case .failed:
            return Finding(level: .warn, title: title, detail: mapping.error ?? "the mapping request failed", action: "Read the error code above; the daemon continues serving local and pinned roads.")
        case .stopped:
            return Finding(level: .wait, title: title, detail: "mapping deallocated when the daemon stopped")
        }
    }

    static func processIsAlive(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        if kill(pid, 0) == 0 { return true }
        return errno == EPERM
    }

    /// A config that will not parse deletes the dial too, and says so —
    /// the same ruling `checkPorts` and `checkMeshEndpoint` already make.
    /// Dialing `DaemonConfig()`'s defaults instead would be a check against
    /// a port nobody configured, reported as though it were this cluster.
    static func checkDial(
        _ dial: Dial,
        stateDirectory: URL,
        config: DaemonConfig?,
        daemonUp: Bool,
        addresses: [[UInt8]]
    ) async -> [Finding] {
        guard let config else {
            return [Finding(
                level: .warn,
                title: "dial",
                detail: "not attempted — config.json did not parse",
                action: "The port to dial lives in that file. Fix the config and run doctor --dial again."
            )]
        }
        let outcome = await ClusterDial.dial(
            stateDirectory: stateDirectory,
            config: config,
            via: dial.via,
            budget: dial.budget,
            supervision: dial.supervision
        )
        return dialFindings(outcome, daemonUp: daemonUp, addresses: addresses)
    }

    /// The dial's verdict in doctor's own grammar, and nothing else — pure,
    /// so every sentence below is assertable without a socket.
    ///
    /// The WAIT/FAIL split is the whole point of the check and it turns on
    /// `daemonUp`. **A daemon that is not running is a runbook step nobody
    /// has taken; a daemon that is running and will not answer a client is
    /// the failure five green reports missed on 6 August.** They are the same
    /// dial result and opposite verdicts, and the difference is one boolean
    /// `examine` already computes.
    ///
    /// ⚠️ **`daemonUp` is evidence about loopback and about nothing else.**
    /// It comes from a local `bind`, so on a dial that named a road it is a
    /// fact about a different question. Quoting it there — which the first
    /// draft did, and it was caught by running the thing — produced "a
    /// process holds :47337 and nothing answered on 10.86.0.1", two true
    /// clauses joined into a false implication.
    static func dialFindings(
        _ outcome: ClusterDial.Outcome,
        daemonUp: Bool,
        addresses: [[UInt8]] = []
    ) -> [Finding] {
        let dialed = "\(outcome.via):\(outcome.port)"
        var findings: [Finding] = []

        switch outcome.result {
        case .opened(let capabilities):
            let took = outcome.elapsed.map { " in \(secondsRounded($0))" } ?? ""
            findings.append(Finding(
                level: .pass,
                title: "dial",
                detail: "a session opened over \(dialed)\(took) — the cluster answers a client"
                    + (capabilities.isEmpty ? "" : ", capabilities \(capabilities.joined(separator: ", "))")
            ))

        case .noAnswer where outcome.pinned:
            // A named road that does not answer is a fault about that road,
            // and the useful half is whether the address is this host's own.
            // Measured on the rig 2026-08-07: the Mac cannot address its own
            // mesh address at all — plain UDP and ICMP to it are dropped the
            // same way the dial is — so "your own address did not answer" is
            // a real and recurring reading that means something other than a
            // broken daemon.
            findings.append(Finding(
                level: .fail,
                title: "dial",
                detail: "nothing answered on \(dialed) — the road named with --via did not reach the cluster",
                action: isOwnAddress(outcome.via, addresses)
                    ? "That is one of this host's own addresses. A tunnel address usually cannot be dialed from the host that terminates the tunnel, so try it from the other side rather than from here; anything else means the listener is not answering on this interface."
                    : "Nothing about the local port checks above bears on this road. Confirm the address is right and reachable from here, then check the edge: doctor cannot see the router."
            ))

        case .noAnswer where !daemonUp:
            findings.append(Finding(
                level: .wait,
                title: "dial",
                detail: "nothing answered on \(dialed), and nothing holds the port either — no daemon running",
                action: "Start it: reachd service install, or reachd serve in a terminal. Then dial again."
            ))

        case .noAnswer:
            findings.append(Finding(
                level: .fail,
                title: "dial",
                detail: "a process holds :\(outcome.port) and nothing answered a client on \(dialed)",
                action: "The port check above passes on any process holding the port; it cannot tell a serving daemon from a deaf one. Read ~/Library/Logs/reachd.log for what that process thinks it is doing."
            ))

        case .answeredAndFailed(let reason):
            findings.append(Finding(
                level: .fail,
                title: "dial",
                detail: "something answered on \(dialed) and would not serve — \(reason)",
                action: "The listener is up and the exchange on it did not finish. A blocked handshake looks exactly like this from here, so check ~/Library/Logs/reachd.log and whether anything is waiting on a dialog."
            ))

        case .noClusterCA:
            findings.append(Finding(
                level: .wait,
                title: "dial",
                detail: "not attempted — there is no cluster CA to mint a diagnostic identity from",
                action: "Created on first serve or pair. Nothing to dial with until then."
            ))

        case .notAttempted(let reason):
            findings.append(Finding(
                level: .warn,
                title: "dial",
                detail: "not attempted — the diagnostic identity would not mint: \(reason)",
                action: "This is doctor's own failure and says nothing about the cluster. Every identity in this project is minted through SecPKCS12Import, which fails intermittently; run it again. If it repeats, the message above is the one to read."
            ))
        }

        findings.append(contentsOf: roadFindings(outcome.road))
        return findings
    }

    /// The instrument checking the instrument.
    ///
    /// `ca10213` gave the daemon a `session … opened from <road>` line
    /// precisely so a session born away could be photographed. A dial that
    /// opened a session and cannot find that line has found the fault the
    /// line was added to fix — so it is a `fail`, and it is one of the five.
    static func roadFindings(_ road: ClusterDial.Road) -> [Finding] {
        switch road {
        case .notApplicable:
            // No session, so no road. The dial finding has already said why,
            // and repeating it as a second failure would double-count one
            // fault in the tally.
            []
        case .named(let road):
            [Finding(level: .pass, title: "road", detail: "the daemon logged the session: opened from \(road)")]
        case .missing:
            [Finding(
                level: .fail,
                title: "road",
                detail: "a session opened and the daemon never logged which road it came in on",
                action: "That line is the only evidence a session born away has. Without it the away test measures nothing, so fix this before the phone goes out: the daemon writing it is a different build from the one answering."
            )]
        case .unread(let why):
            [Finding(
                level: .warn,
                title: "road",
                detail: "the session opened; which road it came in on is unread — \(why)",
                action: "Fine for a foreground serve. For an away test, run under the launchd agent so the line lands in ~/Library/Logs/reachd.log, or read the terminal it is printing to."
            )]
        }
    }

    /// A loopback dial lands in tens of milliseconds, and one decimal place
    /// rendered that as "0.0 s" — a number that reads like a stopped clock in
    /// the finding whose whole job is to be believed.
    private static func secondsRounded(_ duration: Duration) -> String {
        let seconds = Double(duration.components.seconds)
            + Double(duration.components.attoseconds) / 1e18
        return seconds < 1 ? String(format: "%.0f ms", seconds * 1000) : String(format: "%.1f s", seconds)
    }

    /// Whether anything brings the daemon back.
    ///
    /// A `wait` rather than a `fail`: running `serve` by hand in a terminal
    /// is a legitimate way to work and is how every demo has been shot. What
    /// it is not is a service, and the difference only shows on the day the
    /// process dies with nobody watching — so it belongs somewhere a person
    /// can read it before that day rather than after.
    static func checkSupervision(daemonUp: Bool, home: URL? = nil) -> Finding {
        let plist = LaunchAgent.plistURL(home: home)
        guard FileManager.default.fileExists(atPath: plist.path) else {
            return Finding(
                level: .wait,
                title: "supervision",
                detail: daemonUp
                    ? "no launchd agent — the daemon is running, but nothing restarts it"
                    : "no launchd agent — nothing starts the daemon at login or restarts it",
                action: "reachd service install, from a copy of the binary somewhere permanent. It starts at login, not at boot: the cluster's identity lives in the login keychain."
            )
        }
        return Finding(
            level: .pass,
            title: "supervision",
            detail: "launchd agent installed at \(plist.path)"
        )
    }

    // MARK: - Checks

    static func checkStateDirectory(_ directory: URL) -> Finding {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return Finding(
                level: .wait,
                title: "state directory",
                detail: "absent",
                action: "Created on first serve or pair. Nothing to do unless you expected state here."
            )
        }
        let mode = (try? FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? Int) ?? nil
        guard let mode else {
            return Finding(level: .warn, title: "state directory", detail: "present; permissions unreadable")
        }
        let octal = String(mode, radix: 8)
        if mode & 0o077 != 0 {
            return Finding(
                level: .warn,
                title: "state directory",
                detail: "present, mode 0\(octal)",
                action: "Keys live here. chmod 700 \(directory.path)"
            )
        }
        return Finding(level: .pass, title: "state directory", detail: "present, mode 0\(octal)")
    }

    /// Whether a host is one of this machine's own addresses.
    ///
    /// This is the only thing that can tell a carrier-grade NAT lease from a
    /// tailnet address, and `classify` structurally cannot know it — both are
    /// 100.64/10, and the difference is entirely whether this host holds it.
    /// The same question sharpens RFC1918: an address this host owns is one
    /// forward away from the edge; one it does not is something upstream,
    /// which means a second forward that has to exist and be checked.
    static func isOwnAddress(_ host: String, _ addresses: [[UInt8]]) -> Bool {
        guard let octets = MeshEndpoint.ipv4(host) else { return false }
        return addresses.contains(octets)
    }

    static func checkMeshEndpoint(
        config: DaemonConfig?,
        configExists: Bool,
        addresses: [[UInt8]]
    ) -> [Finding] {
        // A config that will not parse used to delete this finding and both
        // port findings from the report — four lines vanishing silently, in
        // a command whose whole reason for existing is that silence is the
        // problem. Say that the check did not run.
        guard let config else {
            return [Finding(
                level: .warn,
                title: "mesh endpoint",
                detail: "not checked — config.json did not parse",
                action: "The endpoint lives in that file, so there is nothing to judge until it reads. Fix the config and run doctor again."
            )]
        }
        let mesh = MeshEndpoint.resolve(config: config, addresses: addresses)

        switch mesh.source {
        case .derived:
            // Derivation is correct on a machine that has never been
            // configured — the next serve or pair writes the file. Once a
            // config exists and simply omits the pin, this host has been set
            // up and the away leg was left out of it, which is precisely the
            // failure that reaches a venue looking healthy.
            guard configExists else {
                return [Finding(
                    level: .wait,
                    title: "mesh endpoint",
                    detail: "\(mesh.endpoint) — derived; no config.json yet",
                    action: "Written on first serve or pair. Pin meshEndpoint in it before the away leg matters."
                )]
            }
            return [Finding(
                level: .fail,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) — derived from a local address, not pinned",
                action: "LAN rehearsals work; the away leg does not, and it fails looking like a routing fault. Set meshEndpoint in config.json to the address the phone will dial."
            )]
        case .unavailable:
            return [Finding(
                level: .fail,
                title: "mesh endpoint",
                detail: "no usable address to derive from",
                action: "Set meshEndpoint in config.json."
            )]
        case .pinned, .mapped:
            break
        }

        guard let (host, port) = MeshEndpoint.split(mesh.endpoint) else {
            return [Finding(
                level: .fail,
                title: "mesh endpoint",
                detail: "\"\(mesh.endpoint)\" is not host:port",
                action: "The ceremony hands this to the phone verbatim. Write it as \"<address>:51820\"."
            )]
        }
        var findings: [Finding] = []
        if port != MeshEndpoint.port {
            findings.append(Finding(
                level: .warn,
                title: "mesh endpoint",
                detail: "port \(port), not \(MeshEndpoint.port)",
                action: "The host's wg listens on \(MeshEndpoint.port). Deliberate only if the forward translates."
            ))
        }
        switch MeshEndpoint.classify(host) {
        case .publicAddress:
            findings.append(Finding(level: .pass, title: "mesh endpoint", detail: "\(mesh.endpoint) pinned, publicly routable"))
        case .privateNetwork:
            findings.append(
                isOwnAddress(host, addresses)
                    ? Finding(
                        level: .warn,
                        title: "mesh endpoint",
                        detail: "\(mesh.endpoint) pinned, RFC1918 — this host's own address",
                        action: "One forward: the edge in front of this host must send UDP \(MeshEndpoint.port) here. Dialable from cellular only through it."
                    )
                    : Finding(
                        level: .warn,
                        title: "mesh endpoint",
                        detail: "\(mesh.endpoint) pinned, RFC1918 — not an address this host holds",
                        action: "You are pinning something upstream, so this is two forwards in series: the upstream must send UDP \(MeshEndpoint.port) to the edge, and the edge to this host. Confirm the outer one exists rather than assuming it."
                    )
            )
        case .sharedAddressSpace:
            // 100.64/10 is carrier-grade NAT and is also where tailnets live.
            // Whether this host holds the address is the whole difference: a
            // lease read off a venue's router cannot carry the leg at all,
            // while an address on this machine is a road it is already on.
            findings.append(
                isOwnAddress(host, addresses)
                    ? Finding(
                        level: .warn,
                        title: "mesh endpoint",
                        detail: "\(mesh.endpoint) pinned, 100.64/10 — this host's own address, so a mesh rather than CGNAT",
                        action: "Deliberate only if the phone is on that same mesh; it does its own traversal and needs no forward. The first-party road is unused while this is pinned."
                    )
                    : Finding(
                        level: .fail,
                        title: "mesh endpoint",
                        detail: "\(mesh.endpoint) pinned, 100.64/10 — carrier-grade NAT",
                        action: "Nothing outside can dial a CGNAT lease and no forward fixes it. If this is a venue's WAN address, the leg is impossible here — leave. That is a thirty-second abort instead of a three-hour one."
                    )
            )
        case .mesh:
            findings.append(Finding(
                level: .fail,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) pinned, inside the mesh subnet",
                action: "Circular: a phone cannot reach the mesh by way of the mesh. Pin the address of the edge in front of this host."
            ))
        case .loopback, .linkLocal:
            findings.append(Finding(
                level: .fail,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) pinned, not reachable from another host",
                action: "Pin the address the phone will dial."
            ))
        case nil:
            findings.append(Finding(
                level: .warn,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) pinned, not an IPv4 literal",
                action: "Pinned verbatim at the ceremony — the phone must be able to resolve it from wherever it stands."
            ))
        }
        return findings
    }

    /// Note what this actually observes: a `10.86.0.x` address, not an
    /// interface named reach0. They are the same thing only while the conf's
    /// `Address` line says so, and that line sits in the `[Interface]` section
    /// the operator edits by hand. So the wording claims an address, and the
    /// remediation does not promise more than the check knows.
    static func checkMeshInterface(_ addresses: [[UInt8]], daemonUp: Bool) -> Finding {
        let rendered = addresses.map(MeshEndpoint.string(from:))
        let meshUp = addresses.contains { Array($0.prefix(3)) == MeshEndpoint.meshPrefix }
        guard meshUp else {
            guard daemonUp else {
                return Finding(
                    level: .wait,
                    title: "mesh interface",
                    detail: "no 10.86.0.x address — reach0 is not up yet (\(rendered.joined(separator: ", ")))",
                    action: "sudo wg-quick up reach0 (standing order: before reachd serve) — until it exists, the away leg has no mesh candidate to fall to."
                )
            }
            return Finding(
                level: .fail,
                title: "mesh interface",
                detail: "no 10.86.0.x address, but a daemon is already serving (\(rendered.joined(separator: ", ")))",
                action: "This host will stream on the LAN and have nothing to fall to at the walk-out. sudo wg-quick up reach0, then restart the daemon so the mesh address is in every artifact."
            )
        }
        return Finding(
            level: .pass,
            title: "mesh interface",
            detail: "up; daemon will declare \(rendered.joined(separator: ", "))"
        )
    }

    /// "Absent or unreadable" was one `try?` covering two answers that call for
    /// opposite actions — the same collapse `DaemonConfig.load` and `addPeer`
    /// each had removed, surviving here in the third place on this path.
    /// A CA that has not been created yet is the next step; a CA that is
    /// present and will not load has taken every enrolled device with it, and
    /// must never be reported as "not started yet".
    static func checkClusterCA(in directory: URL, config: DaemonConfig? = nil) -> Finding {
        let caDirectory = directory.appendingPathComponent("ca", isDirectory: true)
        do {
            let der = try ClusterCA.load(from: caDirectory).certificateDER()
            let pin = Wire.base64URL(Data(SHA256.hash(data: der)))
            // The CA is minted once, with whatever the cluster was called that
            // day, and nothing re-mints it — so a renamed (or regenerated, and
            // therefore defaulted) config.json silently disagrees with the name
            // in every certificate it has ever issued. A granted app reads the
            // CA's subject, because that is the only name that survives its own
            // relaunch, so the drift surfaces as an app confidently naming a
            // cluster nobody calls that any more.
            if let config, let subject = subjectCommonName(ofDER: der), subject != config.clusterName {
                return Finding(
                    level: .warn,
                    title: "cluster CA",
                    detail: "present; pin \(pin) — but its subject is \"\(subject)\" and config.json says \"\(config.clusterName)\"",
                    action: "Granted apps display the CA's name, so they will say \"\(subject)\". Set clusterName back to \"\(subject)\" to agree with every certificate already issued — renaming the CA instead means re-minting it, which invalidates every enrolled device."
                )
            }
            return Finding(level: .pass, title: "cluster CA", detail: "present; pin \(pin)")
        } catch CAError.stateMissing {
            return Finding(
                level: .wait,
                title: "cluster CA",
                detail: "absent",
                action: "Created on first serve or pair."
            )
        } catch {
            return Finding(
                level: .fail,
                title: "cluster CA",
                detail: "present at \(caDirectory.path) but will not load: \(error)",
                action: "Every enrolled device was issued against this CA — if it is gone, they are all invalid and must re-pair. Restore it from wherever it is kept before starting anything."
            )
        }
    }

    /// The CA's own name, read the same way a granted app reads it, so this
    /// check cannot pass on a name the app would never see.
    static func subjectCommonName(ofDER der: Data) -> String? {
        guard let certificate = try? IdentityStore.certificate(fromDER: der) else { return nil }
        return IdentityStore.commonName(of: certificate)
    }

    /// Public keys are the most key material doctor may ever print, and its
    /// output is shot as the evidence tail after a take — so they print short.
    static func shortKey(_ key: Data) -> String {
        String(key.base64EncodedString().prefix(12)) + "…"
    }

    static func checkWireGuard(in directory: URL, conf path: String) -> (findings: [Finding], peers: [[String: String]]?) {
        var findings: [Finding] = []
        let keys = directory.appendingPathComponent("wg", isDirectory: true).appendingPathComponent("server.pub")
        let hostKeyExists = FileManager.default.fileExists(atPath: keys.path)
        // Read as WireGuardHost writes it: base64 of the 32 raw bytes, with
        // whatever trailing newline the editor left behind.
        let hostKey: Data? = (try? String(contentsOf: keys, encoding: .utf8))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .flatMap { Data(base64Encoded: $0) }
            .flatMap { $0.count == 32 ? $0 : nil }
        if hostKeyExists {
            findings.append(
                hostKey == nil
                    ? Finding(
                        level: .fail,
                        title: "wg host key",
                        detail: "\(keys.path) is present but is not a 32-byte base64 key",
                        action: "The daemon refuses to start on this. Restore it, or delete the wg/ directory to re-mint — every enrolled device then has to re-pair."
                    )
                    : Finding(level: .pass, title: "wg host key", detail: "present")
            )
        } else {
            findings.append(Finding(
                level: .wait,
                title: "wg host key",
                detail: "absent",
                action: "Minted on first serve. A new key means every enrolled device must re-pair."
            ))
        }

        // The second half of the same collapse: absent and unreadable were one
        // `try?`, and the absent branch was described as "not readable".
        //
        // Absent is only a first run while the host key is absent too. Once
        // server.pub exists, `serve` will NOT recreate a missing conf —
        // WireGuardHost writes the skeleton inside the branch that mints the
        // keypair, so a host that has ever served skips it — and `addPeer`
        // then reads the missing file as "" and writes out a bare [Peer] with
        // no [Interface], which wg-quick rejects outright. Calling that "not
        // started yet" would be the exact error this level exists to remove.
        guard FileManager.default.fileExists(atPath: path) else {
            findings.append(
                hostKeyExists
                    ? Finding(
                        level: .fail,
                        title: "wg config",
                        detail: "\(path) is missing, but this host already has a wg key",
                        action: "serve will not recreate it — the skeleton is only written alongside a fresh keypair. Restore the conf, or delete \(directory.appendingPathComponent("wg").path) to re-mint (every enrolled device then has to re-pair)."
                    )
                    : Finding(
                        level: .wait,
                        title: "wg config",
                        detail: "\(path) absent",
                        action: "Written on first serve, alongside the host key."
                    )
            )
            return (findings, nil)
        }
        guard let conf = try? String(contentsOfFile: path, encoding: .utf8) else {
            findings.append(Finding(
                level: .fail,
                title: "wg config",
                detail: "\(path) exists but will not read",
                action: "wg-quick reads it as root; doctor reads it as you. Check the owner and mode — editing it under sudo is how it stops being yours."
            ))
            return (findings, nil)
        }
        let parsed: WireGuardConf
        do {
            parsed = try WireGuardConf.parse(conf)
        } catch {
            findings.append(Finding(
                level: .fail,
                title: "wg config",
                detail: "\(path): \(error)",
                action: "wg-quick will refuse this file, so the mesh will not come up at all."
            ))
            return (findings, nil)
        }

        let peers = parsed.peerCount
        findings.append(Finding(
            level: peers > 0 ? .pass : .wait,
            title: "wg config",
            detail: "\(peers) peer\(peers == 1 ? "" : "s") in \(path) — the file, not the interface",
            // `sudo wg show reach0` — the obvious form — fails on this rig with
            // "Unable to access interface" while the interface is demonstrably
            // up. Bare `sudo wg show` prints every interface and works. Naming
            // the form that fails is worse than naming none, because it fails
            // at the exact moment the operator is confirming the one thing
            // doctor cannot see.
            action: peers > 0
                ? "Whether the running interface carries them needs sudo wg show (bare, no interface name — the named form fails here), which doctor cannot run without root. The conf reads identically before and after wg-quick down/up."
                : "No device has been admitted. Pair one, then apply with sudo wg-quick down/up reach0."
        ))
        findings.append(checkWireGuardIdentity(parsed, hostKey: hostKey, conf: path))
        // The invariant `addPeer` is built around, asserted against the file
        // rather than trusted to the code that writes it. Two peers claiming one
        // /32 is a conf wg will load and a mesh that routes that address to
        // whichever block it happened to read — and nothing else here would see
        // it, because a hand-edit and a future removal-plus-reallocation both
        // produce it without going through `addPeer` at all.
        let claims = parsed.peers.flatMap(WireGuardConf.allowedIPs(of:))
        let contested = Set(claims.filter { address in claims.filter { $0 == address }.count > 1 })
        if !contested.isEmpty {
            findings.append(Finding(
                level: .fail,
                title: "wg peers",
                detail: "\(path) has more than one peer claiming \(contested.sorted().joined(separator: ", "))",
                action: "wg will load this and route the address to whichever block it read — so one device silently takes another's mesh. Remove the stale block; the device it belonged to keeps its identity and gets a new one by re-pairing."
            ))
        }
        return (findings, parsed.peers)
    }

    /// Whether the conf and the state directory agree about who this host is.
    ///
    /// They can diverge silently. `WireGuardHost` mints the keypair and writes
    /// the conf skeleton in the same branch, guarded on `server.pub` being
    /// absent — so removing the state directory's `wg/` while the conf survives
    /// gives this host a NEW key while the file still names the old one. wg
    /// comes up, the daemon serves, every previously enrolled device is
    /// talking to a key that no longer exists, and nothing else on this list
    /// looks at both halves.
    ///
    /// Nothing here renders the private key. Doctor's output is shot as the
    /// evidence tail after a take, so the two public keys are the most that
    /// may appear, truncated.
    static func checkWireGuardIdentity(_ conf: WireGuardConf, hostKey: Data?, conf path: String) -> Finding {
        guard conf.hasInterfaceSection else {
            return Finding(
                level: .fail,
                title: "wg identity",
                detail: "\(path) has no [Interface] section",
                action: "wg-quick cannot bring up an interface with no key. This is what a conf looks like after a peer was appended to a file that could not be read — restore it, or delete the state directory's wg/ to re-mint (every device re-pairs)."
            )
        }
        guard let privateKey = conf.privateKey, !privateKey.isEmpty else {
            return Finding(
                level: .fail,
                title: "wg identity",
                detail: "\(path) has an [Interface] with no PrivateKey",
                action: "The host has no mesh identity to present. Restore the conf, or delete the state directory's wg/ to re-mint."
            )
        }
        guard let raw = Data(base64Encoded: privateKey), raw.count == 32,
              let derived = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw).publicKey.rawRepresentation
        else {
            return Finding(
                level: .fail,
                title: "wg identity",
                detail: "\(path)'s PrivateKey is not a 32-byte base64 key",
                action: "wg-quick will refuse it. Restore the conf, or delete the state directory's wg/ to re-mint."
            )
        }
        guard let hostKey else {
            return Finding(
                level: .wait,
                title: "wg identity",
                detail: "conf carries a key; nothing in the state directory to check it against yet",
                action: "server.pub is written on first serve."
            )
        }
        let shown = shortKey
        guard derived == hostKey else {
            return Finding(
                level: .fail,
                title: "wg identity",
                detail: "\(path) is a different host than the state directory — conf is \(shown(derived)), server.pub is \(shown(hostKey))",
                action: "Every enrolled device was given the state directory's key as the one to talk to, so none of them can reach the interface this conf brings up. Whichever is the real host, make the other match it before pairing anything."
            )
        }
        return Finding(
            level: .pass,
            title: "wg identity",
            detail: "conf PrivateKey matches wg/server.pub (\(shown(hostKey)))"
        )
    }

    /// `peers` is what `checkWireGuard` parsed out of the conf, or nil when there
    /// was no conf to read. It is passed in so this check can ask the one
    /// question neither half could answer alone: does every device that believes
    /// it is enrolled actually have a road?
    ///
    /// The ceremony writes the peer block only once the device confirms it holds
    /// the grant, deliberately — admitting it earlier meant a re-pair that failed
    /// at the last step had already evicted the block the phone was using. The
    /// cost is a window: a device can be persisted as active, holding a valid
    /// certificate, with no `[Peer]` line naming it. It authenticates, it opens
    /// sessions, and it has no mesh — so it works on the LAN and dies at the
    /// walk-out, which is this project's signature failure and the one doctor
    /// exists to catch.
    ///
    /// **It compares keys and addresses, not counts, and that is the whole
    /// point.** Counting caught only the narrowest case. A torn *re-pair* leaves
    /// the previous block in place, so one active device and one peer balanced
    /// exactly — and this check reported a sound rig while the phone had no road,
    /// which is the shape it was written for and missed. A stranded device
    /// offsetting an orphaned block did the same. Neither survives a comparison
    /// of *which key holds which address*.
    static func checkDevices(in directory: URL, peers: [[String: String]]?) async -> Finding {
        let devices = await DeviceRegistry(directory: directory).all
        if let peers {
            let active = devices.filter(\.active)
            let holds = { (peer: [String: String], device: DeviceRegistry.Device) in
                WireGuardConf.publicKey(of: peer) == device.wgPub
                    && WireGuardConf.allowedIPs(of: peer).contains("\(device.assignedIP)/32")
            }
            let stranded = active.filter { device in !peers.contains { holds($0, device) } }
            if !stranded.isEmpty {
                let named = stranded
                    .map { "\($0.name) (\($0.assignedIP), key \(shortKey($0.wgPub)))" }
                    .joined(separator: ", ")
                return Finding(
                    level: .fail,
                    title: "enrolled devices",
                    detail: "\(named) — no road onto the mesh: no peer in the conf holds that key at that address",
                    action: "A ceremony was interrupted between admitting the device and writing its peer, or the conf still holds an older key for it. Re-pair the affected device; it will keep its identity and address, and the peer block is written again."
                )
            }
            let orphans = peers.filter { peer in !active.contains { holds(peer, $0) } }
            if !orphans.isEmpty {
                let named = orphans
                    .map { peer in
                        let key = WireGuardConf.publicKey(of: peer).map(shortKey) ?? "no key"
                        let where_ = WireGuardConf.allowedIPs(of: peer).joined(separator: ", ")
                        return "\(key) at \(where_.isEmpty ? "no address" : where_)"
                    }
                    .joined(separator: ", ")
                return Finding(
                    level: .warn,
                    title: "enrolled devices",
                    detail: "\(active.count) active, and the conf also holds \(named)",
                    action: "A peer block outlives the device that owned it, or holds a key that device has replaced. Harmless to the demo — it is a key that can still reach the mesh, which is why revocation is funded scope."
                )
            }
        }
        guard !devices.isEmpty else {
            return Finding(
                level: .wait,
                title: "enrolled devices",
                detail: "none",
                action: "reachd pair, then scan with the keeper. The first device enrolled holds the admin grant."
            )
        }
        let admins = devices.filter { $0.admin && $0.active }
        guard !admins.isEmpty else {
            return Finding(
                level: .warn,
                title: "enrolled devices",
                detail: "\(devices.count) enrolled, none both admin and active",
                action: "Without an active admin device no grant sheet can be ruled, so no app can enrol."
            )
        }
        let names = admins.map { "\($0.name) (\($0.assignedIP))" }.joined(separator: ", ")
        return Finding(level: .pass, title: "enrolled devices", detail: "\(devices.count) enrolled; admin: \(names)")
    }

    static func checkPorts(config: DaemonConfig?, isHeld: @Sendable (UInt16) -> Bool) -> [Finding] {
        guard let config else {
            return [Finding(
                level: .warn,
                title: "ports",
                detail: "not checked — config.json did not parse",
                action: "The port numbers live in that file. Fix the config and run doctor again."
            )]
        }
        return [(config.port, "session"), (config.enrollPort, "enrollment")].map { port, role in
            if isHeld(port) {
                Finding(level: .pass, title: "\(role) port", detail: ":\(port) held — a process has it")
            } else {
                Finding(level: .wait, title: "\(role) port", detail: ":\(port) free — no daemon running")
            }
        }
    }

    /// A UDP bind that fails is a port someone else holds — which, for these
    /// two, means the daemon is already up.
    public static func probePort(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY
        let result = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result != 0
    }
}
