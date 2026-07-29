import Crypto
import Darwin
import Foundation
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

    /// `wireGuardConf` and `addresses` are required rather than defaulted on
    /// purpose. A default would let a test read the developer's live conf and
    /// live interface list without saying so, which is how a suite becomes
    /// green-on-one-machine. The defaults belong on `doctor`'s own options,
    /// where they read as documentation instead of as a trap.
    public static func examine(
        stateDirectory: URL,
        wireGuardConf: String,
        addresses: [[UInt8]],
        portIsHeld: @Sendable (UInt16) -> Bool = HostCheck.probePort
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
        findings.append(checkClusterCA(in: stateDirectory))
        findings.append(contentsOf: checkWireGuard(in: stateDirectory, conf: wireGuardConf))
        findings.append(await checkDevices(in: stateDirectory))
        findings.append(contentsOf: portFindings)

        return Report(findings: findings)
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
        case .pinned:
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
    static func checkClusterCA(in directory: URL) -> Finding {
        let caDirectory = directory.appendingPathComponent("ca", isDirectory: true)
        do {
            let der = try ClusterCA.load(from: caDirectory).certificateDER()
            let pin = Wire.base64URL(Data(SHA256.hash(data: der)))
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

    static func checkWireGuard(in directory: URL, conf path: String) -> [Finding] {
        var findings: [Finding] = []
        let keys = directory.appendingPathComponent("wg", isDirectory: true).appendingPathComponent("server.pub")
        let hostKeyExists = FileManager.default.fileExists(atPath: keys.path)
        if hostKeyExists {
            findings.append(Finding(level: .pass, title: "wg host key", detail: "present"))
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
            return findings
        }
        guard let conf = try? String(contentsOfFile: path, encoding: .utf8) else {
            findings.append(Finding(
                level: .fail,
                title: "wg config",
                detail: "\(path) exists but will not read",
                action: "wg-quick reads it as root; doctor reads it as you. Check the owner and mode — editing it under sudo is how it stops being yours."
            ))
            return findings
        }
        let peers = conf.components(separatedBy: "[Peer]").count - 1
        findings.append(Finding(
            level: peers > 0 ? .pass : .wait,
            title: "wg config",
            detail: "\(peers) peer\(peers == 1 ? "" : "s") in \(path)",
            action: peers > 0 ? nil : "No device has been admitted. Pair one, then apply with sudo wg-quick down/up reach0."
        ))
        return findings
    }

    static func checkDevices(in directory: URL) async -> Finding {
        let devices = await DeviceRegistry(directory: directory).all
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
