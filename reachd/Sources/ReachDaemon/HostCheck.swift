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
    public enum Level: String, Sendable, Equatable {
        case pass = "PASS"
        case warn = "WARN"
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
        do {
            config = try DaemonConfig.load(from: stateDirectory)
            findings.append(Finding(
                level: .pass,
                title: "config.json",
                detail: DaemonConfig.exists(in: stateDirectory)
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

        findings.append(contentsOf: checkMeshEndpoint(config: config, addresses: addresses))
        findings.append(checkMeshInterface(addresses))
        findings.append(checkClusterCA(in: stateDirectory))
        findings.append(contentsOf: checkWireGuard(in: stateDirectory, conf: wireGuardConf))
        findings.append(await checkDevices(in: stateDirectory))
        findings.append(contentsOf: checkPorts(config: config, isHeld: portIsHeld))

        return Report(findings: findings)
    }

    // MARK: - Checks

    static func checkStateDirectory(_ directory: URL) -> Finding {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return Finding(
                level: .warn,
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

    static func checkMeshEndpoint(config: DaemonConfig?, addresses: [[UInt8]]) -> [Finding] {
        guard let config else { return [] }
        let mesh = MeshEndpoint.resolve(config: config, addresses: addresses)

        switch mesh.source {
        case .derived:
            return [Finding(
                level: .warn,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) — derived from a local address, not pinned",
                action: "LAN rehearsals work; the away leg does not. Set meshEndpoint in config.json to the address the phone will dial."
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
            findings.append(Finding(
                level: .warn,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) pinned, RFC1918",
                action: "Dialable from cellular only if the edge forwards UDP \(MeshEndpoint.port) to it. Behind a second router, pin that router's public address instead — two forwards in series."
            ))
        case .sharedAddressSpace:
            findings.append(Finding(
                level: .warn,
                title: "mesh endpoint",
                detail: "\(mesh.endpoint) pinned, 100.64/10",
                action: "Carrier-grade NAT, or a tailnet. A venue's WAN lease in this range cannot carry the away leg; a tailnet address works only if the phone is on the same tailnet."
            ))
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

    static func checkMeshInterface(_ addresses: [[UInt8]]) -> Finding {
        let rendered = addresses.map(MeshEndpoint.string(from:))
        let meshUp = addresses.contains { Array($0.prefix(3)) == MeshEndpoint.meshPrefix }
        guard meshUp else {
            return Finding(
                level: .fail,
                title: "mesh interface",
                detail: "no 10.86.0.x address — reach0 is down (\(rendered.joined(separator: ", ")))",
                action: "sudo wg-quick up reach0 (standing order: before reachd serve) — until it exists, the away leg has no mesh candidate to fall to."
            )
        }
        return Finding(
            level: .pass,
            title: "mesh interface",
            detail: "up; daemon will declare \(rendered.joined(separator: ", "))"
        )
    }

    static func checkClusterCA(in directory: URL) -> Finding {
        let caDirectory = directory.appendingPathComponent("ca", isDirectory: true)
        guard let ca = try? ClusterCA.load(from: caDirectory), let der = try? ca.certificateDER() else {
            return Finding(
                level: .warn,
                title: "cluster CA",
                detail: "absent or unreadable",
                action: "Created on first serve or pair. A CA that vanished invalidates every enrolled device."
            )
        }
        let pin = Wire.base64URL(Data(SHA256.hash(data: der)))
        return Finding(level: .pass, title: "cluster CA", detail: "present; pin \(pin)")
    }

    static func checkWireGuard(in directory: URL, conf path: String) -> [Finding] {
        var findings: [Finding] = []
        let keys = directory.appendingPathComponent("wg", isDirectory: true).appendingPathComponent("server.pub")
        if FileManager.default.fileExists(atPath: keys.path) {
            findings.append(Finding(level: .pass, title: "wg host key", detail: "present"))
        } else {
            findings.append(Finding(
                level: .warn,
                title: "wg host key",
                detail: "absent",
                action: "Minted on first serve. A new key means every enrolled device must re-pair."
            ))
        }

        guard let conf = try? String(contentsOfFile: path, encoding: .utf8) else {
            findings.append(Finding(
                level: .warn,
                title: "wg config",
                detail: "\(path) not readable",
                action: "Written on first serve; wg-quick reads it as root."
            ))
            return findings
        }
        let peers = conf.components(separatedBy: "[Peer]").count - 1
        findings.append(Finding(
            level: peers > 0 ? .pass : .warn,
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
                level: .warn,
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
        guard let config else { return [] }
        return [(config.port, "session"), (config.enrollPort, "enrollment")].map { port, role in
            if isHeld(port) {
                Finding(level: .pass, title: "\(role) port", detail: ":\(port) held — a daemon is running")
            } else {
                Finding(level: .warn, title: "\(role) port", detail: ":\(port) free — no daemon running")
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
