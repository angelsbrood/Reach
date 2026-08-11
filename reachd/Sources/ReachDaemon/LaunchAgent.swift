import Darwin
import Foundation

/// The launchd agent that keeps the daemon running, as data.
///
/// The `service` subcommand does the IO and the printing; everything that
/// can be decided without touching the disk is decided here, so a test can
/// hold it — the same split `HostCheck` and `DoctorCommand` already use.
///
/// ## Why an agent and not a daemon
///
/// Login ownership is the selected product contract. The cluster's state,
/// model process and operator commands belong to one user and one `gui/<uid>`
/// domain; pre-login serving is deliberately unsupported. The listener leaf
/// is imported from disk into process memory, not stored in the login
/// keychain, so keychain folklore is not the reason for this boundary.
///
/// A root process without an explicit state path would resolve `/var/root`,
/// mint a different CA, and silently become a different cluster. The agent
/// therefore pins `REACH_STATE_DIR` explicitly and the CLI refuses ambiguous
/// root entry before touching configuration or CA state. Privileged
/// WireGuard activation remains a separate authority: the current Homebrew
/// script and user-owned hook-capable config are not safe LaunchAgent inputs.
public enum LaunchAgent {
    public static let label = "systems.reach.reachd"

    /// The complete login-owned launch contract, before any filesystem IO.
    ///
    /// `uid` and `domain` do not become redundant merely because launchd can
    /// infer them: service installation, status and removal must all name the
    /// same bootstrap namespace. Keeping the paths here also makes the plist
    /// serializer a mechanical encoding step rather than another authority.
    package struct Definition: Sendable, Equatable {
        package let uid: uid_t
        package let domain: String
        package let executable: String
        package let stateDirectory: URL
        package let logURL: URL
        package let runAtLoad: Bool
        package let keepAlive: Bool
        package let throttleInterval: Int
        package let processType: String

        package var serviceTarget: String { "\(domain)/\(LaunchAgent.label)" }

        package func propertyListData() throws -> Data {
            let propertyList: [String: Any] = [
                "Label": LaunchAgent.label,
                "ProgramArguments": [executable, "serve"],
                "EnvironmentVariables": [DaemonInfo.stateEnvironmentKey: stateDirectory.path],
                "RunAtLoad": runAtLoad,
                "KeepAlive": keepAlive,
                "ThrottleInterval": throttleInterval,
                "StandardOutPath": logURL.path,
                "StandardErrorPath": logURL.path,
                "ProcessType": processType,
            ]
            return try PropertyListSerialization.data(
                fromPropertyList: propertyList,
                format: .xml,
                options: 0
            )
        }
    }

    package static func definition(
        executable: String,
        uid: uid_t = getuid(),
        stateDirectory: URL = DaemonInfo.stateDirectory,
        home: URL? = nil
    ) -> Definition {
        Definition(
            uid: uid,
            domain: "gui/\(uid)",
            executable: executable,
            stateDirectory: stateDirectory,
            logURL: logURL(home: home),
            runAtLoad: true,
            keepAlive: true,
            throttleInterval: 10,
            processType: "Interactive"
        )
    }

    public static func plistURL(home: URL? = nil) -> URL {
        (home ?? FileManager.default.homeDirectoryForCurrentUser)
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    public static func logURL(home: URL? = nil) -> URL {
        (home ?? FileManager.default.homeDirectoryForCurrentUser)
            .appendingPathComponent("Library/Logs/reachd.log")
    }

    /// Checks a path is something launchd can still run in six months.
    public static func executablePath(_ path: String) throws -> String {
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        guard FileManager.default.isExecutableFile(atPath: resolved) else {
            throw ServiceError.notExecutable(resolved)
        }
        // A build directory is not an installation. `~/Library/Caches` is
        // purgeable — macOS reclaims it under disk pressure without asking —
        // so an agent pointed there works until the day it silently does
        // not, and then fails at every login with a missing-file error that
        // reads like nothing in this project.
        if resolved.contains("/Library/Caches/") || resolved.contains("/.build/") {
            throw ServiceError.buildPath(resolved)
        }
        // `reachd` is not a single file. SwiftPM emits resource bundles beside
        // the executable and MLX finds its Metal library by looking there, so
        // a binary copied on its own starts, prints that it is serving, binds
        // the port, and *then* dies on the first thing that touches the GPU.
        // Under launchd that is a crash loop at every login, and the only
        // clue is a metallib path deep inside a build directory. Caught here
        // instead, at the moment someone is still looking at a terminal.
        let beside = URL(fileURLWithPath: resolved)
            .deletingLastPathComponent()
            .appendingPathComponent("mlx-swift_Cmlx.bundle")
        guard FileManager.default.fileExists(atPath: beside.path) else {
            throw ServiceError.missingResources(resolved)
        }
        return resolved
    }

    /// `KeepAlive: true`, and the first draft of this was wrong.
    ///
    /// It shipped as `Crashed: true`, reasoning that the daemon's considered
    /// non-zero exit on a held port should not become a respawn loop. Then
    /// the agent was installed and the daemon `kill -9`'d to see it come
    /// back, **and it did not** — launchd counts a crash as the
    /// SIGSEGV/SIGABRT family, not a deliberate signal. Which also means it
    /// misses the kernel's own `SIGKILL` under memory pressure: the likeliest
    /// unplanned death of a process holding several gigabytes of weights.
    ///
    /// A supervisor whose whole job is that the cluster is there cannot be
    /// selective about which deaths count. Unconditional, with
    /// `ThrottleInterval` bounding the retry: a genuinely held port then
    /// re-attempts every ten seconds and heals itself the moment the port
    /// frees — which is the restart race, and the common case — while a
    /// permanently occupied one writes the reason to the log at the same
    /// pace. That is a log worth having, not noise to design around.
    ///
    /// Both output paths are set because every line the daemon writes is
    /// `print` or stderr, and under launchd those go nowhere by default.
    public static func plist(executable: String, home: URL? = nil) -> String {
        // Preserve the existing source-compatible helper while making
        // PropertyListSerialization the one encoder. Every value in the
        // definition is a property-list primitive, so failure here would be a
        // programmer error rather than an operator input failure; the service
        // command uses the throwing `propertyListData()` path directly.
        String(
            decoding: try! definition(
                executable: executable,
                stateDirectory: DaemonInfo.stateDirectory,
                home: home
            ).propertyListData(),
            as: UTF8.self
        )
    }

    package static func stateDirectory(inPlist data: Data) -> URL? {
        guard let dictionary = try? PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any],
        let environment = dictionary["EnvironmentVariables"] as? [String: String],
        let path = environment[DaemonInfo.stateEnvironmentKey],
        !path.isEmpty
        else { return nil }
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    /// Pure status rendering: a loaded process and an away-ready host are
    /// separate facts. `service status` supplies launchctl output and the
    /// current address set; tests can hold every sentence without a live job.
    package static func statusLines(
        definition: Definition,
        installedPath: String?,
        launchctlOutput: String?,
        addresses: [[UInt8]]
    ) -> [String] {
        var lines = [
            "[reachd] owner: login uid \(definition.uid), domain \(definition.domain)",
            "[reachd] state: \(definition.stateDirectory.path) (explicit \(DaemonInfo.stateEnvironmentKey))",
            "[reachd] log: \(definition.logURL.path)",
            "[reachd] plist: \(installedPath ?? "not installed")",
        ]
        if let launchctlOutput {
            let state = launchctlOutput
                .split(separator: "\n")
                .first { $0.contains("state = ") || $0.contains("pid = ") }
                .map { $0.trimmingCharacters(in: .whitespaces) } ?? "loaded"
            lines.append("[reachd] agent: \(state)")
        } else {
            lines.append("[reachd] agent: not loaded")
        }

        let mesh = addresses.first { $0.count == 4 && $0[0] == 10 && $0[1] == 86 }
        if let mesh {
            lines.append("[reachd] mesh: ready — \(mesh.map(String.init).joined(separator: ".")) is present")
        } else {
            lines.append("[reachd] mesh: missing — the login service may answer on LAN, but away readiness is incomplete")
        }
        return lines
    }
}

/// Entry guards for the selected login-owned contract.
package enum LoginOwnedHost {
    package static func authorizeServiceInstall(effectiveUID: uid_t) throws {
        guard effectiveUID != 0 else { throw ServiceError.rootInstall }
    }

    package static func authorizeServe(
        effectiveUID: uid_t,
        environment: [String: String]
    ) throws {
        guard effectiveUID == 0 else { return }
        let override = environment[DaemonInfo.stateEnvironmentKey] ?? ""
        guard !override.isEmpty, override.hasPrefix("/") else {
            throw ServiceError.rootServeNeedsExplicitState
        }
    }
}

public enum ServiceError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case notExecutable(String)
    case buildPath(String)
    case missingResources(String)
    case launchctlRefused(String)
    case rootInstall
    case rootServeNeedsExplicitState

    public var description: String {
        switch self {
        case .notExecutable(let path):
            "there is no runnable reachd at \(path) — pass --executable with the path to the built binary"
        case .buildPath(let path):
            "\(path) is inside a build directory, and macOS purges those without asking — copy reachd somewhere permanent and install from there"
        case .missingResources(let path):
            "\(path) has no mlx-swift_Cmlx.bundle beside it — reachd is not a single file, and without its resource bundles it starts, says it is serving, and then dies loading the model. Copy the whole build directory's bundles alongside the binary, not just the binary"
        case .launchctlRefused(let detail):
            "launchd would not take the agent: \(detail)"
        case .rootInstall:
            "service install is login-owned and refuses root — run it as the user whose gui domain and Reach state should own the cluster"
        case .rootServeNeedsExplicitState:
            "root serve refuses an implicit state directory — set REACH_STATE_DIR to an explicit absolute scratch path; pre-login serving is unsupported"
        }
    }

    public var errorDescription: String? { description }
}
