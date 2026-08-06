import Foundation

/// The launchd agent that keeps the daemon running, as data.
///
/// The `service` subcommand does the IO and the printing; everything that
/// can be decided without touching the disk is decided here, so a test can
/// hold it — the same split `HostCheck` and `DoctorCommand` already use.
///
/// ## Why an agent and not a daemon
///
/// A `LaunchDaemon` starts at boot without anyone logging in, which is what
/// you actually want from a cluster. It cannot have it here, for two reasons
/// that are both about where the cluster's keys live:
///
/// 1. **The login keychain.** `IdentityMaterializer` imports the listener's
///    identity into it on every start, and a root `LaunchDaemon` has no
///    login keychain to import into. That identity is the cluster's TLS
///    identity — without it there is no listener at all.
/// 2. **The state directory.** `DaemonInfo.stateDirectory` resolves the home
///    directory through `FileManager`, which reads the password database and
///    ignores `HOME`. As root that is `/var/root/Library/Application
///    Support`, where `serve` would find no CA and **mint a fresh one** —
///    not a broken service but a *different cluster*, with every paired
///    phone orphaned and every grant void. `REACH_STATE_DIR` can point that
///    back; the keychain cannot be pointed anywhere.
///
/// So: an agent, starting at login rather than at boot. Worth saying plainly
/// rather than implying a Mac that has rebooted is serving before someone
/// has sat down at it.
public enum LaunchAgent {
    public static let label = "systems.reach.reachd"

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
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(executable)</string>
                <string>serve</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>ThrottleInterval</key>
            <integer>10</integer>
            <key>StandardOutPath</key>
            <string>\(logURL(home: home).path)</string>
            <key>StandardErrorPath</key>
            <string>\(logURL(home: home).path)</string>
            <key>ProcessType</key>
            <string>Interactive</string>
        </dict>
        </plist>
        """
    }
}

public enum ServiceError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case notExecutable(String)
    case buildPath(String)
    case missingResources(String)
    case launchctlRefused(String)

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
        }
    }

    public var errorDescription: String? { description }
}
