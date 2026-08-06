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
        return resolved
    }

    /// `Crashed`, deliberately, and not `SuccessfulExit: false`.
    ///
    /// The daemon now refuses to start when it cannot take its port, and
    /// exits non-zero saying so. Under `SuccessfulExit: false` that refusal
    /// becomes an endless respawn against a port that is never coming free,
    /// with the reason scrolling past ten seconds at a time. `Crashed`
    /// restarts what died — a signal, a `kill -9`, a real fault — and leaves
    /// a considered refusal standing where someone can read it.
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
            <dict>
                <key>Crashed</key>
                <true/>
            </dict>
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
    case launchctlRefused(String)

    public var description: String {
        switch self {
        case .notExecutable(let path):
            "there is no runnable reachd at \(path) — pass --executable with the path to the built binary"
        case .buildPath(let path):
            "\(path) is inside a build directory, and macOS purges those without asking — copy reachd somewhere permanent such as /usr/local/bin and install from there"
        case .launchctlRefused(let detail):
            "launchd would not take the agent: \(detail)"
        }
    }

    public var errorDescription: String? { description }
}
