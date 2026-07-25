import Foundation

/// What went wrong reading a config that exists. "Absent" is deliberately not
/// a case here: a missing config is a first run, and defaults are the correct
/// answer for one. A config that exists and will not decode is an operator's
/// typo, and inventing defaults for it silently discards the pinned mesh
/// endpoint and the cluster name — a failure that surfaces hours later, at the
/// far end of a walk-out, looking like a routing fault.
public enum ConfigError: Error, CustomStringConvertible, LocalizedError {
    case unreadable(path: String, underlying: any Error)
    case malformed(path: String, underlying: any Error)

    public var description: String {
        switch self {
        case .unreadable(let path, let underlying):
            """
            config.json at \(path) cannot be read: \(underlying)
            """
        case .malformed(let path, let underlying):
            """
            config.json at \(path) will not parse: \(underlying)

            Refusing to start on a config that cannot be read. Starting anyway \
            would silently revert the pinned mesh endpoint and the cluster \
            name, and the daemon would look healthy while handing out the \
            wrong address. Values are JSON — strings quoted, commas between \
            entries — or move the file aside to start fresh.
            """
        }
    }

    public var errorDescription: String? { description }
}

public struct DaemonConfig: Codable, Sendable {
    public var clusterID: UUID = UUID()
    public var clusterName: String = "Reach Cluster"
    public var port: UInt16 = 47337
    public var enrollPort: UInt16 = 47338
    public var modelID: String = "gemma-3-1b"
    /// The mesh endpoint pinned at the ceremony (host:port for WireGuard).
    /// Absent means the daemon derives one; `MeshEndpoint.resolve` says so out
    /// loud, because a derived endpoint is LAN-only and the away leg needs a
    /// pin.
    public var meshEndpoint: String?

    public init() {}

    static func url(in directory: URL) -> URL {
        directory.appendingPathComponent("config.json")
    }

    /// Whether a config file exists — the difference between a first run and a
    /// run that should leave the operator's file alone.
    public static func exists(in directory: URL = DaemonInfo.stateDirectory) -> Bool {
        FileManager.default.fileExists(atPath: url(in: directory).path)
    }

    /// Throws only when the file exists and cannot be turned into a config.
    public static func load(from directory: URL = DaemonInfo.stateDirectory) throws -> DaemonConfig {
        let url = url(in: directory)
        guard FileManager.default.fileExists(atPath: url.path) else {
            return DaemonConfig()
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw ConfigError.unreadable(path: url.path, underlying: error)
        }
        do {
            return try JSONDecoder().decode(DaemonConfig.self, from: data)
        } catch {
            throw ConfigError.malformed(path: url.path, underlying: error)
        }
    }

    public func save(to directory: URL = DaemonInfo.stateDirectory) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: Self.url(in: directory), options: .atomic)
    }
}
