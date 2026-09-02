import Foundation
import ReachHost

public enum DaemonProviderKind: Sendable, Equatable {
    case mlx
    case exo(authority: String)

    public var description: String {
        switch self {
        case .mlx: "MLX"
        case .exo(let authority): "EXO at \(authority)"
        }
    }
}

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
    public var modelID: String = "gemma-4-e4b"
    public var exo: EXOConfiguration?
    /// The mesh endpoint pinned at the ceremony (host:port for WireGuard).
    /// Absent means the daemon derives one; `MeshEndpoint.resolve` says so out
    /// loud, because a derived endpoint is LAN-only and the away leg needs a
    /// pin.
    public var meshEndpoint: String?

    public init() {}

    private enum CodingKeys: String, CodingKey {
        case clusterID
        case clusterName
        case port
        case enrollPort
        case modelID
        case exo
        case meshEndpoint
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        clusterID = try container.decode(UUID.self, forKey: .clusterID)
        clusterName = try container.decode(String.self, forKey: .clusterName)
        port = try container.decode(UInt16.self, forKey: .port)
        enrollPort = try container.decode(UInt16.self, forKey: .enrollPort)
        modelID = try container.decode(String.self, forKey: .modelID)
        meshEndpoint = try container.decodeIfPresent(String.self, forKey: .meshEndpoint)
        if container.contains(.exo) {
            guard try !container.decodeNil(forKey: .exo) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .exo,
                    in: container,
                    debugDescription: "explicit null EXO configuration is not valid"
                )
            }
            exo = try container.decode(EXOConfiguration.self, forKey: .exo)
        } else {
            exo = nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clusterID, forKey: .clusterID)
        try container.encode(clusterName, forKey: .clusterName)
        try container.encode(port, forKey: .port)
        try container.encode(enrollPort, forKey: .enrollPort)
        try container.encode(modelID, forKey: .modelID)
        try container.encodeIfPresent(meshEndpoint, forKey: .meshEndpoint)
        try container.encodeIfPresent(exo, forKey: .exo)
    }

    @discardableResult
    public mutating func applyModelOverride(_ override: String?) -> Bool {
        guard let override else { return false }
        modelID = override
        return true
    }

    public var providerKind: DaemonProviderKind {
        guard let exo else { return .mlx }
        return .exo(authority: exo.authority)
    }

    public func makeFilling() throws -> any SlotFilling {
        if let exo {
            return try EXOFilling(modelID: modelID, endpoint: exo.endpoint)
        }
        return MLXFilling(modelID: modelID)
    }

    public func statusDescription(version: String = DaemonInfo.version) -> String {
        switch providerKind {
        case .mlx:
            return "reachd \(version) — cluster \"\(clusterName)\", model \(modelID), port \(port)"
        case .exo(let authority):
            return "reachd \(version) — cluster \"\(clusterName)\", model \(modelID) via EXO at \(authority), port \(port)"
        }
    }

    public func startupDescription(addresses: [[UInt8]]) -> String {
        let renderedAddresses = addresses
            .map { $0.map(String.init).joined(separator: ".") }
            .joined(separator: ", ")
        switch providerKind {
        case .mlx:
            return "[reachd] \(clusterName) serving \(modelID) on :\(port) (\(renderedAddresses))"
        case .exo(let authority):
            return "[reachd] \(clusterName) serving \(modelID) via EXO at \(authority) on :\(port) (\(renderedAddresses))"
        }
    }

    public var prewarmSuccessDescription: String {
        switch providerKind {
        case .mlx: "[reachd] model prewarmed"
        case .exo: "[reachd] EXO catalog check passed"
        }
    }

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
