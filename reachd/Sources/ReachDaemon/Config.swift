import Foundation

public struct DaemonConfig: Codable, Sendable {
    public var clusterID: UUID = UUID()
    public var clusterName: String = "Reach Cluster"
    public var port: UInt16 = 47337
    public var enrollPort: UInt16 = 47338
    public var modelID: String = "gemma-3-1b"
    /// The mesh endpoint pinned at the ceremony (host:port for WireGuard).
    /// Defaults to the first LAN address; the demo environment overrides.
    public var meshEndpoint: String?

    public init() {}

    public static func load(from directory: URL = DaemonInfo.stateDirectory) -> DaemonConfig {
        let url = directory.appendingPathComponent("config.json")
        guard let data = try? Data(contentsOf: url),
              let config = try? JSONDecoder().decode(DaemonConfig.self, from: data)
        else {
            return DaemonConfig()
        }
        return config
    }

    public func save(to directory: URL = DaemonInfo.stateDirectory) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: directory.appendingPathComponent("config.json"))
    }
}
