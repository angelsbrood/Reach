import Foundation

public struct EXOConfiguration: Codable, Sendable, Equatable {
    public let endpoint: String

    /// The already-validated host and port, for status text without exposing
    /// the transport's URL parser as public API.
    public var authority: String {
        // Construction and decoding both validated `endpoint`, so this cannot
        // fail unless the stored representation has somehow been corrupted.
        (try? EXOEndpoint(endpoint).authority) ?? endpoint
    }

    public init(endpoint: String) throws {
        _ = try EXOEndpoint(endpoint)
        self.endpoint = endpoint
    }

    private enum CodingKeys: String, CodingKey { case endpoint }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let endpoint = try container.decode(String.self, forKey: .endpoint)
        do {
            try self.init(endpoint: endpoint)
        } catch {
            throw DecodingError.dataCorruptedError(
                forKey: .endpoint,
                in: container,
                debugDescription: "EXO endpoint is not canonical numeric loopback HTTP"
            )
        }
    }
}

public enum PortableEXOConfigurationError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    case explicitEXORequired

    public var description: String {
        "the portable Reach host requires an explicit numeric-loopback EXO configuration"
    }

    public var errorDescription: String? { description }
}

/// The Linux product's only provider selection surface. It deliberately has
/// no MLX fallback: absence is a legible refusal before a loader is created.
public struct PortableEXOHostConfiguration: Codable, Sendable, Equatable {
    public var modelID: String
    public var exo: EXOConfiguration?

    public init(modelID: String, exo: EXOConfiguration?) {
        self.modelID = modelID
        self.exo = exo
    }

    public func makeFilling() throws -> EXOFilling {
        guard let exo else { throw PortableEXOConfigurationError.explicitEXORequired }
        return try EXOFilling(modelID: modelID, endpoint: exo.endpoint)
    }
}
