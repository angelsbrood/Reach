import Foundation
import ReachIdentity
import Security

/// Process-wide registry mapping identity labels to Security objects.
/// `LanguageModelExecutor.Configuration` must be `Hashable`, so the
/// configuration carries a label and the material lives here. Apps register
/// once at startup (from a provisioning bundle in Phase 1; from the
/// ceremony's keychain items thereafter).
public actor ReachIdentityRegistry {
    public static let shared = ReachIdentityRegistry()

    public struct Material: @unchecked Sendable {
        public let identity: SecIdentity
        public let caCertificate: SecCertificate

        public init(identity: SecIdentity, caCertificate: SecCertificate) {
            self.identity = identity
            self.caCertificate = caCertificate
        }
    }

    private var materials: [String: Material] = [:]

    public func register(label: String, material: Material) {
        materials[label] = material
    }

    /// Installs a Phase 1 provisioning bundle and registers it.
    @discardableResult
    public func register(label: String, provisioned: ProvisionedIdentity) throws -> Material {
        let (identity, ca) = try provisioned.install(label: label)
        let material = Material(identity: identity, caCertificate: ca)
        materials[label] = material
        return material
    }

    public func material(for label: String) -> Material? {
        materials[label]
    }
}
