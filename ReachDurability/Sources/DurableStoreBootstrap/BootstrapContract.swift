import Foundation
import DurableRootKeys

public enum BootstrapError: Error, Equatable { case disabled, invalid, incomplete, busy, closed, io(String, Int32) }
public enum BootstrapLimits {
    public static let record = 64<<10, storage = 1<<20, minimumQuota = (2<<20)+(64<<10), maximumQuota = 2<<30
    public static let revision = "s85-bootstrap-v1", projection = "s84-host-client-v1"
    public static let sourceBinding = "4a49528cc05b6a8cf5080ba1efd59cb0411c9580a378f22a98160dbc50135169"
}
public enum BootstrapRole: String, Codable { case host, client }
public enum BootstrapFault: String {
    case beforeIntentWrite, beforeFileSync, afterIntent, afterFirstKey, afterStores
    case beforeReadyRename, afterReadyRename, beforeReadySync, afterReady
}
public typealias BootstrapHook = (BootstrapFault) throws -> Void
public struct BootstrapPolicy: Codable, Equatable {
    public var boot: String, hostClock: String, clientClock: String, hostQuota: Int, clientQuota: Int
    public init(boot: String, hostClock: String = "system-monotonic-raw-ns-v1", clientClock: String = "system-monotonic-raw-ns-v1",
                hostQuota: Int = BootstrapLimits.maximumQuota, clientQuota: Int = BootstrapLimits.maximumQuota) {
        self.boot = boot; self.hostClock = hostClock; self.clientClock = clientClock; self.hostQuota = hostQuota; self.clientQuota = clientQuota
    }
    public static func current() throws -> Self { try .init(boot: RootKeyCodec.boot()) }
    public func validate() throws {
        try RootKeyCodec.require(RootKeyCodec.uuid(boot) && boot == RootKeyCodec.boot())
        for clock in [hostClock, clientClock] {
            try RootKeyCodec.require(clock.utf8.count <= 256 && (clock == "system-monotonic-raw-ns-v1" || clock.hasPrefix("fixture-ns-v1:")))
        }
        try RootKeyCodec.require((BootstrapLimits.minimumQuota...BootstrapLimits.maximumQuota).contains(hostQuota) &&
            (BootstrapLimits.minimumQuota...BootstrapLimits.maximumQuota).contains(clientQuota))
    }
}
public struct BootstrapCore: Codable, Equatable {
    public var version = 1
    public var identifier: String, hostID: String, clientID: String, container: String, policy: BootstrapPolicy
    public var revision = BootstrapLimits.revision, projection = BootstrapLimits.projection, sourceBinding = BootstrapLimits.sourceBinding
    public var hostLocation = "host", clientLocation = "client"
    public var keys: [RootKeyReference]
    public init(container: String, policy: BootstrapPolicy) {
        let identifier = UUID().uuidString.lowercased(); self.identifier = identifier
        hostID = UUID().uuidString.lowercased(); clientID = UUID().uuidString.lowercased()
        self.container = container; self.policy = policy
        keys = RootKeyRole.allCases.map { .init(bootstrap: identifier, role: $0) }
    }
    public func validate(expected: BootstrapPolicy) throws {
        try policy.validate(); try expected.validate()
        try RootKeyCodec.require(version == 1 && RootKeyCodec.encode(policy) == RootKeyCodec.encode(expected) && revision == BootstrapLimits.revision &&
            projection == BootstrapLimits.projection && sourceBinding == BootstrapLimits.sourceBinding &&
            hostLocation == "host" && clientLocation == "client" && container.hasSuffix(".keychain-db"))
        _ = try RootKeyCodec.parent(container)
        try RootKeyCodec.require([identifier,hostID,clientID].allSatisfy(RootKeyCodec.uuid) && Set([identifier,hostID,clientID]).count == 3 &&
            keys.map(\.role) == RootKeyRole.allCases && Set(keys.map(\.identifier)).count == 3)
        for reference in keys { try reference.validate(); try RootKeyCodec.require(reference.bootstrap == identifier) }
        _ = try RootKeyCodec.encode(self, limit: BootstrapLimits.record)
    }
    public func binding() throws -> String { RootKeyCodec.hash(Data("S85/bootstrap-core/v1\0".utf8)+Data(try RootKeyCodec.encode(self, limit: BootstrapLimits.record))) }
    public func reference(_ role: RootKeyRole) throws -> RootKeyReference {
        guard let result = keys.first(where: { $0.role == role }) else { throw BootstrapError.invalid }; return result
    }
}
public struct BootstrapReady: Codable, Equatable {
    public var state = "ready", core: BootstrapCore, confirmations: [Data]
    public init(core: BootstrapCore, confirmations: [Data]) { self.core = core; self.confirmations = confirmations }
    public func validate(expected: BootstrapPolicy) throws {
        try core.validate(expected: expected)
        try RootKeyCodec.require(state == "ready" && confirmations.count == 3 && confirmations.allSatisfy { $0.count == 32 })
        _ = try RootKeyCodec.encode(self, limit: BootstrapLimits.record)
    }
}
public struct BootstrapKeys {
    private let values: [RootKeyRole:RootKeyMaterial]
    init(_ values: [RootKeyRole:RootKeyMaterial]) { self.values = values }
    public func key(_ role: RootKeyRole) throws -> RootKeyMaterial {
        guard let key = values[role] else { throw BootstrapError.invalid }; return key
    }
}
public struct BootstrapAcquisition {
    public let descriptor: BootstrapReady, keys: BootstrapKeys, journal: String
}
