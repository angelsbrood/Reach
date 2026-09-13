import Foundation
import DurableRootKeys
import RecoveryAuthorityContract

/// One local transaction and exactly its own key selectors. No paired S85 core.
public struct RoleBootstrapCore: Codable, Equatable {
    public let version: Int, role: BootstrapRole
    public let identifier: String, localID: String, root: String, container: String
    public let agreement: String, selection: String, boot: String, epoch: String
    public let origin: UInt64, quota: Int
    public let keys: [RootKeyReference]
    public let lifecycle: RoleLifecycleIdentity?
    public let authority: AuthorityProvision?
    public let unlockPolicy: String?
    public var policy: String { authority.map { role == .host ? $0.hostPolicy : $0.clientPolicy } ?? ("role-monotonic-ns-v1:" + epoch) }
    public init(role: BootstrapRole, localID: String, root: String, agreement: String, selection: String,
                origin: UInt64, epoch: String, boot: String, quota: Int, lifecycle: RoleLifecycleIdentity? = nil, unlockPolicy: String? = nil, authority: AuthorityProvision? = nil) {
        self.authority=authority; version=authority?.native == true ? 5 : authority != nil ? 4 : unlockPolicy != nil ? 3 : lifecycle == nil ? 1 : 2; self.unlockPolicy=unlockPolicy; self.lifecycle=lifecycle; self.role=role; self.localID=localID; self.root=root
        let id=UUID().uuidString.lowercased(); identifier=id; container=root+"/keys/role.keychain-db"
        self.agreement=agreement; self.selection=selection; self.origin=origin
        self.epoch=epoch; self.boot=boot; self.quota=quota
        keys=(role == .host ? [RootKeyRole.hostCatalog,.hostTicket] : [.clientMetadata]).map { .init(bootstrap:id,role:$0) }
    }
    public func validate(role: BootstrapRole, root: String) throws {
        try validateDescription(role:role,root:root)
        try RootKeyCodec.directory(root); _=try RootKeyCodec.parent(container)
        if let lifecycle { try RootKeyCodec.require(lifecycle.identity.present()) }
    }
    public func validateDescription(role: BootstrapRole, root: String) throws {
        try validateStructure(role:role,root:root)
        try RootKeyCodec.require(boot == RootKeyCodec.boot())
    }
    /// Only the explicit cleanup path admits an original v3 role from another boot.
    public func validateForAfterBootRetirement() throws {
        try validateStructure(role:role,root:root)
        try RootKeyCodec.require((version == 3 || version == 4 || version == 5) && unlockPolicy == UnlockCredential.policy && boot != RootKeyCodec.boot())
    }
    /// Explicit qualification authentication; ordinary acquisition still refuses v4.
    public func validateForRecoveryAuthority() throws {
        try validateStructure(role:role,root:root)
        try RootKeyCodec.require(version == 4)
    }
    public func validateForNativeRecovery() throws {
        try validateStructure(role:role,root:root); try RootKeyCodec.require(version == 5 && authority?.native == true)
    }
    var ownershipVersion: Int { version == 5 ? 3 : version == 4 ? 2 : 1 }
    private func validateStructure(role: BootstrapRole, root: String) throws {
        try RootKeyCodec.require((version==1 && lifecycle==nil && unlockPolicy==nil && authority==nil || version==2 && lifecycle != nil && unlockPolicy==nil && authority==nil || version==3 && lifecycle != nil && unlockPolicy==UnlockCredential.policy && authority==nil || version==4 && lifecycle != nil && unlockPolicy==UnlockCredential.policy && authority?.profile == AuthorityCodec.profile || version==5 && lifecycle != nil && unlockPolicy==UnlockCredential.policy && authority?.native == true) && self.role==role && self.root==root && container==root+"/keys/role.keychain-db" &&
            [identifier,localID,boot,epoch].allSatisfy(RootKeyCodec.uuid) && identifier != localID && origin>0 &&
            RootKeyCodec.digest(agreement) && RootKeyCodec.digest(selection) &&
            (BootstrapLimits.minimumQuota...(1<<30)).contains(quota))
        if let authority {
            try authority.validate()
            let records=try authority.originals.records()
            try RootKeyCodec.require(agreement == authority.digest && localID == (role == .host ? authority.hostID : authority.clientID) &&
                origin == (role == .host ? records.host.anchor : records.client.anchor) && epoch == authority.originals.pin.epoch)
        }
        if let lifecycle { try lifecycle.validate(root:root) }
        let roles: [RootKeyRole] = role == .host ? [.hostCatalog,.hostTicket] : [.clientMetadata]
        try RootKeyCodec.require(keys.map(\.role)==roles && Set(keys.map(\.identifier)).count==roles.count)
        for reference in keys { try reference.validate(); try RootKeyCodec.require(reference.bootstrap==identifier) }
        _=try RootKeyCodec.encode(self,limit:BootstrapLimits.record)
    }
    public func binding() throws -> String {
        let domain: String
        switch version {
        case 1: domain="S95/role-bootstrap/v1\0"
        case 2: domain="S96/role-bootstrap/v2\0"
        case 3: domain="S97/role-bootstrap/v3\0"
        case 4: domain="S100/role-bootstrap/v4\0"
        case 5: domain="S101/role-bootstrap/v5\0"
        default: throw BootstrapError.invalid
        }
        return RootKeyCodec.hash(Data(domain.utf8)+Data(try RootKeyCodec.encode(self,limit:BootstrapLimits.record)))
    }
    public func reference(_ role: RootKeyRole) throws -> RootKeyReference {
        guard let key=keys.first(where:{$0.role==role}) else { throw BootstrapError.invalid }; return key
    }
}
public struct RoleBootstrapReady: Codable {
    public let state: String, core: RoleBootstrapCore, confirmations: [Data]
    func validate(role: BootstrapRole, root: String) throws {
        try core.validate(role:role,root:root)
        try RootKeyCodec.require(state=="ready" && confirmations.count==core.keys.count && confirmations.allSatisfy{$0.count==32})
    }
}
public struct RoleBootstrapAcquisition {
    public let ready: RoleBootstrapReady, keys: BootstrapKeys, journal: String
}
