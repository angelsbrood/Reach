import Foundation
import CryptoKit
import ClockPolicy

public enum AuthorityError: String, Error { case invalid, ineligible, scope, partial, state, issuer }
public enum AuthorityCodec {
    public static let profile = "reach-recovery-authority-qualification-v1"
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try ClockPolicy.Wire.encode(value) }
    public static func decode<T: Codable>(_ type: T.Type, _ data: Data) throws -> T { try ClockPolicy.Wire.decode(type, data) }
    public static func hash(_ data: Data) -> String { ClockPolicy.Wire.digest(data) }
    public static func digest<T: Encodable>(_ value: T) throws -> String { hash(try encode(value)) }
    public static func uuid(_ value: String) -> Bool { value.count == 36 && UUID(uuidString:value)?.uuidString.lowercased() == value }
    public static func isDigest(_ value: String) -> Bool { value.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    public static func require(_ condition: Bool) throws { if !condition { throw AuthorityError.invalid } }
}

/// Trusted original provisioning precedes either bootstrap. The clock records
/// are the exact signed originals; no receiver timestamp is an authority anchor.
public struct AuthorityProvision: Codable, Equatable {
    public let version: Int, profile: String
    public let originals: Originals
    public let pair: String, hostID: String, clientID: String
    public let publicModelDigest: String, requestInputDigest: String
    public init(originals: Originals, hostID: String, clientID: String,
                publicModelDigest: String, requestInputDigest: String) throws {
        version = 1; profile = AuthorityCodec.profile; self.originals = originals
        pair = try originals.records().host.subject
        self.hostID = hostID; self.clientID = clientID
        self.publicModelDigest = publicModelDigest; self.requestInputDigest = requestInputDigest
        try validate()
    }
    public func validate() throws {
        let r = try originals.records()
        try AuthorityCodec.require(version == 1 && profile == AuthorityCodec.profile && pair == r.host.subject &&
            [pair,hostID,clientID].allSatisfy(AuthorityCodec.uuid) && Set([pair,hostID,clientID]).count == 3 &&
            [publicModelDigest,requestInputDigest].allSatisfy(AuthorityCodec.isDigest) && r.host.anchor > 0 && r.client.anchor > 0)
        _ = try AuthorityCodec.encode(self)
    }
    public var digest: String { get throws { try validate(); return try AuthorityCodec.digest(self) } }
    public var hostPolicy: String { AuthorityCodec.profile + ":host:" + pair }
    public var clientPolicy: String { AuthorityCodec.profile + ":client:" + pair }
}

/// Created from original ready/ownership records, never inferred from admission.
public struct AuthorityRoot: Codable, Equatable {
    public let role: String, identifier: String, localID: String, root: String, boot: String, core: String
    public init(role: String, identifier: String, localID: String, root: String, boot: String, core: String) {
        self.role=role; self.identifier=identifier; self.localID=localID; self.root=root; self.boot=boot; self.core=core
    }
    public func validate() throws {
        try AuthorityCodec.require(["host","client"].contains(role) && [identifier,localID,boot].allSatisfy(AuthorityCodec.uuid) &&
            root.hasPrefix("/") && root.utf8.count <= 3072 && AuthorityCodec.isDigest(core))
    }
}
public struct AuthorityScope: Codable, Equatable {
    public let version: Int, profile: String
    public let provision: AuthorityProvision, host: AuthorityRoot, client: AuthorityRoot
    public var namespace: String { provision.pair }
    public var generation: String { "generation-" + provision.pair }
    public init(provision: AuthorityProvision, host: AuthorityRoot, client: AuthorityRoot) throws {
        version=1; profile=AuthorityCodec.profile; self.provision=provision; self.host=host; self.client=client
        try validate()
    }
    public func validate() throws {
        try provision.validate(); try host.validate(); try client.validate()
        try AuthorityCodec.require(version == 1 && profile == AuthorityCodec.profile && host.role == "host" && client.role == "client" &&
            host.localID == provision.hostID && client.localID == provision.clientID && host.boot == client.boot &&
            host.identifier != client.identifier && host.root != client.root && host.core != client.core)
    }
    public var digest: String { get throws { try validate(); return try AuthorityCodec.digest(self) } }
}

/// Acyclic: provisioning -> bootstrap -> scope -> request/ticket/store -> export.
/// The host MAC is verified at the host; the exported body is also signed by an
/// issuer derived from its original confirmed ticket key. Initial acceptance
/// pins that issuer and the successful export digest through trusted local control.
public struct AuthorityAdmission: Codable, Equatable {
    public let version: Int, profile: String, scope: AuthorityScope
    public let ticket: Data, context: Data
    public let requestDigest: String, providerDigest: String, record: String, store: String
    public init(scope: AuthorityScope, ticket: Data, context: Data, requestDigest: String,
                providerDigest: String, record: String, store: String) throws {
        version=1; profile=AuthorityCodec.profile; self.scope=scope; self.ticket=ticket; self.context=context
        self.requestDigest=requestDigest; self.providerDigest=providerDigest; self.record=record; self.store=store
        try validate()
    }
    public func validate() throws {
        try scope.validate()
        try AuthorityCodec.require(version == 1 && profile == AuthorityCodec.profile && (41...4096).contains(ticket.count) &&
            !context.isEmpty && context.count <= 16<<10 && [requestDigest,providerDigest].allSatisfy(AuthorityCodec.isDigest) &&
            [record,store].allSatisfy(AuthorityCodec.uuid))
        _ = try AuthorityCodec.encode(self)
    }
    public var digest: String { get throws { try validate(); return try AuthorityCodec.digest(self) } }
}
public struct AuthorityIssued: Codable, Equatable {
    public let body: Data, signature: Data
    public static func issuerKey(ticketKey: Data) throws -> Curve25519.Signing.PrivateKey {
        try AuthorityCodec.require(ticketKey.count == 32)
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial:SymmetricKey(data:ticketKey),
            info:Data("S100/original-admission-issuer/v1".utf8),outputByteCount:32)
        return try derived.withUnsafeBytes { try Curve25519.Signing.PrivateKey(rawRepresentation:Data($0)) }
    }
    public init(_ admission: AuthorityAdmission, ticketKey: Data) throws {
        try admission.validate(); body=try AuthorityCodec.encode(admission)
        signature=try Self.issuerKey(ticketKey:ticketKey).signature(for:body)
    }
    public func verify(issuer: Data, expectedDigest: String) throws -> AuthorityAdmission {
        guard issuer.count == 32, signature.count == 64, expectedDigest == (try AuthorityCodec.digest(self)),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation:issuer), key.isValidSignature(signature,for:body)
        else { throw AuthorityError.issuer }
        let a = try AuthorityCodec.decode(AuthorityAdmission.self,body); try a.validate(); return a
    }
}
/// Persisted only as part of authenticated original client acceptance. Recovery
/// receives neither this pin nor a replacement ticket from a caller.
public struct AuthorityAcceptance: Codable, Equatable {
    public let version: Int, issuer: Data, expectedDigest: String, issued: AuthorityIssued
    public init(issued: AuthorityIssued, originalIssuer: Data, originalSuccessfulExportDigest: String) throws {
        version=1; issuer=originalIssuer; expectedDigest=originalSuccessfulExportDigest; self.issued=issued
        _ = try admission()
    }
    public func admission() throws -> AuthorityAdmission {
        try AuthorityCodec.require(version == 1)
        return try issued.verify(issuer:issuer,expectedDigest:expectedDigest)
    }
}

/// Root storage exists before the paired admission. Its AAD binds the earlier
/// original core, independently of any future request, ticket or manifest.
public struct AuthorityStorageIdentity: Equatable {
    public let provision: AuthorityProvision, root: AuthorityRoot, quota: Int
    public init(provision: AuthorityProvision, root: AuthorityRoot, quota: Int) throws {
        self.provision=provision; self.root=root; self.quota=quota; try validate()
    }
    public func validate() throws {
        try provision.validate(); try root.validate()
        try AuthorityCodec.require(root.localID == (root.role == "host" ? provision.hostID : provision.clientID) &&
            ((3<<20)...(1<<30)).contains(quota))
    }
    public var policy: String { root.role == "host" ? provision.hostPolicy : provision.clientPolicy }
    public var anchor: UInt64 { get throws { let r=try provision.originals.records(); return root.role == "host" ? r.host.anchor : r.client.anchor } }
    public var deadline: UInt64 { get throws { let r=try provision.originals.records(); return root.role == "host" ? r.host.deadline : r.client.deadline } }
    public var digest: String { get throws { try validate(); return try AuthorityCodec.digest([provision.digest,AuthorityCodec.digest(root),String(quota)]) } }
    public func check(_ scope: AuthorityScope, role: String) throws {
        try validate(); try scope.validate()
        try AuthorityCodec.require(provision == scope.provision && root == (role == "host" ? scope.host : scope.client) && root.role == role)
    }
}

/// Bounded non-content diagnostics. No original ticket, context, request,
/// decrypted record, handle or reusable authorization leaves authentication.
public struct AuthorityDiagnostic: Codable {
    public let profile: String, operation: AuthorityOperation, phase: String
    public let scope: String, admission: String, ticket: String, context: String, request: String, record: String, store: String
    public private(set) var evaluation: Evaluation
    public mutating func refresh(action: RecoveryAuthorityAction) throws {
        try action.confirmPublicationDigest(admission,scope:scope,operation:operation)
        evaluation=try action.check(scope:action.scope,operation:operation)
    }
    public init(admission a: AuthorityAdmission, phase: String, action: RecoveryAuthorityAction) throws {
        profile=AuthorityCodec.profile; operation=action.operation; self.phase=phase
        scope=try a.scope.digest; admission=try a.digest; ticket=AuthorityCodec.hash(a.ticket); context=AuthorityCodec.hash(a.context)
        request=a.requestDigest; record=a.record; store=a.store
        evaluation=try action.publication(a)
    }
}
