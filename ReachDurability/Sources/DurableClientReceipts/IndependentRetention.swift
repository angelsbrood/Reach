import Foundation
import RecoveryContract
import RecoveryAuthorityContract

public enum ClientAuthorityMode: String {
    case legacy, independent, recoveryAuthority = "recovery-authority", nativeRecovery = "native-recovery"
    var storageVersion: Int { switch self { case .legacy: 1; case .independent: 2; case .recoveryAuthority: 3; case .nativeRecovery: 4 } }
    var storageMagic: String { switch self { case .legacy: "S83GCM01"; case .independent: "S95GCM02"; case .recoveryAuthority: "S100CR03"; case .nativeRecovery: "S101CR04" } }
}

/// Encrypted with the generation's selected manifest. All values are original;
/// host timestamps remain host claims and never become a client clock reading.
public struct ClientLocalRetention: Codable, Equatable {
    public let acceptance: AuthorityAcceptance?
    public let version: Int
    public let anchor: UInt64, deadline: UInt64, cap: UInt64
    public let boot: String, policy: String, pair: String, context: String, ticket: String
    public let hostBoot: String, hostPolicy: String
    public init(anchor: UInt64, cap: UInt64, boot: String, policy: String, pair: String,
                context: ClientContext, ticket: Data) throws {
        let claims = try RecoveryTicketClaims.parse(ticket)
        guard claims.issued == context.issued, claims.expires == context.expires,
              claims.incarnation == context.host, claims.namespace == context.namespace,
              try crEncode(claims.caller) == crEncode(context.caller),
              claims.expires > claims.issued, claims.expires - claims.issued <= ClientLimits.session,
              anchor > 0, cap > 0, cap <= ClientLimits.session else { throw ClientError.unavailable }
        acceptance=nil; version = 1; self.anchor = anchor; self.cap = cap
        deadline = try crAdd(anchor, min(cap, claims.expires - claims.issued))
        self.boot = boot; self.policy = policy; self.pair = pair
        self.context = crHash(try crEncode(context)); self.ticket = crHash(ticket)
        hostBoot = claims.boot; hostPolicy = claims.policy
        try validate(); try check(context)
    }
    public init(acceptance: AuthorityAcceptance) throws {
        let a=try acceptance.admission(), scope=a.scope, original=try scope.provision.originals.records().client
        version=scope.provision.native ? 3 : 2; self.acceptance=acceptance; anchor=original.anchor; deadline=original.deadline; cap=original.cap
        boot=scope.client.boot; policy=scope.provision.clientPolicy; pair=try scope.provision.digest
        context=crHash(a.context); ticket=crHash(a.ticket); hostBoot=scope.host.boot; hostPolicy=scope.provision.hostPolicy
        try validate()
    }
    func validate() throws {
        if version == 2 || version == 3 {
            guard let acceptance else { throw ClientError.unavailable }
            let a=try acceptance.admission(), s=a.scope, original=try s.provision.originals.records().client
            guard version == (s.provision.native ? 3 : 2), anchor == original.anchor, deadline == original.deadline, cap == original.cap, boot == s.client.boot,
                  policy == s.provision.clientPolicy, pair == (try s.provision.digest), context == crHash(a.context),
                  ticket == crHash(a.ticket), hostBoot == s.host.boot, hostPolicy == s.provision.hostPolicy else { throw ClientError.unavailable }
            return
        }
        guard version == 1, acceptance == nil, anchor > 0, deadline > anchor, cap > 0, cap <= ClientLimits.session,
              deadline - anchor <= cap, crUUID(boot), crUUID(hostBoot),
              clientRolePolicy(policy), clientRolePolicy(hostPolicy), policy != hostPolicy,
              [pair, context, ticket].allSatisfy(crDigest) else { throw ClientError.unavailable }
    }
    func check(_ c: ClientContext) throws {
        try validate(); try c.validate()
        guard context == crHash(try crEncode(c)) else { throw ClientError.unavailable }
        if version == 2 || version == 3 {
            guard c.authority == (try acceptance!.admission().scope.digest) else { throw ClientError.unavailable }
        } else {
            guard c.authority == nil, deadline == (try crAdd(anchor,min(cap,c.expires-c.issued))) else { throw ClientError.unavailable }
        }
    }
    public var digest: String { get throws { try validate(); return crHash(try crEncode(self)) } }
}
func clientRolePolicy(_ value: String) -> Bool {
    let prefix = "role-monotonic-ns-v1:"
    return value.hasPrefix(prefix) && crUUID(String(value.dropFirst(prefix.count)))
}
extension ClientAuthority {
    public var localIssued: UInt64 { retention?.anchor ?? context.issued }
    public var localExpires: UInt64 { retention?.deadline ?? context.expires }
}
extension LiveClientRecord {
    var localIssued: UInt64 { retention?.anchor ?? issued }
    var localExpires: UInt64 { retention?.deadline ?? expires }
}
extension ClientEnvironment {
    func check(_ retention: ClientLocalRetention?) throws {
        if authorityMode == .legacy {
            guard retention == nil else { throw ClientError.unavailable }; return
        }
        guard let retention else { throw ClientError.unavailable }
        try retention.validate()
        if authorityMode == .recoveryAuthority || authorityMode == .nativeRecovery {
            guard let authority, let acceptance=retention.acceptance, retention.version == (authorityMode == .nativeRecovery ? 3 : 2), authority.provision.native == (authorityMode == .nativeRecovery) else { throw ClientError.unavailable }
            try authority.check(acceptance.admission().scope,role:"client")
        } else { guard authorityMode == .independent, retention.version == 1, retention.acceptance == nil else { throw ClientError.unavailable } }
        guard retention.boot == boot, retention.policy == policy, retention.pair == pairDigest,
              retention.cap == retentionCap else { throw ClientError.unavailable }
    }
}
extension DurableClientReceipts {
    public var authorityMode: ClientAuthorityMode { environment.authorityMode }
    /// Called directly before the original session-open send; never on recovery.
    public func originalAnchor() throws -> UInt64 {
        try fs.ensure(); try environment.validate(clock)
        let m = try readManifest(); return try observe(m)
    }
    public func originalAuthority(_ context: ClientContext, ticket: Data, anchor: UInt64?) throws -> ClientAuthority {
        guard authorityMode == .legacy || authorityMode == .independent, context.authority == nil else { throw ClientError.unavailable }
        if authorityMode == .legacy { return try ClientAuthority(context) }
        guard let anchor, let pair = environment.pairDigest else { throw ClientError.unavailable }
        let retention = try ClientLocalRetention(anchor: anchor, cap: environment.retentionCap,
            boot: environment.boot, policy: environment.policy, pair: pair, context: context, ticket: ticket)
        let authority = try ClientAuthority(context, retention: retention)
        try environment.check(retention)
        let now = try originalAnchor()
        guard now >= anchor, now < retention.deadline else { throw ClientError.expired }
        return authority
    }
}
