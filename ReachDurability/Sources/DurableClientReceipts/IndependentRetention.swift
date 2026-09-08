import Foundation
import RecoveryContract

public enum ClientAuthorityMode: String { case legacy, independent }

/// Encrypted with the generation's selected manifest. All values are original;
/// host timestamps remain host claims and never become a client clock reading.
public struct ClientLocalRetention: Codable, Equatable {
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
        version = 1; self.anchor = anchor; self.cap = cap
        deadline = try crAdd(anchor, min(cap, claims.expires - claims.issued))
        self.boot = boot; self.policy = policy; self.pair = pair
        self.context = crHash(try crEncode(context)); self.ticket = crHash(ticket)
        hostBoot = claims.boot; hostPolicy = claims.policy
        try validate(); try check(context)
    }
    func validate() throws {
        guard version == 1, anchor > 0, deadline > anchor, cap > 0, cap <= ClientLimits.session,
              deadline - anchor <= cap, crUUID(boot), crUUID(hostBoot),
              clientRolePolicy(policy), clientRolePolicy(hostPolicy), policy != hostPolicy,
              [pair, context, ticket].allSatisfy(crDigest) else { throw ClientError.unavailable }
    }
    func check(_ c: ClientContext) throws {
        try validate(); try c.validate()
        guard context == crHash(try crEncode(c)), deadline == (try crAdd(anchor, min(cap, c.expires - c.issued))) else { throw ClientError.unavailable }
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
