import Foundation
import CryptoKit

public struct SessionTicket {
    public let data: Data
    public init(data: Data) throws {
        guard data.count <= LifecycleLimits.ticket else { throw LifecycleError.ticket }
        // A Data slice may retain a nonzero startIndex. Normalize the bounded
        // public input before applying the ticket format's zero-based offsets.
        self.data = Data(data)
    }
}
struct TicketClaims: Codable {
    var version = 1
    var incarnation: String
    var boot: String
    var policy: String
    var namespace: String
    var caller: CallerIdentity
    var issued: UInt64
    var expires: UInt64
}
enum TicketCodec {
    static func issue(identity: LifecycleIdentity, keys: LifecycleKeys, auth: LifecycleAuthorization, now: UInt64, ttl: UInt64) throws -> SessionTicket {
        try auth.validate()
        guard ttl > 0, ttl <= LifecycleLimits.session else { throw LifecycleError.ticket }
        let claims = TicketClaims(incarnation: identity.incarnation, boot: identity.boot, policy: identity.clockPolicy,
            namespace: UUID().uuidString.lowercased(), caller: auth.caller, issued: now, expires: try lcAdd(now, ttl))
        let bytes = try lcEncode(claims), mac = HMAC<SHA256>.authenticationCode(for: bytes, using: keys.ticket)
        return try .init(data: lcUInt(UInt64(bytes.count)) + bytes + Data(mac))
    }
    static func verify(_ ticket: SessionTicket, identity: LifecycleIdentity, keys: LifecycleKeys, auth: LifecycleAuthorization, now: UInt64) throws -> TicketClaims {
        try auth.validate()
        let bytes = ticket.data
        guard (41...LifecycleLimits.ticket).contains(bytes.count) else { throw LifecycleError.ticket }
        let length = bytes.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard length == UInt64(bytes.count-40) else { throw LifecycleError.ticket }
        let body = Data(bytes[8..<bytes.count-32]), mac = Data(bytes.suffix(32))
        guard HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: body, using: keys.ticket) else { throw LifecycleError.ticket }
        let claims = try JSONDecoder().decode(TicketClaims.self, from: body)
        guard claims.version == 1, claims.incarnation == identity.incarnation, claims.boot == identity.boot,
              claims.policy == identity.clockPolicy, claims.caller == auth.caller, lcUUID(claims.namespace),
              claims.issued > 0, claims.issued <= now, claims.expires > claims.issued,
              claims.expires <= (try lcAdd(claims.issued, LifecycleLimits.session)), try lcEncode(claims) == body else { throw LifecycleError.ticket }
        guard now < claims.expires else { throw LifecycleError.expired }
        return claims
    }
}
