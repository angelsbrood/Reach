import Foundation

/// Constants every layer of the wire agrees on.
public enum Wire {
    /// Envelope/protocol version carried in `Hello`; one live version.
    public static let version: UInt8 = 0

    /// ALPN for authenticated app sessions.
    ///
    /// Derived from `version` rather than typed, because the two used to be
    /// independent literals and nothing forced them to agree: bumping
    /// `version` to 1 would have broken no build and no test while the wire
    /// still said `reach/0`, quietly letting two protocol generations share
    /// one ALPN. That is not the whole of version safety — nothing in the
    /// tree can read a *negotiated* ALPN, so a mismatch still refuses
    /// illegibly, and a v1 daemon that wants to serve both generations on
    /// one port dissolves the partition entirely. It is only the half that
    /// costs an interpolation.
    public static let alpn = "reach/\(version)"

    /// ALPN for the ceremony's enrollment channel (server-auth-only TLS —
    /// client certificates do not exist yet at enrollment time).
    ///
    /// ⚠️ This channel is stricter than it looks: `EnrollmentService` opens
    /// on `.enrollBegin`/`.appEnrollBegin`, so there is no `Hello` and no
    /// version field anywhere on it. The ALPN is its only partition, with
    /// no fallback at all if it is ever missed.
    public static let enrollALPN = "reach-enroll/\(version)"

    /// Bonjour service type reachd advertises on the local network.
    public static let bonjourService = "_reach._udp"

    /// Bonjour service type for the enrollment listener, advertised under
    /// the same cluster name — how an identity-less app finds the door.
    public static let bonjourEnrollService = "_reach-enroll._udp"

    /// TXT key on the session advertisement carrying the base64url SHA-256
    /// of the cluster CA's DER. An enrolling app pins this: the pin rides
    /// the same unauthenticated discovery as the address itself (provenance
    /// TOFU, upgraded by the keeper's ruling — the named stub).
    public static let txtCAHashKey = "ca"

    /// One codec for the TXT-carried hash, both ends.
    public static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func dataFromBase64URL(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        return Data(base64Encoded: base64)
    }
}
