import Foundation

/// Constants every layer of the wire agrees on.
public enum Wire {
    /// Envelope/protocol version carried in `Hello`; one live version.
    public static let version: UInt8 = 0

    /// ALPN for authenticated app sessions.
    public static let alpn = "reach/0"

    /// ALPN for the ceremony's enrollment channel (server-auth-only TLS —
    /// client certificates do not exist yet at enrollment time).
    public static let enrollALPN = "reach-enroll/0"

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
