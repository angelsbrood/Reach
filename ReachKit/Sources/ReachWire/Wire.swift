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
}
