import Foundation

/// Constants every layer of the wire agrees on.
public enum Wire {
    /// The first dialect. Missing version fields mean this generation so a
    /// peer built before negotiation existed remains legible.
    public static let baselineVersion: UInt8 = 0

    /// Preferred dialect carried first in `Hello`; one live dialect today.
    public static let version: UInt8 = 0

    /// Dialects this build can speak, in server preference order.
    public static let supportedVersions: [UInt8] = [version]

    /// The framing generation named by ALPN. This changes only when the
    /// length/type/body envelope itself becomes incompatible, not when a JSON
    /// dialect grows inside it.
    public static let envelopeVersion: UInt8 = 0

    /// ALPN for authenticated app sessions.
    ///
    /// Dialect compatibility belongs to `Hello`; ALPN partitions only peers
    /// that cannot parse one another's envelope at all.
    public static let alpn = "reach/\(envelopeVersion)"

    /// ALPN for the ceremony's enrollment channel (server-auth-only TLS —
    /// client certificates do not exist yet at enrollment time).
    ///
    /// Enrollment negotiates additively in its begin/challenge frames; this
    /// ALPN therefore names only that channel's envelope generation too.
    public static let enrollALPN = "reach-enroll/\(envelopeVersion)"

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

    /// Advisory Bonjour value carrying every supported dialect. Discovery is
    /// not available on stored roads, so this can inform UI but never decides
    /// whether a peer may connect.
    public static let txtVersionsKey = "v"

    /// Comma-separated in preference order. A one-version daemon continues to
    /// advertise exactly `v=0`, preserving the existing TXT shape.
    public static var txtVersionsValue: String {
        txtVersionsValue(for: supportedVersions)
    }

    /// Kept separately testable so a future multi-dialect build cannot
    /// accidentally reverse the advertised server preference.
    public static func txtVersionsValue(for versions: [UInt8]) -> String {
        versions.map(String.init).joined(separator: ",")
    }

    /// Selects the server's most-preferred dialect that the peer offered.
    public static func negotiate(
        offered: [UInt8],
        supported: [UInt8] = supportedVersions
    ) -> UInt8? {
        let offered = Set(offered)
        return supported.first(where: offered.contains)
    }

    /// A missing offer/selection is a peer from before negotiation and means
    /// v0. An explicitly empty offer still means "no versions" and refuses.
    public static func offeredOrLegacy(_ versions: [UInt8]?) -> [UInt8] {
        versions ?? [baselineVersion]
    }

    public static func selectedOrLegacy(_ version: UInt8?) -> UInt8 {
        version ?? baselineVersion
    }

    /// Public refusal copy shared by the daemon, ReachKit and Keeper.
    public static func mismatchMessage(app: [UInt8], cluster: [UInt8]) -> String {
        let appRange = (app.min(), app.max())
        let clusterRange = (cluster.min(), cluster.max())
        let detail = "app offers \(versionList(app)); cluster supports \(versionList(cluster))"
        if let appMin = appRange.0, let clusterMax = clusterRange.1, appMin > clusterMax {
            return "your cluster speaks an older generation of this protocol than this app (\(detail))"
        }
        if let clusterMin = clusterRange.0, let appMax = appRange.1, clusterMin > appMax {
            return "this app speaks an older generation of this protocol than your cluster (\(detail))"
        }
        return "this app and your cluster do not share a protocol generation (\(detail))"
    }

    private static func versionList(_ versions: [UInt8]) -> String {
        versions.isEmpty ? "none" : versions.map(String.init).joined(separator: ",")
    }

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
