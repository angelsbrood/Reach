import Foundation
import Network
import ReachWire
import Security

/// Builders for the QUIC security options both ends use. Verify blocks pin
/// the cluster CA and evaluate under the role-correct SSL policy — the
/// default policy checks the serverAuth EKU, which wrongly rejects client
/// certificates on the daemon side (spike S1a).
public enum TLSBuilder {
    private static let tlsQueue = DispatchQueue(label: "reach.transport.tls")

    /// Server-side options: presents `identity`, and when `trustRoots` is
    /// non-empty demands and verifies client certificates against them.
    /// The enrollment listener passes an empty `trustRoots` (server-auth
    /// only — client certificates do not exist yet at enrollment).
    public static func serverOptions(
        alpn: String,
        identity: SecIdentity,
        clientTrustRoots: [SecCertificate]
    ) -> NWProtocolQUIC.Options {
        let options = NWProtocolQUIC.Options(alpn: [alpn])
        let sec = options.securityProtocolOptions
        sec_protocol_options_set_local_identity(sec, sec_identity_create(identity)!)
        if !clientTrustRoots.isEmpty {
            sec_protocol_options_set_peer_authentication_required(sec, true)
            installVerifyBlock(sec, roots: clientTrustRoots, verifyingClient: true)
        }
        tune(options)
        return options
    }

    /// Client-side options: verifies the server against `serverTrustRoots`
    /// and supplies `identity` when challenged (nil during enrollment).
    public static func clientOptions(
        alpn: String,
        identity: SecIdentity?,
        serverTrustRoots: [SecCertificate]
    ) -> NWProtocolQUIC.Options {
        let options = NWProtocolQUIC.Options(alpn: [alpn])
        let sec = options.securityProtocolOptions
        if let identity {
            sec_protocol_options_set_challenge_block(sec, { _, complete in
                complete(sec_identity_create(identity))
            }, tlsQueue)
        }
        installVerifyBlock(sec, roots: serverTrustRoots, verifyingClient: false)
        tune(options)
        return options
    }

    private static func installVerifyBlock(
        _ sec: sec_protocol_options_t,
        roots: [SecCertificate],
        verifyingClient: Bool
    ) {
        sec_protocol_options_set_verify_block(sec, { _, trustRef, complete in
            let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(!verifyingClient, nil))
            SecTrustSetAnchorCertificates(trust, roots as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var error: CFError?
            let trusted = SecTrustEvaluateWithError(trust, &error)
            complete(trusted)
        }, tlsQueue)
    }

    private static func tune(_ options: NWProtocolQUIC.Options) {
        options.idleTimeout = 30_000
        options.direction = .bidirectional
    }
}

extension NWParameters {
    /// Session parameters over the given QUIC options. `handover` opts the
    /// client into multipath handover mode (per the S1b verdict).
    public static func reachQUIC(options: NWProtocolQUIC.Options, handover: Bool = false) -> NWParameters {
        let parameters = NWParameters(quic: options)
        if handover {
            parameters.multipathServiceType = .handover
        }
        return parameters
    }
}
