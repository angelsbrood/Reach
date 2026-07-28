import CryptoKit
import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

/// The keeper's half of the ceremony: parse the QR, mint the two keys,
/// prove possession once, and come back holding a certificate and a mesh.
enum EnrollmentClient {
    struct QRPayload: Codable {
        var v: Int
        var cluster: UUID
        var name: String
        var addrs: [String]
        var port: UInt16
        /// Session listener; absent on QRs minted before the console
        /// existed, so the well-known default fills in.
        var sport: UInt16?
        var caHash: Data
        var token: String
    }

    struct Outcome: Sendable {
        var clusterName: String
        var assignedIP: String
        var wgQuickConfig: String
    }

    enum EnrollError: LocalizedError {
        case badPayload
        case refused(String)
        case sequence(String)

        var errorDescription: String? {
            switch self {
            case .badPayload: "That QR is not a Reach pairing code."
            case .refused(let message): "The cluster refused: \(message)"
            case .sequence(let message): "Enrollment broke: \(message)"
            }
        }
    }

    static func enroll(qrText: String, deviceName: String) async throws -> Outcome {
        guard let payload = try? JSONDecoder().decode(QRPayload.self, from: Data(qrText.utf8)),
              payload.v == 1
        else {
            throw EnrollError.badPayload
        }

        // The two keys of the one gesture.
        let deviceKey = try DeviceKey.createOrLoad()
        let devicePub = try DeviceKey.publicKeyX963(deviceKey)
        let wgKey = Curve25519.KeyAgreement.PrivateKey()

        let options = TLSBuilder.enrollClientOptions(alpn: Wire.enrollALPN, caHashPin: payload.caHash)
        // Only the DIAL may be retried on another address. The QR carries
        // every address the host answers on, and trying them in turn is the
        // right way to find the one this phone can reach — but the moment
        // EnrollBegin leaves, the host has spent the one-time token, and
        // whatever comes back is a verdict about this pairing rather than a
        // fact about this address. Retrying past that point re-presents a
        // dead token to the next address, and its "this QR is spent" answer
        // then overwrites the reason the host actually gave: the operator
        // reads a complaint about the QR and never learns about the config,
        // the proof of possession, or the CA hash that did not match.
        var lastError: Error = EnrollError.sequence("no address reachable")
        for addr in payload.addrs {
            let stream: ReachTransport.QUICStream
            do {
                stream = try await QUICDialer(
                    endpoint: .hostPort(host: NWEndpoint.Host(addr), port: NWEndpoint.Port(rawValue: payload.port)!),
                    parameters: .reachQUIC(options: options)
                ).openStream(timeout: 20)
            } catch {
                lastError = error
                continue
            }
            return try await run(
                stream: stream,
                payload: payload,
                deviceName: deviceName,
                deviceKey: deviceKey,
                devicePub: devicePub,
                wgKey: wgKey
            )
        }
        throw lastError
    }

    private static func run(
        stream: ReachTransport.QUICStream,
        payload: QRPayload,
        deviceName: String,
        deviceKey: SecKey,
        devicePub: Data,
        wgKey: Curve25519.KeyAgreement.PrivateKey
    ) async throws -> Outcome {
        defer { stream.cancel() }
        var frames = stream.frames.makeAsyncIterator()

        try await stream.send(EnrollBegin(token: payload.token, deviceName: deviceName))
        guard let challengeRaw = try await frames.next() else { throw EnrollError.sequence("closed at challenge") }
        if challengeRaw.type == .errorFrame {
            let error = try challengeRaw.decode(ErrorFrame.self)
            throw EnrollError.refused("\(error.code): \(error.message)")
        }
        let challenge = try challengeRaw.decode(EnrollChallenge.self)

        let wgPub = wgKey.publicKey.rawRepresentation
        let popSig = try DeviceKey.sign(challenge.nonce + devicePub + wgPub, with: deviceKey)
        try await stream.send(EnrollCertRequest(devicePubDER: devicePub, wgPubKey: wgPub, popSig: popSig))

        guard let grantRaw = try await frames.next() else { throw EnrollError.sequence("closed at grant") }
        if grantRaw.type == .errorFrame {
            let error = try grantRaw.decode(ErrorFrame.self)
            throw EnrollError.refused("\(error.code): \(error.message)")
        }
        let grant = try grantRaw.decode(EnrollGrant.self)

        // Trust, then hold it: the CA the chain pinned to becomes ours.
        guard Data(SHA256.hash(data: grant.caCertDER)) == payload.caHash else {
            throw EnrollError.sequence("granted CA does not match the pinned hash")
        }
        _ = try DeviceKey.installCertificate(grant.deviceCertDER)
        try await stream.send(EnrollComplete(ok: true))

        // The cluster's calling card, held for the grant console: where the
        // session door is, and the CA everything verifies against.
        ClusterRecord(
            name: payload.name,
            addrs: payload.addrs,
            sessionPort: payload.sport ?? 47337,
            caCertDER: grant.caCertDER
        ).save()

        let config = """
        [Interface]
        PrivateKey = \(wgKey.rawRepresentation.base64EncodedString())
        Address = \(grant.wg.assignedIP)

        [Peer]
        PublicKey = \(grant.wg.serverPublicKey.base64EncodedString())
        Endpoint = \(grant.wg.endpoint)
        AllowedIPs = \(grant.wg.allowedIPs.joined(separator: ", "))
        PersistentKeepalive = \(grant.wg.keepaliveSeconds)

        """
        return Outcome(
            clusterName: payload.name,
            assignedIP: grant.wg.assignedIP,
            wgQuickConfig: config
        )
    }
}
