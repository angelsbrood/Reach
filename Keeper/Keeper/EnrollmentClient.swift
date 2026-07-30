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
        /// The host wrote a new peer block and has not loaded it yet, so the
        /// mesh will not carry anything until the operator applies it. False
        /// when the conf already named this device's key — which is what a
        /// re-pair reaches now that the mesh key is kept.
        var applyPending: Bool
    }

    /// The ceremony this build speaks. The QR is minted by the same daemon that
    /// serves the ceremony, so the QR's version IS the daemon's version — which
    /// makes one integer a tripwire in both directions. It matters because the
    /// ceremony now ends with a frame the daemon sends: an older daemon closes
    /// its send side without one, so this build would read a clean end-of-stream
    /// and report a pairing that fully succeeded as a failure, every time.
    /// `nonisolated` because `EnrollError.errorDescription` is a nonisolated
    /// protocol requirement and names this number in the sentence it shows.
    nonisolated static let ceremonyVersion = 2

    enum EnrollError: LocalizedError {
        case badPayload
        case wrongVersion(Int)
        case refused(String)
        case sequence(String)

        var errorDescription: String? {
            switch self {
            case .badPayload: "That QR is not a Reach pairing code."
            // A mismatch used to read as "not a Reach pairing code", which sends
            // the operator hunting the phone at the moment the host is the thing
            // that is behind.
            case .wrongVersion(let found):
                "That QR is from a different version of Reach (it says \(found), this build speaks \(EnrollmentClient.ceremonyVersion)). Update the host and this app together, then run `reachd pair` again."
            case .refused(let message): "The cluster refused: \(message)"
            case .sequence(let message): "Enrollment broke: \(message)"
            }
        }
    }

    static func enroll(qrText: String, deviceName: String) async throws -> Outcome {
        guard let payload = try? JSONDecoder().decode(QRPayload.self, from: Data(qrText.utf8)) else {
            throw EnrollError.badPayload
        }
        guard payload.v == ceremonyVersion else {
            throw EnrollError.wrongVersion(payload.v)
        }

        // The two keys of the one gesture. Both are minted once and kept: the
        // identity key because it IS the device, and the mesh key because a
        // fresh one every scan is what made a re-pair destructive — it forced
        // the host to evict the peer block this phone was still using, and to
        // ask for a sudo before the mesh worked again.
        let deviceKey = try DeviceKey.createOrLoad()
        let devicePub = try DeviceKey.publicKeyX963(deviceKey)
        let wgKey = try WGKey.createOrLoad()

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
        // Half-close, because `send` resolves on `.contentProcessed` — handed
        // to the transport, not flushed to the peer. The `defer` above cancels
        // the connection the moment this function returns, and an abortive
        // close arriving where a FIN belongs takes the last frame with it: the
        // daemon's pending read fails with ENOTCONN and the peer it was about
        // to install never gets installed. The daemon has always finished its
        // own send side; neither client ever did.
        stream.finishSending()

        // Nothing below this line is reversible — the cluster record, the conf
        // written over the one the tunnel is using, and an install that stops a
        // running tunnel first — so none of it runs until the host says a road
        // exists. Until this frame existed, "paired" meant "I sent a frame."
        //
        // The bound is a deadline task rather than a racing task group: `frames`
        // is one `AsyncThrowingStream` fed by a receive pump, its iterator is not
        // Sendable, and reading it from a child task would need a second
        // iterator over shared storage. Cancelling the stream is safe here
        // because a timeout IS abandonment — the `defer` above does the same
        // thing on every other exit path — and it lands as a clean nil below.
        //
        // Ten seconds, not the twenty a dial gets: this is one round trip after
        // a local file write, and at a venue a fast failure beats a patient one.
        let deadline = Task {
            try? await Task.sleep(for: .seconds(10))
            stream.cancel()
        }
        defer { deadline.cancel() }
        guard let confirmRaw = try await frames.next() else {
            throw EnrollError.sequence(
                "the cluster never confirmed a road for this device. It may have admitted the peer without saying so, so pair again to settle it — this device keeps its identity and address."
            )
        }
        if confirmRaw.type == .errorFrame {
            let error = try confirmRaw.decode(ErrorFrame.self)
            throw EnrollError.refused("\(error.code): \(error.message)")
        }
        let confirmed = try confirmRaw.decode(EnrollConfirmed.self)

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
            wgQuickConfig: config,
            applyPending: confirmed.applyPending
        )
    }
}
