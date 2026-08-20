import Crypto
import Foundation
import ReachIdentity
import ReachTransport
import ReachWire
import Security
import SwiftASN1
import X509

/// The ceremony's daemon side: one bidirectional stream on the enrollment
/// listener carries EnrollBegin → EnrollChallenge → EnrollCertRequest →
/// EnrollGrant → EnrollComplete → EnrollConfirmed. The last frame comes back
/// the other way, and it is what makes the phone's idea of success the same
/// event as this side's: without it the phone's condition was "I sent it" and
/// the daemon's was "I received it," and everything between them was a pairing
/// that reported success and had no road. Mutual authentication is asymmetric by
/// design — the phone authenticates the daemon via the CA-hash pin from
/// the QR; the daemon authenticates the phone via the one-time token. One
/// proof-of-possession signature binds the device key and the WireGuard
/// key in a single gesture. Stateless by construction — every mutable
/// organ it touches (registry, desk, host) is its own actor.
public struct EnrollmentService: Sendable {
    public struct Provisioned: Sendable {
        public let deviceID: UUID
        public let name: String
        public let assignedIP: String
        public let admin: Bool
    }

    private let ca: ClusterCA
    private let tokens: TokenStore
    private let devices: DeviceRegistry
    private let wgHost: WireGuardHost
    private let desk: GrantDesk

    public init(ca: ClusterCA, tokens: TokenStore, devices: DeviceRegistry, wgHost: WireGuardHost, desk: GrantDesk = GrantDesk()) {
        self.ca = ca
        self.tokens = tokens
        self.devices = devices
        self.wgHost = wgHost
        self.desk = desk
    }

    /// The confirming frame, or why one never came — because those are three
    /// endings and the code that read them only ever handled two.
    ///
    /// Both ceremonies close by reading a frame the daemon has already earned:
    /// the grant is sent, and only the acknowledgement is outstanding. A stream
    /// that was RESET and one that closed cleanly are the same event there —
    /// the confirmation did not arrive — but they do not reach the *code* the
    /// same way. **A reset THROWS out of `next()`, and a throw cannot reach a
    /// `guard`'s `else`.** It went to `serve`'s catch instead and printed
    /// `enrollment stream failed: … POSIXErrorCode 57: Socket is not
    /// connected` — a socket rather than a situation — which left both
    /// sentences written for exactly this ending unreachable by construction:
    /// that the QR is spent, and that the verdict stays parked.
    ///
    /// Measured 2026-07-30 in the July cut's own daemon log: two of four app
    /// grants lost the confirmation this way, and one of the two is the take
    /// that became the cut.
    ///
    /// The type moved to `ReachTransport.FrameEnding` when the same defect was
    /// found in the keeper (7e): the shape belongs beside the stream, and the
    /// keeper cannot import this module. The name stays because it is what the
    /// ceremony calls it here — and because a `Confirmation` that had to be
    /// spelled `FrameEnding` at every site would make two readings of one
    /// event look like two events.
    typealias Confirmation = FrameEnding

    /// Serves one enrollment stream to completion. The first frame decides
    /// which ceremony this is: a device (token-authorized) or an app
    /// (grant-authorized, parked for the keeper's ruling).
    public func serve(stream: ReachTransport.QUICStream) async {
        var iterator = stream.frames.makeAsyncIterator()
        do {
            guard let first = try await iterator.next() else { return }
            switch first.type {
            case .enrollBegin:
                let begin = try first.decode(EnrollBegin.self)
                let offered = Wire.offeredOrLegacy(begin.versions)
                guard let version = Wire.negotiate(offered: offered) else {
                    try await refuseVersion(offered: offered, stream: stream)
                    return
                }
                try await serveDevice(
                    begin: begin,
                    stream: stream,
                    iterator: &iterator,
                    version: version
                )
            case .appEnrollBegin:
                let begin = try first.decode(AppEnrollBegin.self)
                let offered = Wire.offeredOrLegacy(begin.versions)
                guard let version = Wire.negotiate(offered: offered) else {
                    try await refuseVersion(offered: offered, stream: stream)
                    return
                }
                try await serveApp(
                    begin: begin,
                    stream: stream,
                    iterator: &iterator,
                    version: version
                )
            default:
                try await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected EnrollBegin or AppEnrollBegin"))
                stream.cancel()
            }
        } catch {
            Log.error("enrollment stream failed: \(error)")
            stream.cancel()
        }
    }

    /// Refuses before a token is consumed or an app request is parked.
    private func refuseVersion(
        offered: [UInt8],
        stream: ReachTransport.QUICStream
    ) async throws {
        try await stream.send(ErrorFrame(
            code: "wire-version",
            message: Wire.mismatchMessage(app: offered, cluster: Wire.supportedVersions)
        ))
        stream.finishSending()
    }

    private func serveDevice(
        begin: EnrollBegin,
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        version: UInt8
    ) async throws {
        // Consumed on presentation, deliberately: holding the token open
        // across the round trip below would let a second device present it
        // while the first is still mid-ceremony. What makes the consumption
        // itself single-use is `unlink`, in TokenStore — this line only has
        // to be early, not clever.
        //
        // The cost of that is real and belongs here rather than in a puzzled
        // operator: every refusal past this line spends the QR, so a fixed
        // fault is retried against a token that no longer exists. Say which
        // it is, and say it on both ends — the phone sees the message, and
        // the Mac's terminal, which said nothing at all before this.
        guard tokens.consume(begin.token) else {
            Log.error("enrollment refused — this QR is spent or expired; run `reachd pair` for a fresh one")
            try await stream.send(ErrorFrame(
                code: "enroll-token",
                message: "this QR is spent or expired — run `reachd pair` on the host for a fresh one"
            ), for: version)
            stream.cancel()
            return
        }

        // Where this device will be told to find the mesh, settled before
        // anything is minted. A grant nobody can act on is worse than a
        // refusal, and refusing here leaves no half-enrolled device, no
        // issued certificate and no peer intent behind — though note the token
        // above is already spent, so this refusal costs a fresh `reachd pair`.
        let endpoint: String
        do {
            endpoint = try wgHost.currentEndpoint()
        } catch {
            Log.error("enrollment refused — no mesh endpoint: \(error)")
            try await stream.send(ErrorFrame(code: "enroll-endpoint", message: "\(error)"), for: version)
            stream.cancel()
            return
        }

        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try await stream.send(EnrollChallenge(nonce: nonce, version: version), for: version)

        // The same three endings as the confirming read below, and this one
        // answered two — worse, it said nothing at all about either. A stream
        // that broke here threw past the guard entirely into `serve`'s catch,
        // which prints `enrollment stream failed: <socket>`: a fault with no
        // device in it and no mention that the token above is already spent.
        // A stream that closed, or a frame of the wrong type, reached the
        // guard and still left the Mac's terminal silent.
        //
        // The absence of `device enrolled:` is a signal only to someone who
        // already knows to look for it. Say it instead — and say it here,
        // where nothing has been minted yet, so the QR is the entire cost.
        let requested = await FrameEnding.next(from: &iterator)
        guard case .frame(let requestRaw) = requested, requestRaw.type == .enrollCertRequest else {
            Log.error("enrollment abandoned by \(begin.deviceName) before the certificate request: \(requested.reason(waitingFor: "EnrollCertRequest")); nothing was issued and the QR is spent — run `reachd pair` for a fresh one")
            // Worth answering only when something is still listening, exactly
            // as below: a stream that closed or broke has no reader left.
            if case .frame = requested {
                try? await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected EnrollCertRequest"), for: version)
            }
            stream.cancel()
            return
        }
        try requestRaw.requireSupported(by: version)
        let request = try requestRaw.decode(EnrollCertRequest.self)

        // Proof of possession over nonce ‖ devicePub ‖ wgPub with the
        // device key — "one QR, two keys," literally.
        let signed = nonce + request.devicePubDER + request.wgPubKey
        guard
            let publicKey = try? P256.Signing.PublicKey(x963Representation: request.devicePubDER),
            let signature = try? P256.Signing.ECDSASignature(derRepresentation: request.popSig),
            publicKey.isValidSignature(signature, for: signed),
            request.wgPubKey.count == 32
        else {
            try await stream.send(ErrorFrame(code: "enroll-pop", message: "proof of possession failed"), for: version)
            stream.cancel()
            return
        }

        let record = try await devices.reserve(name: begin.deviceName, devicePubX963: request.devicePubDER)
        let certificate = try ca.issueClientLeaf(
            publicKeyX963: request.devicePubDER,
            commonName: begin.deviceName,
            uri: "reach://device/\(record.id.uuidString.lowercased())"
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)

        try await stream.send(EnrollGrant(
            deviceCertDER: Data(serializer.serializedBytes),
            caCertDER: try ca.certificateDER(),
            wg: WGProvision(
                assignedIP: "\(record.assignedIP)/24",
                serverPublicKey: wgHost.serverPublicKey,
                endpoint: endpoint,
                allowedIPs: ["\(wgHost.serverMeshIP)/32"],
                keepaliveSeconds: 25
            )
        ), for: version)

        // Four answers, not one silent return. A stream that closed, a stream
        // that broke, a frame that was the wrong thing, and a device that said
        // `ok: false` are different faults — and this used to report none of
        // them, which is why a ceremony that tore mid-grant left the log with
        // nothing in it. The token is spent in all four cases, so every message
        // says so: the absence of `device enrolled:` was the only signal, and
        // it is one you have to already know to look for.
        //
        // The broken-stream ending is the one this half could not reach until
        // `Confirmation` existed, and it is the likeliest of the four here: a
        // phone that backgrounds or dies after the grant resets the connection
        // rather than closing it.
        let spent = "\(record.assignedIP) has no peer and the QR is spent — run `reachd pair` for a fresh one"
        let confirmation = await FrameEnding.next(from: &iterator)
        guard case .frame(let completeRaw) = confirmation, completeRaw.type == .enrollComplete else {
            Log.error("enrollment abandoned by \(begin.deviceName) after the grant: \(confirmation.reason(waitingFor: "EnrollComplete")); \(spent)")
            // Worth answering only when something is still listening — a
            // stream that closed or broke has no reader on the other end.
            if case .frame = confirmation {
                try? await stream.send(ErrorFrame(code: "enroll-sequence", message: "the ceremony ends with EnrollComplete"), for: version)
            }
            stream.cancel()
            return
        }
        try completeRaw.requireSupported(by: version)
        // `ok` was decoded and discarded here, so a device reporting failure
        // read as success. It is the device's own verdict on the grant it just
        // installed; honour it.
        guard try completeRaw.decode(EnrollComplete.self).ok else {
            Log.error("enrollment declined by \(begin.deviceName) after the grant: it could not hold the certificate; \(spent)")
            stream.cancel()
            return
        }
        // The peer waits until the device has confirmed it holds the grant.
        // Admitting it earlier meant a re-pair that failed after the grant
        // had already evicted the block the phone was using — two peers must
        // never claim one /32, so installing the new key deletes the old one,
        // and a device that never completed then has no working mesh and no
        // way back to the one it had. Nothing in the grant depends on this
        // having run: it carries the host's public key and the assigned
        // address, both known well before here.
        let applyPending: Bool
        do {
            applyPending = try await wgHost.addPeer(publicKey: request.wgPubKey, allowedIP: record.assignedIP)
        } catch {
            // Reachable: login-owned intent is the persistent half of the mesh
            // contract. It is also the phone's business, because the phone is
            // about to decide whether it is paired — so it hears the reason
            // rather than a closed stream. Nothing was admitted, so there is
            // nothing to
            // undo: the reservation keeps its address and its certificate and
            // has no road, which is exactly what doctor now reports.
            Log.error("enrollment refused — no road for \(begin.deviceName): \(error)")
            try? await stream.send(ErrorFrame(code: "enroll-peer", message: "\(error)"), for: version)
            stream.cancel()
            return
        }
        // The key and the active flag land here, on the same side of the
        // confirmation as the peer intent that carries them.
        await devices.admit(record.id, wgPub: request.wgPubKey)
        // The endpoint is logged because it is the one thing in the grant
        // that cannot be re-derived later: the phone carries it into its
        // tunnel config, and this line is the record of what it was told.
        Log.info("device enrolled: \(begin.deviceName) → \(record.assignedIP)\(record.admin ? " (admin)" : ""), mesh endpoint \(endpoint)")
        // Best-effort, and after the success line on purpose. A keeper built
        // before this frame existed has already closed its side, so the send
        // fails — and a pairing that fully succeeded must not come out of the
        // log as nothing but an error. The peer is installed and the record is
        // admitted; there is nothing here to roll back.
        do {
            try await stream.send(EnrollConfirmed(applyPending: applyPending), for: version)
        } catch {
            Log.error("device enrolled, but \(begin.deviceName) was never told: \(error). It will report the pairing as failed; re-pair to settle it.")
        }
        stream.finishSending()
    }

    /// The app half: prove the key, then wait — the stream stays parked
    /// while the request rides the desk to the keeper. TOFU on both sides
    /// here (the app pinned the CA hash from discovery; the daemon takes
    /// the bundle identity at its word) is the named App-Attest stub: the
    /// binding in v0 is the human ruling the sheet.
    private func serveApp(
        begin: AppEnrollBegin,
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator,
        version: UInt8
    ) async throws {
        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try await stream.send(EnrollChallenge(nonce: nonce, version: version), for: version)

        // The last instance of the shape in this file, closed by the grep the
        // other three earned. Losing this frame costs nothing durable — no
        // token spent, nothing minted, no verdict parked, and the app's next
        // knock starts a fresh ceremony — but the ending that produces it, an
        // asker iOS suspended between the challenge and its request, THREW
        // past this guard. So did the `send` below, which was ungated and
        // wrote to a stream that may already be gone: both routes ended at
        // `serve`'s catch as `enrollment stream failed: <socket>`, with no
        // bundle in it.
        //
        // `appHalfConverges` is deliberately not consulted. Its sentence is
        // about a verdict the desk is holding, and there is no verdict yet;
        // borrowing it would make its own doc false at a second site. The
        // level stays `error` because that is the level this path already
        // fires at — if a take shows this is the ordinary ending, it moves
        // then, on evidence, the way the app half's did.
        let requested = await FrameEnding.next(from: &iterator)
        guard case .frame(let requestRaw) = requested, requestRaw.type == .appEnrollCertRequest else {
            Log.error("app enrollment abandoned by \(begin.bundleID) before its certificate request: \(requested.reason(waitingFor: "AppEnrollCertRequest")); nothing was minted and its next knock starts over")
            // Worth answering only when something is still listening, exactly
            // as the device half does at both of its reads.
            if case .frame = requested {
                try? await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected AppEnrollCertRequest"), for: version)
            }
            stream.cancel()
            return
        }
        try requestRaw.requireSupported(by: version)
        let request = try requestRaw.decode(AppEnrollCertRequest.self)

        let signed = nonce + request.appPubX963
        guard
            let publicKey = try? P256.Signing.PublicKey(x963Representation: request.appPubX963),
            let signature = try? P256.Signing.ECDSASignature(derRepresentation: request.popSig),
            publicKey.isValidSignature(signature, for: signed)
        else {
            try await stream.send(ErrorFrame(code: "enroll-pop", message: "proof of possession failed"), for: version)
            stream.cancel()
            return
        }

        let fingerprint = SHA256.hash(data: request.appPubX963)
            .map { String(format: "%02x", $0) }.joined()
        let event = GrantEvent(
            requestID: UUID(),
            deviceID: await provenance(of: stream),
            bundleID: begin.bundleID,
            displayName: begin.displayName,
            appKeyFingerprint: fingerprint
        )
        Log.info("grant request parked: \(begin.bundleID) (\(fingerprint.prefix(16))…) from \(event.deviceID)")

        switch await desk.park(event) {
        case .superseded:
            // A newer knock (the app came back on a fresh stream) carries
            // the ceremony now; this stream just goes away.
            stream.cancel()
        case .denied:
            try await stream.send(ErrorFrame(code: "grant-denied", message: "the keeper refused"), for: version)
            await desk.collected(fingerprint)
            stream.cancel()
        case .timedOut:
            try await stream.send(ErrorFrame(code: "grant-timeout", message: "no ruling within the window"), for: version)
            stream.cancel()
        case .allowed(let ruler):
            let certificate = try ca.issueClientLeaf(
                publicKeyX963: request.appPubX963,
                commonName: begin.displayName,
                uri: "reach://app/\(ruler.uuidString.lowercased())/\(begin.bundleID)"
            )
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            try await stream.send(AppEnrollGrant(
                appCertDER: Data(serializer.serializedBytes),
                caCertDER: try ca.certificateDER()
            ), for: version)
            // The same silence the device half had, and the same fix. This one
            // costs far less — the app holds a valid certificate the moment the
            // grant lands, and the verdict stays parked for its hold window, so
            // the app's next knock collects it. That is why this half needs no
            // confirming frame: it converges on a re-knock, and the device half
            // could not, because its authorization is single-use and burned.
            let confirmation = await FrameEnding.next(from: &iterator)
            guard case .frame(let completeRaw) = confirmation, completeRaw.type == .enrollComplete else {
                // Two endings, because they are two different events. The app
                // going away before it confirms is how a one-phone grant
                // ordinarily ends — the ruling lands on a stream the operator
                // suspended by walking to the keeper — and it heals itself on
                // the next knock, so it is news, not a fault. Reading it at
                // `error` for a whole recording session is what made the level
                // wrong; saying less than this is what would make it useless.
                if confirmation.appHalfConverges {
                    Log.info("grant stands for \(begin.bundleID) — the app left before confirming; the verdict stays parked and its next knock collects it (\(confirmation.reason(waitingFor: "EnrollComplete")))")
                } else {
                    Log.error("app enrollment unconfirmed for \(begin.bundleID): \(confirmation.reason(waitingFor: "EnrollComplete")). The grant stands and the verdict stays parked — the app collects it on its next knock.")
                }
                stream.cancel()
                return
            }
            try completeRaw.requireSupported(by: version)
            guard try completeRaw.decode(EnrollComplete.self).ok else {
                // The app says it did not retain the granted identity. Keep
                // the ruling exactly as an interrupted delivery does, so the
                // same key can collect it on its next knock; do not print the
                // success line for a grant its recipient rejected.
                Log.error("app enrollment declined by \(begin.bundleID) after the grant: it could not hold the certificate; the ruling stays parked for its next knock")
                stream.cancel()
                return
            }
            // Only a confirmed delivery clears the held verdict — anything
            // short of EnrollComplete leaves it for the app's next knock.
            await desk.collected(fingerprint)
            Log.info("app enrolled: \(begin.bundleID), granted under device \(ruler.uuidString.lowercased())")
            // The app is waiting on exactly this: it drains to EOF after its
            // confirmation, so the half-close is what tells it the frame was
            // read. Suppressing this line puts every pairing on the client's
            // two-second deadline instead — measured, not assumed.
            stream.finishSending()
        }
    }

    /// What the daemon actually knows about where a request came from: the
    /// remote address, upgraded to the enrolled device's name when it is a
    /// mesh address the registry can bind. Shown on the sheet as observed
    /// provenance, not proof.
    private func provenance(of stream: ReachTransport.QUICStream) async -> String {
        guard let remote = stream.remoteEndpointDescription() else { return "unknown" }
        for device in await devices.all
        where remote == device.assignedIP || remote.hasPrefix("\(device.assignedIP):") {
            return "\(device.name) · \(remote)"
        }
        return remote
    }
}

/// What the ceremony makes of an ending. The classification is the transport's
/// (`FrameEnding`); the words are this file's, because the daemon is the half
/// that has to say what was lost and what it costs.
extension FrameEnding {
    /// Why the frame never came, phrased to sit inside a caller's sentence.
    ///
    /// The caller names the frame it was waiting for, because the reads do not
    /// end alike: losing `EnrollComplete` costs an acknowledgement the grant has
    /// already outlived, and losing `EnrollCertRequest` costs a QR that is
    /// already spent. Neither can borrow the other's noun and stay true.
    func reason(waitingFor frame: String) -> String {
        switch self {
        case .frame(let raw): "it sent \(raw.type) where \(frame) belongs"
        case .closed: "the stream closed before \(frame)"
        case .broke(let error): "the stream broke before \(frame): \(error)"
        }
    }

    /// Whether the **app** half recovers from this ending unaided. Two of
    /// the three do: the desk holds the ruled verdict and the app's next
    /// knock collects it.
    ///
    /// That is not the exceptional case — on a one-phone rig it is the
    /// only case. The operator has to leave the asking app to rule the
    /// sheet, iOS suspends it there, and so the app is reliably gone by
    /// the time the ruling lands and the certificate is sent. Measured at
    /// five of five ceremonies on 2026-07-30, which is what retired the
    /// reading that this was an anomaly worth an `error`.
    ///
    /// The third ending does not converge: an app that sends the wrong
    /// frame will send it again. That one stays an error.
    ///
    /// ⚠️ The **device** half converges from none of these — its
    /// authorization is a one-time token, already spent — so it does not
    /// consult this and logs all three at `error`. The asymmetry is the
    /// ceremony's own, and `docs/ceremony.md` states it.
    var appHalfConverges: Bool {
        switch self {
        case .frame: false
        case .closed, .broke: true
        }
    }
}

/// One-time enrollment tokens, file-backed so `reachd pair` (a separate
/// process) can mint what `reachd serve` validates. Hashes only; 10-minute
/// TTL; consumed on first presentation.
///
/// **One token is one file, and an exclusive create is what makes it
/// single-use.**
///
/// This used to be one JSON array rewritten in place, guarded by the
/// argument that the check and the removal were a single synchronous step.
/// That argument is only half of what the invariant needs: a synchronous
/// step cannot be interrupted by a *suspension*, but it can be executed by
/// two threads at the same instant, and it was —
/// `Daemon.startEnrollment` spawns a fresh `Task` per inbound stream and
/// `EnrollmentService` is a non-isolated struct, so two ceremonies ran in
/// parallel against one file. Both read the entry, both found it, both
/// wrote a copy without it: a lost update, which an atomic write prevents
/// from tearing the file but cannot prevent. Measured before the change at
/// **24 double-spends in 24 races**, and the token is the only thing
/// authenticating a device ceremony — proof-of-possession is over a key
/// the caller minted seconds earlier, so it says nothing about *which*
/// device is asking.
///
/// **Do not "simplify" this to `unlink` deciding the winner.** That was the
/// first fix written here and it is wrong on this platform. Raced eight
/// ways against one path, `unlink` returns 0 — with `errno` untouched — to
/// *every* caller, not one; measured in Swift and again in plain C, inside
/// the sandbox and outside it, 23 races of 24. The file does get removed;
/// what is not true is that the return value identifies who removed it, and
/// a single-use check needs the second property, not the first.
/// `open(O_CREAT|O_EXCL)` does have it — exactly one caller gets a
/// descriptor and the other seven get `EEXIST`, 24 races of 24 — so the
/// claim marker, not the removal, is the arbiter. Creation is also
/// cross-process, which this needs: `pair` mints in one process while
/// `serve` consumes in another, and the old array could resurrect a spent
/// token when those two interleaved.
public struct TokenStore: Sendable {
    private let directory: URL

    public init(directory: URL = DaemonInfo.stateDirectory) {
        self.directory = directory.appendingPathComponent("enroll-tokens", isDirectory: true)
    }

    /// A token's file is named by its own SHA-256, so the name is the
    /// lookup and no index is needed. base64url, because a filename cannot
    /// carry `/`.
    private func url(for token: String) -> URL {
        let hash = Data(SHA256.hash(data: Data(token.utf8)))
        let name = hash.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return directory.appendingPathComponent(name)
    }

    public func mint(ttl: TimeInterval = 600) -> String {
        var bytes = Data(count: 32)
        bytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let token = bytes.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        sweepExpired()

        let deadline = Date().addingTimeInterval(ttl)
        let file = url(for: token)
        if let data = try? JSONEncoder().encode(deadline) {
            try? data.write(to: file, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        return token
    }

    public func consume(_ token: String) -> Bool {
        let file = url(for: token)
        // No token file is the ordinary "spent or never existed" answer, and
        // it is checked first so a stranger's guess leaves nothing behind.
        guard let data = try? Data(contentsOf: file),
              let deadline = try? JSONDecoder().decode(Date.self, from: data)
        else { return false }

        // The arbiter. Exactly one caller creates this, in this process or
        // any other; everyone else gets EEXIST and is not the device this QR
        // admits. It carries the same deadline as the token so the sweep can
        // read both kinds without knowing which is which.
        let claim = URL(fileURLWithPath: file.path + claimSuffix)
        let fd = open(claim.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard fd >= 0 else { return false }
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        close(fd)

        // Now that the winner is decided, retiring the token is bookkeeping.
        _ = unlink(file.path)
        return deadline > Date()
    }

    private var claimSuffix: String { ".claim" }

    /// Expired tokens and their claim markers are removed when the next
    /// token is minted. Nothing else sweeps, and nothing needs to: both
    /// kinds are inert once past their deadline — an absent token refuses
    /// and a surviving claim refuses — so this is housekeeping rather than
    /// enforcement. The claim has to outlive the token it retired, or the
    /// same QR could be presented twice inside its own ten minutes.
    private func sweepExpired() {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return }
        let now = Date()
        for name in names {
            let file = directory.appendingPathComponent(name)
            guard let data = try? Data(contentsOf: file),
                  let deadline = try? JSONDecoder().decode(Date.self, from: data),
                  deadline <= now
            else { continue }
            _ = unlink(file.path)
        }
        // The array this replaced. Left behind it would read like live
        // state to the next person who opens the state directory.
        _ = unlink(directory.deletingLastPathComponent().appendingPathComponent("enroll-tokens.json").path)
    }
}

/// Enrolled devices and mesh address allocation, persisted under the state
/// directory. The first device enrolled holds the admin grant.
public actor DeviceRegistry {
    public struct Device: Codable, Sendable {
        public var id: UUID
        public var name: String
        public var devicePubX963: Data
        public var wgPub: Data
        public var assignedIP: String
        public var admin: Bool
        public var active: Bool
        public var enrolledAt: Date
    }

    private let url: URL
    private var devices: [Device]

    public init(directory: URL = DaemonInfo.stateDirectory) {
        url = directory.appendingPathComponent("devices.json")
        if let data = try? Data(contentsOf: url),
           let loaded = try? JSONDecoder().decode([Device].self, from: data) {
            devices = loaded
        } else {
            devices = []
        }
    }

    /// Reserves the device's identity — id, address, admin grant, name — and
    /// deliberately does NOT record its mesh key. The grant carries the address,
    /// so this has to run before the certificate is issued; the key is admitted
    /// later, beside the peer intent, by `admit`.
    ///
    /// The split is the point. This used to write the key here too, which put
    /// the registry and mesh intent on opposite sides of the confirmation: the
    /// key landed before the grant was even sent, the peer intent only after
    /// `EnrollComplete`. An abandoned re-pair therefore left the two disagreeing
    /// **by design**, and any check comparing them would accuse a rig whose mesh
    /// was carrying traffic. One decision writes both now.
    public func reserve(name: String, devicePubX963: Data) throws -> Device {
        // The Secure Enclave key IS the device: a re-pair arrives with the same
        // device key and keeps its identity — id, address, and the admin grant.
        if let existing = devices.firstIndex(where: { $0.devicePubX963 == devicePubX963 }) {
            devices[existing].name = name
            persist()
            return devices[existing]
        }
        // Monotonic, not `2 + count`. A count re-issues an address as soon as
        // anything removes a record, and the /32 it hands out could be one a
        // stale peer intent still holds under a different key — breaking the
        // invariant `addPeer` exists to protect, at the one place `addPeer`
        // cannot see it. Nothing removes records yet; this is why it stays safe
        // when something does.
        let taken = devices.compactMap { Int($0.assignedIP.split(separator: ".").last ?? "") }
        let device = Device(
            id: UUID(),
            name: name,
            devicePubX963: devicePubX963,
            wgPub: Data(),
            assignedIP: "10.86.0.\((taken.max() ?? 1) + 1)",
            admin: devices.isEmpty,
            active: false,
            enrolledAt: Date()
        )
        devices.append(device)
        persist()
        return device
    }

    /// Admits the device: its mesh key and its active flag, in one write, once
    /// the peer intent naming that key is on disk. Before this the record is a
    /// reservation — it holds an address and a certificate, and it has no road.
    public func admit(_ id: UUID, wgPub: Data) {
        if let index = devices.firstIndex(where: { $0.id == id }) {
            devices[index].wgPub = wgPub
            devices[index].active = true
            persist()
        }
    }

    public func device(id: UUID) -> Device? {
        devices.first { $0.id == id }
    }

    public var all: [Device] { devices }

    private func persist() {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(devices) {
            try? data.write(to: url, options: [.atomic])
        }
    }
}

/// The login-owned half of the mesh contract. It owns the host key and a
/// deterministic, non-secret intent. The root-owned mesh helper is the only
/// process that owns the live interface, and sees a private key only through a
/// validated, consumed mode-0600 specification produced by `reachd mesh apply`.
public actor WireGuardHost {
    public nonisolated let serverPublicKey: Data
    public nonisolated let serverMeshIP = "10.86.0.1"

    /// Where a device is told to find the mesh — read at the moment of
    /// granting, never remembered. The operator can re-pin `meshEndpoint`
    /// between two enrollments (which is exactly what moving to a venue
    /// is), and a value cached at process start would hand the next phone
    /// the last venue's address: invisible on the LAN, and fatal the one
    /// time it matters. It is read once per pairing, so there is nothing
    /// to cache but the mistake.
    private nonisolated let endpointResolver: @Sendable () throws -> String

    private let stateDirectory: URL

    /// The one visible administrator action after enrollment changes intent.
    /// This command compiles data, names the exact privileged operation, and
    /// invokes only the installed root-owned helper through `/usr/bin/sudo`.
    public static let applyCommand = "reachd mesh apply"

    public nonisolated func currentEndpoint() throws -> String {
        try endpointResolver()
    }

    public init(
        keysDirectory: URL = DaemonInfo.stateDirectory.appendingPathComponent("wg", isDirectory: true),
        confPath: String = HostCheck.defaultWireGuardConf,
        endpoint: @escaping @Sendable () throws -> String
    ) throws {
        stateDirectory = keysDirectory.deletingLastPathComponent()
        let fm = FileManager.default
        let pubURL = keysDirectory.appendingPathComponent("server.pub")
        let keyURL = keysDirectory.appendingPathComponent("server.key")
        let publicExists = fm.fileExists(atPath: pubURL.path)
        let privateExists = fm.fileExists(atPath: keyURL.path)
        guard publicExists == privateExists else {
            throw CAError.stateMissing("wg/server.key and wg/server.pub must exist together")
        }
        if !publicExists {
            // Fresh host: mint only Reach's identity. The legacy config is no
            // longer live authority and is never created or rewritten here.
            try fm.createDirectory(at: keysDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: keysDirectory.path)
            let key = Curve25519.KeyAgreement.PrivateKey()
            try key.rawRepresentation.base64EncodedString().write(to: keyURL, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
            try key.publicKey.rawRepresentation.base64EncodedString().write(to: pubURL, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pubURL.path)
        }
        let privateText = try MeshIntentStore.readCanonicalKey(keyURL, role: "host private key", exactMode: 0o600)
        let publicText = try MeshIntentStore.readCanonicalKey(pubURL, role: "host public key", exactMode: nil)
        let privateData = try MeshIntent.decodeKey(privateText, role: "host private key")
        let derived = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateData).publicKey.rawRepresentation
        let pub = try MeshIntent.decodeKey(publicText, role: "host public key")
        guard derived == pub else {
            throw CAError.stateMissing("wg/server.key and wg/server.pub do not agree")
        }
        serverPublicKey = pub
        endpointResolver = endpoint
        _ = try MeshIntentStore.loadOrImport(
            stateDirectory: stateDirectory,
            legacyConf: URL(fileURLWithPath: confPath),
            privateKey: privateText,
            publicKey: publicText
        )
    }

    /// A fixed endpoint — for tests and for any caller that genuinely has
    /// one value for the host's whole life.
    public init(
        keysDirectory: URL = DaemonInfo.stateDirectory.appendingPathComponent("wg", isDirectory: true),
        confPath: String = HostCheck.defaultWireGuardConf,
        endpoint: String
    ) throws {
        try self.init(keysDirectory: keysDirectory, confPath: confPath, endpoint: { endpoint })
    }

    /// Installs the peer in user-owned intent: idempotent when this key already
    /// holds this address, and otherwise replaces any entry claiming either.
    /// Returns whether intent changed (the operator then applies it).
    ///
    /// Since the phone keeps its mesh key, the idempotent branch is the one a
    /// re-pair takes: nothing is written, nothing is evicted, and no sudo is
    /// needed before the mesh carries traffic again. The eviction branch is
    /// still here and still enforces that two peers never claim one /32 — it is
    /// now reached by a first pairing, or by a device whose address changed.
    @discardableResult
    public func addPeer(publicKey: Data, allowedIP: String) throws -> Bool {
        guard publicKey.count == 32 else {
            throw MeshIntentError.refused("peer public key is not 32 bytes")
        }
        let base64 = publicKey.base64EncodedString()
        let route = "\(allowedIP)/32"
        guard MeshIntent.peerOrdinal(route) != nil else {
            throw MeshIntentError.refused("peer route is outside 10.86.0.2...254/32")
        }
        let update = try MeshIntentStore.update(in: stateDirectory) { intent in
            guard intent.publicKey == serverPublicKey.base64EncodedString() else {
                throw MeshIntentError.refused("mesh intent host key no longer matches this host")
            }
            if intent.peers.contains(where: { $0.publicKey == base64 && $0.allowedIP == route }) {
                return false
            }
            intent.peers.removeAll {
                $0.allowedIP == route || $0.publicKey == base64
            }
            intent.peers.append(.init(publicKey: base64, allowedIP: route))
            intent.peers.sort {
                MeshIntent.peerOrdinal($0.allowedIP)! < MeshIntent.peerOrdinal($1.allowedIP)!
            }
            if let relay = intent.relay {
                intent.relay = try relay.rederived(for: intent.peers)
            }
            guard intent.generation < UInt64.max else {
                throw MeshIntentError.refused("mesh intent generation is exhausted")
            }
            intent.generation += 1
            return true
        }
        guard update.changed else { return false }
        Log.info("mesh intent updated — apply with: \(Self.applyCommand)")
        return true
    }
}
