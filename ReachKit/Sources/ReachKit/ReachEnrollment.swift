import CryptoKit
import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

public enum ReachEnrollmentError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case badCAHash
    case refused(code: String, message: String)
    case sequence(String)

    public var description: String {
        switch self {
        case .badCAHash:
            "the cluster presented a certificate authority that does not match the pin discovery advertised — this is not the cluster this app enrolled against"
        case .refused(let code, let message):
            "the cluster declined the grant (\(code)): \(message)"
        case .sequence(let detail):
            // "arrived out of order" was true of the one ending this case was
            // written for and false of the two it now also carries: a stream
            // that closed or broke did not arrive at all. The detail says which
            // — this only has to stop contradicting it.
            "the enrollment exchange did not complete: \(detail)"
        }
    }

    public var errorDescription: String? { description }
}

/// The app half of the grant ceremony: an identity-less app dials the
/// cluster's enrollment door (found under the same Bonjour name as the
/// cluster itself), proves possession of a fresh key, and waits parked
/// while the request rides to the keeper's sheet. The CA pin comes from
/// the cluster's TXT record — the same unauthenticated discovery as the
/// address, provenance TOFU by design; the human ruling on the keeper is
/// the binding, and server-side App Attest is the funded upgrade. The app
/// key is software-backed in v0 (the named stub; the DEVICE key is the
/// Secure Enclave one).
public enum ReachEnrollment {
    /// True when material for `label` is already registered, or could be
    /// reloaded from the keychain items a prior enrollment stored.
    public static func ensureRegistered(label: String) async -> Bool {
        if await ReachIdentityRegistry.shared.material(for: label) != nil {
            return true
        }
        return await ReachIdentityRegistry.shared.registerFromKeychain(label: label) != nil
    }

    /// The name of the cluster this label is registered against, or nil when it
    /// is not registered.
    ///
    /// A consumer app knows the name on the path that enrolls — it passed it in —
    /// and had no way to recover it on a relaunch, because `ensureRegistered`
    /// answers only yes or no and nothing persists the name beside the identity.
    /// So the sample app rendered a placeholder, and its header read "Paired with
    /// enrolled". The pinned CA already carries the answer in its subject, which
    /// is authoritative rather than remembered, and survives an app reinstall the
    /// way every keychain item does.
    public static func registeredClusterName(label: String) async -> String? {
        var material = await ReachIdentityRegistry.shared.material(for: label)
        if material == nil {
            material = await ReachIdentityRegistry.shared.registerFromKeychain(label: label)
        }
        return material.flatMap { IdentityStore.commonName(of: $0.caCertificate) }
    }

    /// Runs the ceremony against a discovered cluster and registers the
    /// granted identity under `label`. Suspends for as long as the request
    /// stays parked — surface that state in UI ("asking your keeper…").
    ///
    /// The knock retries: on a one-phone cluster the asker is SUSPENDED
    /// while the human rules (opening the keeper backgrounds this app and
    /// its parked stream dies), so the ceremony must survive coming back —
    /// the same key re-knocks and collects the verdict the desk held.
    @discardableResult
    public static func enroll(
        clusterName: String,
        caHashBase64URL: String,
        identityLabel: String,
        bundleID: String? = nil,
        displayName: String? = nil,
        connectTimeout: Double = 20
    ) async throws -> ReachIdentityRegistry.Material {
        guard let pin = Wire.dataFromBase64URL(caHashBase64URL), pin.count == 32 else {
            throw ReachEnrollmentError.badCAHash
        }
        let bundle = bundleID ?? Bundle.main.bundleIdentifier ?? ProcessInfo.processInfo.processName
        let name = displayName
            ?? (Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? ProcessInfo.processInfo.processName

        let options = TLSBuilder.enrollClientOptions(alpn: Wire.enrollALPN, caHashPin: pin)
        let dialer = QUICDialer(
            endpoint: .service(name: clusterName, type: Wire.bonjourEnrollService, domain: "local.", interface: nil),
            parameters: .reachQUIC(options: options)
        )
        // One key for the whole ceremony — it IS the request's name at the
        // desk across every knock.
        // ⚠️ Deliberately NOT `SigningKey.mint()`, and the reason is worth one
        // line because the three-doors record tells readers to hunt bare mints.
        // This key is stored through `KeychainIdentity.store` on a device that
        // has the entitlement — it never becomes a PKCS#12 archive, so the
        // LibreSSL leading-zero defect cannot reach it. Every mint that CAN
        // reach `viaPKCS12` goes through the guard; this one cannot.
        let key = P256.Signing.PrivateKey()

        // Attempts, not wall time: while this app is suspended no attempts
        // burn, so a long visit to the keeper costs nothing.
        var attemptsLeft = 40
        while true {
            do {
                return try await attempt(
                    dialer: dialer, pin: pin, key: key,
                    bundle: bundle, name: name,
                    identityLabel: identityLabel, connectTimeout: connectTimeout
                )
            } catch let error as ReachEnrollmentError {
                if case .refused = error { throw error }   // a verdict, not a failure
                attemptsLeft -= 1
                guard attemptsLeft > 0 else { throw error }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                attemptsLeft -= 1
                guard attemptsLeft > 0 else { throw error }
            }
            try? await Task.sleep(for: .milliseconds(1500))
        }
    }

    private static func attempt(
        dialer: QUICDialer,
        pin: Data,
        key: P256.Signing.PrivateKey,
        bundle: String,
        name: String,
        identityLabel: String,
        connectTimeout: Double
    ) async throws -> ReachIdentityRegistry.Material {
        let stream = try await dialer.openStream(timeout: connectTimeout)
        defer { stream.cancel() }
        var frames = stream.frames.makeAsyncIterator()

        try await stream.send(AppEnrollBegin(bundleID: bundle, displayName: name))
        // Three endings, and this shape answered two. A reset THROWS out of
        // `next()`, and a throw cannot reach a `guard`'s `else`, so it went to
        // the retry loop's generic catch above and left as
        // `TransportError.connectionFailed` — which renders as "could not open
        // a connection to the cluster" about a door that had just opened. That
        // reaches a person: `ExampleModel` puts "no grant: \(error)" on screen.
        let challenged = await FrameEnding.next(from: &frames)
        guard case .frame(let challengeRaw) = challenged else {
            throw ReachEnrollmentError.sequence(challenged.detailing(
                "the cluster stopped answering before the challenge; nothing has been asked of the keeper yet"
            ))
        }
        if challengeRaw.type == .errorFrame {
            let error = try challengeRaw.decode(ErrorFrame.self)
            throw ReachEnrollmentError.refused(code: error.code, message: error.message)
        }
        let challenge = try challengeRaw.decode(EnrollChallenge.self)

        let pub = key.publicKey.x963Representation
        let popSig = try key.signature(for: challenge.nonce + pub).derRepresentation
        try await stream.send(AppEnrollCertRequest(appPubX963: pub, popSig: popSig))

        // The parked wait: nothing moves until a human rules the sheet — which
        // is exactly why this read has to answer all three endings. On a
        // one-phone cluster the operator must LEAVE this app to rule, iOS
        // suspends it there, and the stream dies: five of five ceremonies on
        // 2026-07-30, and the daemon says the same thing from its side in
        // `appHalfConverges`. So the ending that threw past this guard is not
        // the exceptional one — it is the only one — and the sentence that
        // could tell a person their request is still on the desk was
        // unreachable in precisely the case that produces it every time.
        // ⚠️ It says "usually" because the desk keeps nothing on disk: its
        // parked requests, its held verdicts and its request index are all
        // process memory. So the promise is true for the ending it was
        // written for — iOS suspending this app while the operator walks to
        // the keeper — and false in **two** cases, not one. A daemon that
        // restarts drops the ruling outright; and a daemon that never
        // restarts still retires it after `GrantDesk.holdWindow`, ten
        // minutes, which is the likelier of the two for an app the operator
        // came back to slowly. Both take a ruling the human already made and
        // ask them for it again. Knocking again is still the right move in
        // every case; only the certainty differs, and claiming the certainty
        // we do not have is what this sentence must not do. The window is
        // stated out loud because "usually" alone leaves a person guessing
        // whether to wait or knock, and ten minutes answers that.
        let ruled = await FrameEnding.next(from: &frames)
        guard case .frame(let grantRaw) = ruled else {
            throw ReachEnrollmentError.sequence(ruled.detailing(
                "the connection ended while the request was parked on the keeper's sheet — usually the ruling is not lost, the cluster holds it for ten minutes and this app's next knock collects it; if the cluster restarted or that window passed, the sheet comes round once more"
            ))
        }
        if grantRaw.type == .errorFrame {
            let error = try grantRaw.decode(ErrorFrame.self)
            throw ReachEnrollmentError.refused(code: error.code, message: error.message)
        }
        let grant = try grantRaw.decode(AppEnrollGrant.self)

        // Trust, then hold it: the granted CA must be the one the TXT
        // record pinned, and it becomes the app's trust root from here on.
        guard Data(SHA256.hash(data: grant.caCertDER)) == pin else {
            throw ReachEnrollmentError.sequence("granted CA does not match the pinned hash")
        }
        // A fresh grant REPLACES whatever an earlier provisioning left
        // under this label — keychain items outlive app installs, and a
        // stale identity beside a granted one makes lookup a coin toss.
        KeychainIdentity.remove(label: identityLabel)
        KeychainIdentity.remove(label: identityLabel + ".ca")
        // The roads go with them. A grant against a different cluster would
        // otherwise inherit the last one's addresses: trust makes dialing
        // them harmless — they cannot present this cluster's chain — but they
        // are noise in the race, and a record of where this device used to be
        // is not something a re-pair should keep.
        try? ClusterRoads.forget(for: identityLabel)
        let identity = try KeychainIdentity.store(
            privateKeyX963: key.x963Representation,
            certificateDER: grant.appCertDER,
            label: identityLabel
        )
        try KeychainIdentity.storeCertificate(der: grant.caCertDER, label: identityLabel + ".ca")
        try await stream.send(EnrollComplete(ok: true))
        // Same half-close as the device ceremony: `defer` cancels below, and a
        // reset where a FIN belongs can take this frame with it. Here it only
        // costs the desk a held verdict it would expire anyway — the app keeps
        // a valid certificate either way — but the fix is the same one line.
        stream.finishSending()
        // The half-close alone was not enough, and the FIN is why: `send`
        // resolves on `.contentProcessed` — handed to the transport, not
        // flushed — and `defer { stream.cancel() }` fires the instant this
        // function returns, microseconds behind it. Whether the daemon drained
        // the frame before the reset landed was a coin flip: **7 of 10 lost on
        // loopback, 2 of 4 on the rig**, where the cost is a daemon that logs
        // `enrollment stream failed: … Socket is not connected` for a ceremony
        // that fully succeeded and an app that is already streaming.
        //
        // So wait for the cluster's own goodbye. It sends nothing after the
        // grant and half-closes only once it has read this confirmation, so
        // **EOF here IS the acknowledgement** — which is exactly why this half
        // still needs no confirming frame of its own. The asymmetry
        // `docs/ceremony.md` describes is intact: the device half needs a
        // FRAME because its authorization is single-use and there is nothing
        // to re-knock with; this half needs only to hear the door close.
        //
        // A deadline task rather than a racing task group, for the reason the
        // Keeper's ceremony gives at the same point: `frames` is one
        // `AsyncThrowingStream` fed by a receive pump and its iterator is not
        // Sendable. Two seconds, not the ten a device gets — the app is
        // granted either way, so a cluster that never says goodbye costs
        // nothing but the daemon's log line, and a venue should not wait on
        // bookkeeping.
        let goodbye = Task {
            try? await Task.sleep(for: .seconds(2))
            stream.cancel()
        }
        defer { goodbye.cancel() }
        while (try? await frames.next()) != nil {}

        let material = ReachIdentityRegistry.Material(
            identity: identity,
            caCertificate: try IdentityStore.certificate(fromDER: grant.caCertDER)
        )
        await ReachIdentityRegistry.shared.register(label: identityLabel, material: material)
        return material
    }
}
