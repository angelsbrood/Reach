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
            "the enrollment exchange arrived out of order: \(detail)"
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
        guard let challengeRaw = try await frames.next() else {
            throw ReachEnrollmentError.sequence("closed at challenge")
        }
        if challengeRaw.type == .errorFrame {
            let error = try challengeRaw.decode(ErrorFrame.self)
            throw ReachEnrollmentError.refused(code: error.code, message: error.message)
        }
        let challenge = try challengeRaw.decode(EnrollChallenge.self)

        let pub = key.publicKey.x963Representation
        let popSig = try key.signature(for: challenge.nonce + pub).derRepresentation
        try await stream.send(AppEnrollCertRequest(appPubX963: pub, popSig: popSig))

        // The parked wait: nothing moves until a human rules the sheet.
        guard let grantRaw = try await frames.next() else {
            throw ReachEnrollmentError.sequence("closed while parked")
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

        let material = ReachIdentityRegistry.Material(
            identity: identity,
            caCertificate: try IdentityStore.certificate(fromDER: grant.caCertDER)
        )
        await ReachIdentityRegistry.shared.register(label: identityLabel, material: material)
        return material
    }
}
