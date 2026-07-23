import CryptoKit
import Foundation
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Security

public enum ReachEnrollmentError: Error, Sendable {
    case badCAHash
    case refused(code: String, message: String)
    case sequence(String)
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

        let material = ReachIdentityRegistry.Material(
            identity: identity,
            caCertificate: try IdentityStore.certificate(fromDER: grant.caCertDER)
        )
        await ReachIdentityRegistry.shared.register(label: identityLabel, material: material)
        return material
    }
}
