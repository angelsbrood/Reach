import Crypto
import Foundation
import FoundationModels
import Network
import ReachIdentity
import ReachTransport
import ReachWire
import Testing
import X509
@testable import ReachDaemon

/// The grant sheet over loopback: an admin device (enrolled through the
/// real ceremony) subscribes on its authenticated control stream; an
/// identity-less app parks an enrollment; the ruling releases it as an
/// app-scoped certificate that then opens a session and streams.
@Suite(.serialized) struct GrantTests {
    private struct Fixture {
        let ca: ClusterCA
        let caHash: Data
        let tokens: TokenStore
        let devices: DeviceRegistry
        let desk: GrantDesk
        let daemon: Daemon
        let caCert: SecCertificate
        let sessionPort: UInt16
        let enrollDialer: QUICDialer
        /// Identities this fixture mints *after* it exists — the device's and
        /// the app's, both issued mid-test by the ceremony halves below. A
        /// captured cleanup closure cannot grow to hold them, which is why
        /// this was reaching for the global bin; an instance answers for its
        /// own fixture and nobody else's.
        let bin: IdentityBin
        let cleanup: @Sendable () -> Void
    }

    private func makeFixture(sessionPort: UInt16, enrollPort: UInt16, window: Duration = .seconds(120)) async throws -> Fixture {
        let stateDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-grant-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)

        let ca = try ClusterCA.create(commonName: "Grant CA")
        let caDER = try ca.certificateDER()
        let caHash = Data(SHA256.hash(data: caDER))
        let server = try ca.issueServer(commonName: "localhost", dnsNames: ["localhost"], ipAddresses: [[127, 0, 0, 1]])
        let serverIdentity = try IdentityMaterializer.materialize(server, label: "reach-grant-server-\(UUID())")
        // Materialized identities land in the login keychain via
        // SecPKCS12Import; the fixture owns removing what it made.
        let serverBox = IdentityBox(serverIdentity)
        let bin = IdentityBin()
        let caCert = try IdentityStore.certificate(fromDER: caDER)

        let tokens = TokenStore(directory: stateDir)
        let devices = DeviceRegistry(directory: stateDir)
        let desk = GrantDesk(window: window)
        let wgHost = try WireGuardHost(
            keysDirectory: stateDir.appendingPathComponent("wg", isDirectory: true),
            confPath: stateDir.appendingPathComponent("reach0.conf").path,
            endpoint: "192.0.2.1:51820"
        )
        let service = EnrollmentService(ca: ca, tokens: tokens, devices: devices, wgHost: wgHost, desk: desk)

        var config = DaemonConfig()
        config.clusterName = "grant-test"
        config.port = sessionPort
        config.enrollPort = enrollPort
        let daemon = Daemon(
            config: config,
            filling: ScriptedFilling(),
            identity: Daemon.ListenerIdentity(identity: serverIdentity, caCertificate: caCert),
            grants: Daemon.GrantWiring(desk: desk, devices: devices)
        )
        try await daemon.start(advertise: false)
        try await daemon.startEnrollment(service: service, advertise: false)

        let enrollDialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: enrollPort)!),
            parameters: .reachQUIC(options: TLSBuilder.enrollClientOptions(alpn: Wire.enrollALPN, caHashPin: caHash))
        )
        return Fixture(
            ca: ca, caHash: caHash, tokens: tokens, devices: devices, desk: desk,
            daemon: daemon, caCert: caCert, sessionPort: sessionPort, enrollDialer: enrollDialer,
            bin: bin,
            cleanup: {
                Task { await daemon.stop() }
                KeychainIdentity.remove(identity: serverBox.identity)
                bin.drain()
                try? FileManager.default.removeItem(at: stateDir)
            }
        )
    }

    // MARK: Halves

    /// The device ceremony, returning the granted material AND the key the
    /// "phone" minted — the tests dial the control stream with it.
    private func enrollDevice(_ fixture: Fixture, name: String) async throws -> (grant: EnrollGrant, identity: SecIdentity) {
        let deviceKey = P256.Signing.PrivateKey()
        let wgKey = Curve25519.KeyAgreement.PrivateKey()
        let token = fixture.tokens.mint()

        let stream = try await fixture.enrollDialer.openStream(timeout: 45)
        defer { stream.cancel() }
        var frames = stream.frames.makeAsyncIterator()
        try await stream.send(EnrollBegin(token: token, deviceName: name))
        let challenge = try await frames.next()!.decode(EnrollChallenge.self)
        let devicePub = deviceKey.publicKey.x963Representation
        let wgPub = wgKey.publicKey.rawRepresentation
        let popSig = try deviceKey.signature(for: challenge.nonce + devicePub + wgPub).derRepresentation
        try await stream.send(EnrollCertRequest(devicePubDER: devicePub, wgPubKey: wgPub, popSig: popSig))
        let grant = try await frames.next()!.decode(EnrollGrant.self)
        try await stream.send(EnrollComplete(ok: true))
        // Half-close handshake: wait for the daemon's FIN so activation
        // has landed before the test proceeds.
        _ = try? await frames.next()
        let identity = try IdentityMaterializer.materialize(
            certificateDER: grant.deviceCertDER,
            privateKey: deviceKey,
            label: "reach-grant-device-\(UUID())"
        )
        fixture.bin.add(identity)
        return (grant, identity)
    }

    private enum AppOutcome {
        case granted(AppEnrollGrant, appKey: P256.Signing.PrivateKey)
        case refused(ErrorFrame)
    }

    /// How the app leaves, which is the whole of item 7d.
    private enum Closing {
        /// What `ReachKit.ReachEnrollment` does: confirm, half-close, and wait
        /// for the cluster's own goodbye before hanging up.
        case confirm
        /// What it did before 7d: confirm, half-close, and hang up on the FIN's
        /// heels. `send` resolves on `.contentProcessed` — handed to the
        /// transport, not flushed — so the reset can overtake the frame.
        case confirmAndHangUp
        /// The app is gone after the grant (suspended, killed, uninstalled) and
        /// never confirms at all. Deterministic, unlike the race above.
        case vanish
    }

    /// The app ceremony: begins, proves the key, and stays parked until
    /// ruled or timed out. Pass `appKey` to re-knock as the same app.
    private func appEnroll(
        _ fixture: Fixture,
        bundleID: String,
        name: String,
        appKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey(),
        closing: Closing = .confirm
    ) async throws -> AppOutcome {
        let stream = try await fixture.enrollDialer.openStream(timeout: 45)
        defer { stream.cancel() }
        var frames = stream.frames.makeAsyncIterator()
        try await stream.send(AppEnrollBegin(bundleID: bundleID, displayName: name))
        guard let challengeRaw = try await frames.next() else { throw TransportError.streamClosed }
        if challengeRaw.type == .errorFrame {
            return .refused(try challengeRaw.decode(ErrorFrame.self))
        }
        let challenge = try challengeRaw.decode(EnrollChallenge.self)
        let pub = appKey.publicKey.x963Representation
        let popSig = try appKey.signature(for: challenge.nonce + pub).derRepresentation
        try await stream.send(AppEnrollCertRequest(appPubX963: pub, popSig: popSig))
        guard let grantRaw = try await frames.next() else { throw TransportError.streamClosed }
        if grantRaw.type == .errorFrame {
            return .refused(try grantRaw.decode(ErrorFrame.self))
        }
        let grant = try grantRaw.decode(AppEnrollGrant.self)
        if closing == .vanish { return .granted(grant, appKey: appKey) }

        try await stream.send(EnrollComplete(ok: true))
        stream.finishSending()
        if closing == .confirm {
            // Wait for the cluster's own FIN — the daemon sends nothing after
            // the grant and half-closes only once it has read the confirmation,
            // so EOF here IS the acknowledgement. Mirrors `ReachEnrollment`;
            // the bound is there so a cluster that never says goodbye cannot
            // hang the ceremony.
            let deadline = Task {
                try? await Task.sleep(for: .seconds(2))
                stream.cancel()
            }
            defer { deadline.cancel() }
            while (try? await frames.next()) != nil {}
        }
        return .granted(grant, appKey: appKey)
    }

    private func openControl(_ fixture: Fixture, identity: SecIdentity) async throws -> (ReachTransport.QUICStream, AsyncThrowingStream<RawFrame, Error>.AsyncIterator) {
        let options = TLSBuilder.clientOptions(alpn: Wire.alpn, identity: identity, serverTrustRoots: [fixture.caCert])
        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: fixture.sessionPort)!),
            parameters: .reachQUIC(options: options)
        )
        let control = try await dialer.openStream(timeout: 45)
        var frames = control.frames.makeAsyncIterator()
        try await control.send(Hello(client: "grant-test"))
        _ = try await frames.next()!.decode(HelloAck.self)
        return (control, frames)
    }

    // MARK: Tests

    @Test func sheetRulesAppOntoTheCluster() async throws {
        let fixture = try await makeFixture(sessionPort: 47440, enrollPort: 47441)
        defer { fixture.cleanup() }

        // The keeper: enrolled first (admin), subscribed on its
        // authenticated control stream.
        let keeper = try await enrollDevice(fixture, name: "keeper-phone")
        let deviceID = try #require(await fixture.devices.all.first?.id)
        var (control, controlFrames) = try await openControl(fixture, identity: keeper.identity)
        defer { control.cancel() }
        try await control.send(GrantSubscribe())

        // The app knocks and parks.
        let appTask = Task {
            try await appEnroll(fixture, bundleID: "systems.reach.example-test", name: "Example")
        }

        // The sheet's content arrives on the keeper's stream.
        let eventRaw = try #require(try await controlFrames.next())
        let event = try eventRaw.decode(GrantEvent.self)
        #expect(event.bundleID == "systems.reach.example-test")
        #expect(event.appKeyFingerprint.count == 64)

        // Ruled: allow.
        try await control.send(GrantRule(requestID: event.requestID, allow: true))

        guard case .granted(let grant, let appKey) = try await appTask.value else {
            Issue.record("app was refused after an allow ruling")
            return
        }

        // The granted chain verifies against the pinned root, and the SAN
        // scopes the app under the RULING device.
        #expect(Data(SHA256.hash(data: grant.caCertDER)) == fixture.caHash)
        let leaf = try Certificate(derEncoded: Array(grant.appCertDER))
        let root = try Certificate(derEncoded: Array(grant.caCertDER))
        var verifier = try Verifier(rootCertificates: CertificateStore([root])) { RFC5280Policy() }
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore())
        guard case .validCertificate = result else {
            Issue.record("granted chain did not validate: \(result)")
            return
        }
        let uri = try #require(try leaf.extensions.subjectAlternativeNames?.compactMap { name -> String? in
            if case .uniformResourceIdentifier(let value) = name { return value }
            return nil
        }.first)
        #expect(uri == "reach://app/\(deviceID.uuidString.lowercased())/systems.reach.example-test")

        // And the cert is live: the app opens a session and streams.
        let appIdentity = try IdentityMaterializer.materialize(
            certificateDER: grant.appCertDER,
            privateKey: appKey,
            label: "reach-grant-app-\(UUID())"
        )
        fixture.bin.add(appIdentity)
        let options = TLSBuilder.clientOptions(alpn: Wire.alpn, identity: appIdentity, serverTrustRoots: [fixture.caCert])
        let dialer = QUICDialer(
            endpoint: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: fixture.sessionPort)!),
            parameters: .reachQUIC(options: options)
        )
        let appControl = try await dialer.openStream(timeout: 45)
        defer { appControl.cancel() }
        var appFrames = appControl.frames.makeAsyncIterator()
        try await appControl.send(Hello(client: "granted-app"))
        _ = try await appFrames.next()!.decode(HelloAck.self)
        try await appControl.send(SessionOpen(modelID: "scripted"))
        let opened = try await appFrames.next()!.decode(SessionOpened.self)

        let gen = try await dialer.openStream(timeout: 45)
        defer { gen.cancel() }
        try await gen.send(GenerateBegin(
            sessionID: opened.sessionID,
            genID: UUID(),
            request: WireGenerationRequest(id: UUID(), transcript: Transcript())
        ))
        var text = ""
        for try await raw in gen.frames {
            guard raw.type == .ev else { continue }
            let ev = try raw.decode(Ev.self)
            if case .responseAppend(_, let t, _, _) = ev.event { text += t }
            if case .finished = ev.event { break }
        }
        #expect(text == ScriptedFilling().words.joined())
    }

    /// `app enrolled:` is the daemon's whole account of a grant landing, and
    /// it was a coin flip: **2 of 4 on the rig on 2026-07-30**, and the two
    /// that lost included the take that became the July cut. What the daemon
    /// printed instead was `enrollment stream failed: … POSIXErrorCode 57`,
    /// which is what a genuinely broken ceremony prints.
    ///
    /// This asserts the DESK rather than the log, because they are the same
    /// fact: `desk.collected` runs only on the path that logs the line, so a
    /// verdict still held is a confirmation the daemon never read. And the
    /// assertion is well-ordered rather than timing-dependent — the daemon
    /// half-closes *after* collecting, so an app that waits for that close
    /// cannot observe the desk mid-decision.
    @Test func everyGrantTheAppConfirmsIsCollectedFromTheDesk() async throws {
        let fixture = try await makeFixture(sessionPort: 47448, enrollPort: 47449)
        defer { fixture.cleanup() }

        let keeper = try await enrollDevice(fixture, name: "keeper-phone")
        var (control, controlFrames) = try await openControl(fixture, identity: keeper.identity)
        defer { control.cancel() }
        try await control.send(GrantSubscribe())

        let rounds = 10
        var slowestGoodbye = Duration.zero
        for round in 0..<rounds {
            let bundleID = "systems.reach.round-\(round)"
            let knock = Task {
                try await appEnroll(fixture, bundleID: bundleID, name: "Round \(round)")
            }
            let event = try (try #require(try await controlFrames.next())).decode(GrantEvent.self)
            #expect(event.bundleID == bundleID)

            let ruled = ContinuousClock.now
            try await control.send(GrantRule(requestID: event.requestID, allow: true))
            guard case .granted = try await knock.value else {
                Issue.record("round \(round) was refused after an allow ruling")
                return
            }
            slowestGoodbye = max(slowestGoodbye, ContinuousClock.now - ruled)
        }

        // Nothing sweeps inside a run (the hold window is ten minutes), so
        // what is left on the desk is exactly the count that went unread.
        let stranded = await fixture.desk.footprint.ruled
        #expect(
            stranded == 0,
            "\(stranded) of \(rounds) confirmed grants left the verdict parked — the daemon never read EnrollComplete"
        )

        // The app waits for the cluster's goodbye, and that wait is only a fix
        // if the goodbye arrives. A transport that never surfaces the peer's
        // FIN would turn it into a silent two-second stall on every pairing —
        // a dead beat on camera, and invisible in a suite that only checks
        // correctness. Loopback, after a round trip the link has already
        // carried: half a second is generous.
        #expect(
            slowestGoodbye < .milliseconds(500),
            "the slowest ruling-to-granted was \(slowestGoodbye) — the cluster's FIN is not arriving"
        )
    }

    /// The other ending, and the one the daemon promises in writing: *"the
    /// grant stands and the verdict stays parked — the app collects it on its
    /// next knock."* Nothing asserted that until now, which is how the
    /// sentence came to be unreachable without anyone noticing.
    ///
    /// Distinct from `verdictSurvivesTheAskersStreamDeath`, which kills the
    /// stream while it is still PARKED. This one dies after the grant has
    /// been issued — the app already holds a valid certificate, and the only
    /// thing outstanding is the daemon's bookkeeping.
    @Test func aGrantThatIsNeverConfirmedStaysOnTheDeskForTheNextKnock() async throws {
        let fixture = try await makeFixture(sessionPort: 47450, enrollPort: 47451)
        defer { fixture.cleanup() }

        let keeper = try await enrollDevice(fixture, name: "keeper-phone")
        var (control, controlFrames) = try await openControl(fixture, identity: keeper.identity)
        defer { control.cancel() }
        try await control.send(GrantSubscribe())

        // The app is granted and then vanishes without confirming.
        let appKey = P256.Signing.PrivateKey()
        let knock = Task {
            try await appEnroll(fixture, bundleID: "systems.reach.vanished", name: "Vanished", appKey: appKey, closing: .vanish)
        }
        let event = try (try #require(try await controlFrames.next())).decode(GrantEvent.self)
        try await control.send(GrantRule(requestID: event.requestID, allow: true))
        guard case .granted = try await knock.value else {
            Issue.record("the app was refused after an allow ruling")
            return
        }

        // The daemon read no confirmation, so it holds the verdict rather than
        // forgetting it. Give the unconfirmed path a moment to be taken.
        try await Task.sleep(for: .milliseconds(300))
        #expect(await fixture.desk.footprint.ruled == 1)

        // …and the same app key collects it on its next knock, with no second
        // ruling — which is the whole reason this half needs no confirming
        // frame. The desk is clean afterwards.
        let second = try await appEnroll(fixture, bundleID: "systems.reach.vanished", name: "Vanished", appKey: appKey)
        guard case .granted(let grant, _) = second else {
            Issue.record("the held verdict was not collectable on a re-knock: \(second)")
            return
        }
        let leaf = try Certificate(derEncoded: Array(grant.appCertDER))
        let uri = try leaf.extensions.subjectAlternativeNames?.compactMap { name -> String? in
            if case .uniformResourceIdentifier(let value) = name { return value }
            return nil
        }.first
        #expect(uri?.hasSuffix("/systems.reach.vanished") == true)
        #expect(await fixture.desk.footprint.ruled == 0)
    }

    @Test func nonAdminRefusedAndDenialRefusesApp() async throws {
        let fixture = try await makeFixture(sessionPort: 47442, enrollPort: 47443)
        defer { fixture.cleanup() }

        let admin = try await enrollDevice(fixture, name: "keeper-phone")
        let second = try await enrollDevice(fixture, name: "second-device")

        // The second device holds a valid cluster certificate but not the
        // admin grant: it may open sessions, not rule them.
        var (secondControl, secondFrames) = try await openControl(fixture, identity: second.identity)
        defer { secondControl.cancel() }
        try await secondControl.send(GrantSubscribe())
        let refusal = try #require(try await secondFrames.next())
        #expect(refusal.type == .errorFrame)
        #expect(try refusal.decode(ErrorFrame.self).code == "grant-denied")

        // The app parks BEFORE the admin subscribes — the pending request
        // must replay to the late subscriber.
        let appTask = Task {
            try await appEnroll(fixture, bundleID: "systems.reach.denied-test", name: "Denied")
        }
        try await Task.sleep(for: .milliseconds(400))

        var (adminControl, adminFrames) = try await openControl(fixture, identity: admin.identity)
        defer { adminControl.cancel() }
        try await adminControl.send(GrantSubscribe())
        let event = try (try #require(try await adminFrames.next())).decode(GrantEvent.self)
        #expect(event.bundleID == "systems.reach.denied-test")

        try await adminControl.send(GrantRule(requestID: event.requestID, allow: false))
        guard case .refused(let error) = try await appTask.value else {
            Issue.record("app was granted despite a deny ruling")
            return
        }
        #expect(error.code == "grant-denied")
    }

    @Test func unruledRequestTimesOut() async throws {
        let fixture = try await makeFixture(sessionPort: 47444, enrollPort: 47445, window: .seconds(1))
        defer { fixture.cleanup() }

        // Nobody is watching the desk; the park window closes on its own.
        let outcome = try await appEnroll(fixture, bundleID: "systems.reach.timeout-test", name: "Timeout")
        guard case .refused(let error) = outcome else {
            Issue.record("app was granted with no ruling")
            return
        }
        #expect(error.code == "grant-timeout")
    }

    /// The one-phone reality: the asker is suspended while the human
    /// rules, so its parked stream is dead when the Allow lands. The desk
    /// holds the verdict; the same key re-knocks and collects it.
    @Test func verdictSurvivesTheAskersStreamDeath() async throws {
        let fixture = try await makeFixture(sessionPort: 47446, enrollPort: 47447)
        defer { fixture.cleanup() }

        let keeper = try await enrollDevice(fixture, name: "keeper-phone")
        var (control, controlFrames) = try await openControl(fixture, identity: keeper.identity)
        defer { control.cancel() }
        try await control.send(GrantSubscribe())

        // The app knocks, parks — and its transport dies (backgrounded).
        let appKey = P256.Signing.PrivateKey()
        let firstKnock = Task {
            try await appEnroll(fixture, bundleID: "systems.reach.suspended", name: "Suspended", appKey: appKey)
        }
        let event = try (try #require(try await controlFrames.next())).decode(GrantEvent.self)
        firstKnock.cancel()   // kills the parked stream client-side
        _ = try? await firstKnock.value
        try await Task.sleep(for: .milliseconds(200))

        // The ruling lands with no live asker.
        try await control.send(GrantRule(requestID: event.requestID, allow: true))
        try await Task.sleep(for: .milliseconds(200))

        // The app returns as the SAME key and collects the held verdict.
        let outcome = try await appEnroll(fixture, bundleID: "systems.reach.suspended", name: "Suspended", appKey: appKey)
        guard case .granted(let grant, _) = outcome else {
            Issue.record("held verdict was not collectable: \(outcome)")
            return
        }
        let leaf = try Certificate(derEncoded: Array(grant.appCertDER))
        let uri = try leaf.extensions.subjectAlternativeNames?.compactMap { name -> String? in
            if case .uniformResourceIdentifier(let value) = name { return value }
            return nil
        }.first
        #expect(uri?.hasSuffix("/systems.reach.suspended") == true)

        // And the desk forgot it after delivery: a fresh knock by the same
        // key parks again (new event on the keeper's stream) rather than
        // silently re-collecting a spent grant.
        let reKnock = Task {
            try await appEnroll(fixture, bundleID: "systems.reach.suspended", name: "Suspended", appKey: appKey)
        }
        let second = try (try #require(try await controlFrames.next())).decode(GrantEvent.self)
        #expect(second.bundleID == "systems.reach.suspended")
        try await control.send(GrantRule(requestID: second.requestID, allow: false))
        guard case .refused = try await reKnock.value else {
            Issue.record("post-collection knock did not park freshly")
            return
        }
    }

    /// An app that goes away between the challenge and its certificate request.
    ///
    /// That read was the last `guard let … = try await ….next() else` in
    /// `EnrollmentService`, so a break threw past it — and so did the `send` in
    /// its `else`, which was ungated and wrote to a stream that may already be
    /// gone. Both routes ended at `serve`'s catch as `enrollment stream failed:
    /// <socket>`, with no bundle in it.
    ///
    /// Nothing durable is at stake there, and that is what this pins: no token
    /// is spent, no verdict is parked, and the service is not wedged. The log
    /// line itself is not assertable — the daemon has no sink a test can read —
    /// so this holds the two things that are observable and says plainly that
    /// it does not hold the third.
    @Test func anAppThatLeavesBeforeItsCertificateRequestParksNothing() async throws {
        let fixture = try await makeFixture(sessionPort: 47452, enrollPort: 47453)
        defer { fixture.cleanup() }

        let keeper = try await enrollDevice(fixture, name: "keeper-phone")
        var (control, controlFrames) = try await openControl(fixture, identity: keeper.identity)
        defer { control.cancel() }
        try await control.send(GrantSubscribe())

        // Knock, take the challenge, and vanish without answering it.
        let abandoned = try await fixture.enrollDialer.openStream(timeout: 45)
        var abandonedFrames = abandoned.frames.makeAsyncIterator()
        try await abandoned.send(AppEnrollBegin(bundleID: "systems.reach.abandoned", displayName: "Abandoned"))
        let challengeRaw = try #require(try await abandonedFrames.next())
        #expect(challengeRaw.type == EnrollChallenge.frameType)
        abandoned.cancel()
        try await Task.sleep(for: .milliseconds(200))

        // A whole ceremony for a different bundle now runs. The first event to
        // reach the keeper has to be that one: if the abandoned knock had
        // parked, its event would be sitting ahead of this in the queue.
        let second = Task {
            try await appEnroll(fixture, bundleID: "systems.reach.arrived", name: "Arrived")
        }
        let event = try (try #require(try await controlFrames.next())).decode(GrantEvent.self)
        #expect(
            event.bundleID == "systems.reach.arrived",
            "a knock that never sent its certificate request parked anyway: \(event.bundleID)"
        )
        try await control.send(GrantRule(requestID: event.requestID, allow: true))
        guard case .granted = try await second.value else {
            Issue.record("the enrollment service did not serve a fresh ceremony after the abandoned one")
            return
        }
    }
}

/// The desk's own tables, which nothing else in the daemon can observe.
///
/// It is the only organ with no persistence — no `devices.json`, no `ca/`,
/// no conf — so a table growing without bound leaves no artifact anywhere
/// that a person could notice. These watch the two that did.
@Suite struct GrantDeskFootprintTests {
    private func knock(_ fingerprint: String) -> GrantEvent {
        GrantEvent(
            requestID: UUID(),
            deviceID: "127.0.0.1:1",
            bundleID: "systems.reach.footprint",
            displayName: "Footprint",
            appKeyFingerprint: fingerprint
        )
    }

    /// An allowed verdict was cleared by `collected`, or lazily by a later
    /// knock from the same app. An app that crashed or was uninstalled
    /// sends no later knock, so its verdict stayed for the life of the
    /// process — while `docs/wire.md` says it is *held* ten minutes.
    @Test func aVerdictNobodyCollectsDoesNotOutliveItsHoldWindow() async throws {
        let desk = GrantDesk(window: .seconds(30), holdWindow: 0.05)

        for index in 0..<4 {
            let event = knock("fingerprint-\(index)")
            let parked = Task { await desk.park(event) }
            // Let the park land before ruling on it.
            try await Task.sleep(for: .milliseconds(20))
            #expect(await desk.rule(requestID: event.requestID, allow: true, ruler: UUID()))
            _ = await parked.value
        }

        var footprint = await desk.footprint
        #expect(footprint.ruled == 4)

        // Nothing collects — the four apps never come back.
        try await Task.sleep(for: .milliseconds(120))
        #expect(await desk.sweep() > 0)
        footprint = await desk.footprint
        #expect(footprint.ruled == 0)
        #expect(footprint.index == 0)
    }

    /// A knock that times out never reaches `collected`, so its index entry
    /// had nothing that could ever retire it.
    @Test func aKnockThatTimesOutDoesNotLeaveAnIndexEntryBehind() async throws {
        let desk = GrantDesk(window: .milliseconds(30), holdWindow: 0.05)

        for index in 0..<4 {
            let verdict = await desk.park(knock("timeout-\(index)"))
            #expect(verdict == .timedOut)
        }
        #expect(await desk.footprint.index == 4)

        try await Task.sleep(for: .milliseconds(120))
        await desk.sweep()
        #expect(await desk.footprint.index == 0)
    }

    /// …but a knock still parked keeps its entry, because the keeper can
    /// still rule on it and that ruling has to find its fingerprint.
    @Test func aKnockStillWaitingKeepsTheIndexItsRulingNeeds() async throws {
        let desk = GrantDesk(window: .seconds(30), holdWindow: 0.05)
        let event = knock("still-waiting")
        let parked = Task { await desk.park(event) }
        try await Task.sleep(for: .milliseconds(20))

        try await Task.sleep(for: .milliseconds(80))
        await desk.sweep()
        #expect(await desk.footprint.index == 1)

        #expect(await desk.rule(requestID: event.requestID, allow: true, ruler: UUID()))
        _ = await parked.value
    }
}
