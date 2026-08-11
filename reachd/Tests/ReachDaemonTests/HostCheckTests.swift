import Crypto
import Foundation
import Testing

@testable import ReachDaemon

/// The first tests `doctor` has ever had. They are deliberately pure
/// filesystem: no identity materialization, no real sockets, no listeners —
/// so this suite is deterministic, needs no `.serialized`, and cannot be
/// implicated in the PKCS#12 import failure that the identity path still has.
@Suite struct HostCheckTests {
    /// Fixtures set their own mode. `createDirectory` alone lands at
    /// `0777 & ~umask`, so a developer at `umask 022` gets 0755 and a
    /// developer at `umask 077` gets 0700 — and a permission assertion that
    /// inherits either one passes or fails according to whose machine it is.
    private func fixture(mode: Int = 0o700) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-doctor-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    private func report(
        _ directory: URL,
        conf: String? = nil,
        addresses: [[UInt8]] = [[192, 168, 8, 104], [10, 86, 0, 1]],
        portsHeld: Bool = false
    ) async -> HostCheck.Report {
        await HostCheck.examine(
            stateDirectory: directory,
            wireGuardConf: conf ?? directory.appendingPathComponent("absent.conf").path,
            addresses: addresses,
            supervision: .ordinary,
            supervisionHome: directory,
            canonicalState: directory.appendingPathComponent("Library/Application Support/Reach"),
            portIsHeld: { _ in portsHeld }
        )
    }

    private func finding(_ report: HostCheck.Report, _ title: String) throws -> HostCheck.Finding {
        try #require(report.findings.first { $0.title == title })
    }

    // MARK: - The exit code answers one question

    @Test func aColdRigIsWaitingNotBroken() async throws {
        // Nothing has been started: no CA, no wg key, no conf, no devices,
        // no daemon, no mesh interface. Every one of those is the next step
        // in the runbook, and none of them is a fault.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        var config = DaemonConfig()
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: directory)

        let report = await report(directory, addresses: [[192, 168, 8, 104]])

        #expect(report.isSound, "a rig that has not been started is not a broken one")
        #expect(report.count(.fail) == 0)
        #expect(report.count(.wait) > 0)
        for title in ["mesh interface", "cluster CA", "wg host key", "mesh intent", "mesh owner", "enrolled devices", "session port"] {
            #expect(try finding(report, title).level == .wait, "\(title) should be waiting, not faulted")
        }
    }

    @Test func aMissingUnconfiguredMeshOwnerStaysWaitingWhileLANServingContinues() async throws {
        // The login daemon and the privileged mesh owner are separate facts.
        // An absent/unconfigured helper is actionable WAIT, not a daemon fault.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        var config = DaemonConfig()
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: directory)

        let waiting = await report(directory, addresses: [[192, 168, 8, 104]], portsHeld: false)
        #expect(try finding(waiting, "mesh interface").level == .wait)
        #expect(waiting.isSound)

        let serving = await report(directory, addresses: [[192, 168, 8, 104]], portsHeld: true)
        #expect(try finding(serving, "mesh interface").level == .wait)
        #expect(try finding(serving, "mesh owner").level == .wait)
        #expect(serving.isSound)
    }

    // MARK: - Absent is not the same answer as broken

    @Test func aCorruptCADoesNotReadAsAbsent() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ca = directory.appendingPathComponent("ca", isDirectory: true)
        try FileManager.default.createDirectory(at: ca, withIntermediateDirectories: true)

        let absent = await report(directory)
        #expect(try finding(absent, "cluster CA").level == .wait)

        // Present, and will not load. Every enrolled device was issued
        // against this; reporting it as "not started yet" would be worse
        // than the undifferentiated warning it replaced.
        try Data("not a certificate".utf8).write(to: ca.appendingPathComponent("ca.der"))
        try Data("not a key".utf8).write(to: ca.appendingPathComponent("ca-key.raw"))

        let corrupt = await report(directory)
        #expect(try finding(corrupt, "cluster CA").level == .fail)
        #expect(!corrupt.isSound)
    }

    @Test func aHostKeyWithoutItsMeshIntentIsAFault() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path

        // No host key yet: missing intent is a genuine first run.
        let firstRun = await report(directory, conf: conf)
        #expect(try finding(firstRun, "mesh intent").level == .wait)
        #expect(firstRun.isSound)

        _ = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        try FileManager.default.removeItem(at: MeshIntentStore.intentURL(in: directory))

        let stranded = await report(directory, conf: conf)
        #expect(try finding(stranded, "mesh intent").level == .fail)
        #expect(!stranded.isSound)
    }

    @Test func anUnsafeIntentIsAFaultAndSaysSo() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        _ = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: directory.appendingPathComponent("absent.conf").path,
            endpoint: "192.0.2.1:51820"
        )
        let intent = MeshIntentStore.intentURL(in: directory)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: intent.path)

        let report = await report(directory)
        let meshIntent = try finding(report, "mesh intent")
        #expect(meshIntent.level == .fail)
        #expect(meshIntent.detail.contains("unsafe ownership, mode"))
        #expect(!report.isSound)
    }

    // MARK: - The endpoint says who can reach this host

    @Test func aFirstRunIsNotAFailureButAConfiguredHostThatForgotThePinIs() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }

        // No config at all: derivation is what the type says it is — correct
        // for a machine nobody has configured yet.
        let firstRun = await report(directory)
        #expect(try finding(firstRun, "mesh endpoint").level == .wait)
        #expect(firstRun.isSound, "a machine that has never been configured must not exit non-zero")

        // A config exists and omits meshEndpoint. This host HAS been set up,
        // and the away leg was left out of it — the failure that reaches a
        // venue looking healthy and presents as a routing fault.
        try DaemonConfig().save(to: directory)
        let unpinned = await report(directory)
        #expect(try finding(unpinned, "mesh endpoint").level == .fail)
        #expect(!unpinned.isSound)
    }

    @Test func aCGNATLeaseIsAFailureButThisHostsOwnMeshAddressIsNot() async throws {
        // Both are 100.64/10 and classify cannot tell them apart. Whether
        // this host holds the address is the entire difference: a lease read
        // off a venue's router can never carry the leg; an address on this
        // machine is a road it is already standing on.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        var config = DaemonConfig()
        config.meshEndpoint = "100.66.143.31:51820"
        try config.save(to: directory)

        let ownAddress = await report(directory, addresses: [[100, 66, 143, 31], [10, 86, 0, 1]])
        #expect(try finding(ownAddress, "mesh endpoint").level == .warn)
        #expect(ownAddress.isSound)

        let routerLease = await report(directory, addresses: [[192, 168, 8, 104], [10, 86, 0, 1]])
        #expect(try finding(routerLease, "mesh endpoint").level == .fail)
        #expect(!routerLease.isSound, "a CGNAT lease cannot carry the away leg and must say so")
    }

    @Test func anRFC1918PinSaysWhetherItIsThisHostsOwnAddress() async throws {
        // One forward or two. The runbook makes this call by hand at the
        // venue; the difference is observable from here.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        var config = DaemonConfig()
        config.meshEndpoint = "192.168.8.104:51820"
        try config.save(to: directory)

        let own = try await finding(report(directory, addresses: [[192, 168, 8, 104]]), "mesh endpoint")
        #expect(own.level == .warn)
        #expect(own.action?.contains("One forward") == true)

        let upstream = try await finding(report(directory, addresses: [[10, 0, 0, 5]]), "mesh endpoint")
        #expect(upstream.level == .warn, "RFC1918 stays a warning — two forwards in series is a real venue")
        #expect(upstream.detail.contains("not an address this host holds"))
        #expect(upstream.action?.contains("two forwards in series") == true)
    }

    @Test func aMalformedConfigDoesNotDeleteFindings() async throws {
        // The endpoint and both ports used to vanish from the report, so an
        // operator told to read the diff between two runs saw a shorter list
        // and no statement that anything had been skipped.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        try DaemonConfig().save(to: directory)
        let sound = await report(directory)

        try Data(#"{ "meshEndpoint" : 192.168.4.94:51820 }"#.utf8)
            .write(to: directory.appendingPathComponent("config.json"))
        let broken = await report(directory)

        #expect(try finding(broken, "config.json").level == .fail)
        #expect(broken.findings.count >= sound.findings.count - 1, "findings must not silently disappear")
        #expect(try finding(broken, "mesh endpoint").detail.contains("not checked"))
        #expect(try finding(broken, "ports").detail.contains("not checked"))
    }

    // MARK: - The conf and the state directory must agree

    /// Every row here is a conf wg-quick accepts. A parser stricter than the
    /// thing that actually consumes the file would report a fault in a working
    /// rig, and a false FAIL that stops a venue is worse than the blindness it
    /// replaced. The live conf exercises none of these, which is exactly why
    /// they are tested rather than eyeballed.
    @Test(arguments: [
        ("canonical", "[Interface]\nPrivateKey = KEY\nListenPort = 51820\n"),
        ("lowercased key", "[Interface]\nprivatekey = KEY\n"),
        ("lowercased section", "[interface]\nPrivateKey = KEY\n"),
        ("trailing comment", "[Interface]\nPrivateKey = KEY # the host key\n"),
        ("comment naming a section", "# see [Interface] below\n[Interface]\nPrivateKey = KEY\n"),
        ("no trailing newline", "[Interface]\nPrivateKey = KEY"),
        ("CRLF", "[Interface]\r\nPrivateKey = KEY\r\n"),
        ("wg-quick-only keys", "[Interface]\nPrivateKey = KEY\nPostUp = /bin/true\nTable = off\n"),
        ("no spaces around =", "[Interface]\nPrivateKey=KEY\n"),
    ])
    func theConfParserAcceptsEveryConfWgQuickAccepts(name: String, template: String) throws {
        // A real 32-byte key: 44 base64 characters ending in one "=" of
        // padding. A parser that splits on the LAST separator reads this as
        // empty, which is every conf this rig has ever written.
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        #expect(key.hasSuffix("="), "the regression this row exists for needs the padding")

        let parsed = try WireGuardConf.parse(template.replacingOccurrences(of: "KEY", with: key))
        #expect(parsed.hasInterfaceSection, "\(name): lost the [Interface] section")
        #expect(parsed.privateKey == key, "\(name): read the key as \(parsed.privateKey ?? "nil")")
    }

    @Test func aPrivateKeyUnderPeerIsNotTheHostKey() throws {
        // Section-scoped: any [-headed line closes the section, so a key in a
        // peer block belongs to the peer and this host has no identity.
        let key = Data(repeating: 9, count: 32).base64EncodedString()
        let parsed = try WireGuardConf.parse("[Peer]\nPrivateKey = \(key)\nAllowedIPs = 10.86.0.2/32\n")
        #expect(!parsed.hasInterfaceSection)
        #expect(parsed.privateKey == nil)
        #expect(parsed.peerCount == 1)
    }

    @Test func aCommentedOutPeerIsNotAPeer() throws {
        // The old count was a substring split on "[Peer]", so a commented
        // block counted as an admitted device.
        let parsed = try WireGuardConf.parse("""
            [Interface]
            PrivateKey = \(Data(repeating: 1, count: 32).base64EncodedString())

            # [Peer]
            # PublicKey = something

            [Peer]
            PublicKey = \(Data(repeating: 2, count: 32).base64EncodedString())
            AllowedIPs = 10.86.0.2/32
            """)
        #expect(parsed.peerCount == 1)
    }

    @Test func twoInterfaceSectionsAreRefusedRatherThanGuessedAt() throws {
        let key = Data(repeating: 3, count: 32).base64EncodedString()
        #expect(throws: WireGuardConf.Trouble.self) {
            try WireGuardConf.parse("[Interface]\nPrivateKey = \(key)\n[Interface]\nPrivateKey = \(key)\n")
        }
    }

    @Test func theWireGuardPrivateAndPublicKeysMustAgree() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path

        // WireGuardHost mints the keypair and intent together.
        _ = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        let agreeing = await report(directory, conf: conf)
        #expect(try finding(agreeing, "wg identity").level == .pass)
        #expect(agreeing.isSound)

        let pub = directory.appendingPathComponent("wg/server.pub")
        let other = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        try other.write(to: pub, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pub.path)

        let diverged = await report(directory, conf: conf)
        let identity = try finding(diverged, "wg host key")
        #expect(identity.level == .fail)
        #expect(!diverged.isSound)
    }

    @Test func legacyEvidenceWithNoInterfaceIsStillRecognizedAsInvalid() throws {
        let parsed = try WireGuardConf.parse("""
            [Peer]
            PublicKey = \(Data(repeating: 4, count: 32).base64EncodedString())
            AllowedIPs = 10.86.0.2/32
            """)
        let identity = HostCheck.checkWireGuardIdentity(parsed, hostKey: nil, conf: "rollback.conf")
        #expect(identity.level == .fail)
        #expect(identity.detail.contains("no [Interface]"))
    }

    @Test func noFindingEverRendersThePrivateKey() async throws {
        // doctor's output is filmed as the evidence tail after a take.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path
        _ = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        let keyURL = directory.appendingPathComponent("wg/server.key")
        let secret = try MeshIntentStore.readCanonicalKey(keyURL, role: "host private key", exactMode: 0o600)

        // Both the agreeing case and the mismatching one, since the mismatch
        // is the branch that has keys in hand and something to say about them.
        for mutate in [false, true] {
            if mutate {
                let pub = directory.appendingPathComponent("wg/server.pub")
                let other = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
                try other.write(to: pub, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pub.path)
            }
            let rendered = await report(directory, conf: conf).findings
                .map { "\($0.level.rawValue) \($0.title) \($0.detail) \($0.action ?? "")" }
                .joined(separator: "\n")
            #expect(!rendered.contains(secret), "a private key reached doctor's output")
        }
    }

    /// A device that enrolled and never got a road is a fault doctor can see.
    ///
    /// The ceremony activates the record and then writes the peer block, in
    /// that order on purpose. A crash in the window between leaves a device
    /// that authenticates, opens sessions and has no mesh — so it streams on
    /// the LAN and dies at the walk-out, which is exactly the shape doctor
    /// was built for. Neither half saw it before: one counts records, the
    /// other counts peers, and nothing compared them.
    @Test func aDeviceWithNoRoadOntoTheMeshIsAFault() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path
        let host = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        // The conf exists with an [Interface] and no peer — which is what
        // `serve` leaves behind before any device is admitted.
        try await host.addPeer(publicKey: Data(repeating: 7, count: 32), allowedIP: "10.86.0.2")

        // Two devices reach EnrollComplete; only one peer was ever written.
        let registry = DeviceRegistry(directory: directory)
        for (index, name) in ["phone", "tablet"].enumerated() {
            let record = try await registry.reserve(
                name: name,
                devicePubX963: P256.Signing.PrivateKey().publicKey.x963Representation
            )
            await registry.admit(record.id, wgPub: Data(repeating: UInt8(20 + index), count: 32))
        }

        let devices = try await finding(report(directory, conf: conf), "enrolled devices")
        #expect(devices.level == .fail)
        #expect(devices.detail.contains("no road onto the mesh"))
        #expect(await !report(directory, conf: conf).isSound)
    }

    /// …and the ordinary rig, where every active device has its block, is
    /// not accused of anything.
    @Test func aRigWhereEveryDeviceHasItsPeerIsSound() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path
        let host = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        let registry = DeviceRegistry(directory: directory)
        let record = try await registry.reserve(
            name: "phone",
            devicePubX963: P256.Signing.PrivateKey().publicKey.x963Representation
        )
        await registry.admit(record.id, wgPub: Data(repeating: 9, count: 32))
        try await host.addPeer(publicKey: Data(repeating: 9, count: 32), allowedIP: record.assignedIP)

        let devices = try await finding(report(directory, conf: conf), "enrolled devices")
        #expect(devices.level == .pass)
    }

    /// The case that actually bit, and the one counting could never see. A torn
    /// re-pair leaves the previous intent peer in place, so the tally balances at
    /// one active device and one peer while the phone — holding a key intent
    /// does not name — has no road at all. Measured on the rig on 2026-07-29: the
    /// registry held one key, the conf held another, and doctor called it sound.
    @Test func aDeviceWhoseIntentKeyIsStaleIsAFault() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path
        let host = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        // The block the phone walked in with.
        try await host.addPeer(publicKey: Data(repeating: 7, count: 32), allowedIP: "10.86.0.2")

        // The registry moved on to the key a re-pair brought; intent did not.
        let registry = DeviceRegistry(directory: directory)
        let record = try await registry.reserve(
            name: "phone",
            devicePubX963: P256.Signing.PrivateKey().publicKey.x963Representation
        )
        await registry.admit(record.id, wgPub: Data(repeating: 8, count: 32))

        // One active device and one peer: the counts agree, the keys do not, and
        // the old check read exactly this as a sound rig.
        let intent = try await finding(report(directory, conf: conf), "mesh intent")
        #expect(intent.detail.contains("1 ordered peer"))
        let devices = try await finding(report(directory, conf: conf), "enrolled devices")
        #expect(devices.level == .fail)
        #expect(devices.detail.contains("no road onto the mesh"))
        #expect(await !report(directory, conf: conf).isSound)
    }

    /// Strict intent refuses a hand edit that gives two keys the same /32.
    @Test func twoPeersClaimingOneAddressIsAFault() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path
        let host = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        try await host.addPeer(publicKey: Data(repeating: 7, count: 32), allowedIP: "10.86.0.2")
        let intentURL = MeshIntentStore.intentURL(in: directory)
        var object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: intentURL)) as? [String: Any])
        var peers = try #require(object["peers"] as? [[String: Any]])
        peers.append([
            "publicKey": Data(repeating: 8, count: 32).base64EncodedString(),
            "allowedIP": "10.86.0.2/32",
            "keepalive": 0,
        ])
        object["peers"] = peers
        try JSONSerialization.data(withJSONObject: object).write(to: intentURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: intentURL.path)

        let duplicate = try await finding(report(directory, conf: conf), "mesh intent")
        #expect(duplicate.level == .fail)
        #expect(duplicate.detail.contains("repeats a peer route"))
        #expect(await !report(directory, conf: conf).isSound)
    }

    @Test func thePeerCountSaysItReadTheIntent() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path
        let host = try WireGuardHost(
            keysDirectory: directory.appendingPathComponent("wg", isDirectory: true),
            confPath: conf,
            endpoint: "192.0.2.1:51820"
        )
        try await host.addPeer(publicKey: Data(repeating: 5, count: 32), allowedIP: "10.86.0.2")

        let meshIntent = try await finding(report(directory, conf: conf), "mesh intent")
        #expect(meshIntent.level == .pass)
        #expect(meshIntent.detail.contains("1 ordered peer"))
    }

    // MARK: - The tally

    @Test func theTallyCountsEveryLevel() async throws {
        // Passes used to be derived by subtracting warnings and failures from
        // the total, which is arithmetic that silently loses a level the
        // moment a fourth one exists.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let report = await report(directory)

        let counted = report.count(.pass) + report.count(.warn) + report.count(.wait) + report.count(.fail)
        #expect(counted == report.findings.count)
    }

    // MARK: - The CA's name and the config's name

    /// The CA is minted once, with whatever the cluster was called that day,
    /// and nothing re-mints it. A `config.json` that is renamed — or
    /// regenerated, and so quietly returned to the default — leaves every
    /// issued certificate saying the old name while the daemon advertises the
    /// new one. A granted app reads the CA's name, because that is the only
    /// one that survives its own relaunch, so the drift shows up as an app
    /// confidently naming a cluster nobody calls that any more. It went
    /// unnoticed until it was read off a screen.
    @Test func aCAWhoseNameTheConfigNoLongerSharesIsReported() throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        try ClusterCA.create(commonName: "Drift CA")
            .save(to: directory.appendingPathComponent("ca", isDirectory: true))

        var config = DaemonConfig()
        config.clusterName = "Renamed In Config"

        let finding = HostCheck.checkClusterCA(in: directory, config: config)
        #expect(finding.level == .warn)
        #expect(finding.detail.contains("Drift CA"))
        #expect(finding.detail.contains("Renamed In Config"))
        // The action has to name which way to resolve it: agreeing with the CA
        // costs nothing, re-minting invalidates every enrolled device.
        #expect(finding.action?.contains("Drift CA") == true)
    }

    @Test func aCAAndConfigThatAgreeSaySoAndNothingMore() throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        try ClusterCA.create(commonName: "Drift CA")
            .save(to: directory.appendingPathComponent("ca", isDirectory: true))

        var config = DaemonConfig()
        config.clusterName = "Drift CA"

        let finding = HostCheck.checkClusterCA(in: directory, config: config)
        #expect(finding.level == .pass)
    }

    /// No config is not a mismatch. Without this the check would invent a
    /// warning on a first run, which is the failure mode doctor exists to
    /// avoid: noise that trains an operator to skim.
    @Test func aCAWithNoConfigToCompareAgainstIsNotADrift() throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        try ClusterCA.create(commonName: "Drift CA")
            .save(to: directory.appendingPathComponent("ca", isDirectory: true))

        #expect(HostCheck.checkClusterCA(in: directory, config: nil).level == .pass)
    }
}

/// Whether anything brings the daemon back after it dies.
///
/// The design note said "a launchd service on the Mac today" while there was
/// no plist anywhere in the tree, so `doctor` — the one place that reports
/// what the host actually is — had nothing to say about it either.
@Suite struct SupervisionCheckTests {
    private func emptyHome() throws -> URL {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-supervision-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        return home
    }

    private func canonicalState(in home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support/Reach", isDirectory: true)
    }

    private func writeAgent(home: URL, state: URL) throws {
        let plist = LaunchAgent.plistURL(home: home)
        try FileManager.default.createDirectory(
            at: plist.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try LaunchAgent.definition(
            executable: "/opt/reach/reachd",
            uid: 501,
            stateDirectory: state,
            home: home
        ).propertyListData().write(to: plist)
    }

    @Test func noAgentIsAWaitAndNotAFailure() throws {
        let home = try emptyHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let state = canonicalState(in: home)
        let finding = HostCheck.checkSupervision(
            daemonUp: false,
            examinedState: state,
            home: home,
            canonicalState: state
        )
        #expect(finding.level == .wait, "running serve by hand is a way to work, not a fault")
        #expect(finding.action?.contains("reachd service install") == true)
    }

    /// A running daemon and a supervised daemon are different states, and the
    /// gap between them is the whole point of the check.
    @Test func aRunningDaemonWithNoAgentStillSaysNothingRestartsIt() throws {
        let home = try emptyHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let state = canonicalState(in: home)
        let finding = HostCheck.checkSupervision(
            daemonUp: true,
            examinedState: state,
            home: home,
            canonicalState: state
        )
        #expect(finding.level == .wait)
        #expect(finding.detail.contains("nothing restarts it"))
    }

    @Test func anInstalledAgentPasses() throws {
        let home = try emptyHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let state = canonicalState(in: home)
        try writeAgent(home: home, state: state)
        let finding = HostCheck.checkSupervision(
            daemonUp: true,
            examinedState: state,
            home: home,
            canonicalState: state
        )
        #expect(finding.level == .pass)
        #expect(finding.detail.contains(state.path))
    }

    @Test func anInvalidOrNoncanonicalInstalledStateFails() throws {
        let home = try emptyHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let canonical = canonicalState(in: home)
        let plist = LaunchAgent.plistURL(home: home)
        try FileManager.default.createDirectory(
            at: plist.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try "<plist/>".write(to: plist, atomically: true, encoding: .utf8)

        let malformed = HostCheck.checkSupervision(
            daemonUp: true,
            examinedState: canonical,
            home: home,
            canonicalState: canonical
        )
        #expect(malformed.level == .fail)
        #expect(malformed.detail.contains("invalid state"))

        try writeAgent(home: home, state: home.appendingPathComponent("Other Cluster"))
        let divergent = HostCheck.checkSupervision(
            daemonUp: true,
            examinedState: canonical,
            home: home,
            canonicalState: canonical
        )
        #expect(divergent.level == .fail)
        #expect(divergent.detail.contains("noncanonical"))
    }

    @Test func ordinaryAndExplicitScratchDiagnosisDisagreeDeliberately() throws {
        let home = try emptyHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let canonical = canonicalState(in: home)
        let scratch = home.appendingPathComponent("Scratch Cluster")
        try writeAgent(home: home, state: canonical)

        let ordinary = HostCheck.checkSupervision(
            daemonUp: true,
            examinedState: scratch,
            context: .ordinary,
            home: home,
            canonicalState: canonical
        )
        #expect(ordinary.level == .fail)
        #expect(ordinary.detail.contains("doctor is examining"))

        let explicit = HostCheck.checkSupervision(
            daemonUp: true,
            examinedState: scratch,
            context: .explicitScratch,
            home: home,
            canonicalState: canonical
        )
        #expect(explicit.level == .wait)
        #expect(explicit.detail.contains("not supervised"))
    }
}

/// What `service install` refuses, and why each refusal exists.
///
/// Both were met for real while installing the agent on 5 Aug: the binary
/// went to a bin directory on its own, launchd started it, it printed that
/// it was serving, bound the port, and died on the metallib.
@Suite struct LaunchAgentInstallTests {
    private func propertyList(_ data: Data) throws -> [String: Any] {
        try #require(
            try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        )
    }

    private func propertyListData(_ value: Any) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
    }

    private func invalidReason(_ state: LaunchAgent.InstalledState) throws -> String {
        guard case .invalid(let reason) = state else {
            Issue.record("expected invalid installed state, got \(state)")
            return ""
        }
        return reason
    }

    private func stage(_ files: [String]) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-agent-\(UUID())", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        for file in files {
            let url = directory.appendingPathComponent(file)
            if file.hasSuffix(".bundle") {
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            } else {
                try Data().write(to: url)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
            }
        }
        return directory
    }

    @Test func aBinaryWithoutItsBundlesIsRefused() throws {
        let directory = try stage(["reachd"])
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: ServiceError.missingResources(
            directory.appendingPathComponent("reachd").resolvingSymlinksInPath().path
        )) {
            _ = try LaunchAgent.executablePath(directory.appendingPathComponent("reachd").path)
        }
    }

    @Test func aBinaryBesideItsBundlesIsAccepted() throws {
        let directory = try stage(["reachd", "mlx-swift_Cmlx.bundle"])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = try LaunchAgent.executablePath(directory.appendingPathComponent("reachd").path)
        #expect(path.hasSuffix("/reachd"))
    }

    @Test func somethingThatIsNotThereIsRefusedBeforeAnythingElse() throws {
        #expect(throws: ServiceError.self) {
            _ = try LaunchAgent.executablePath("/nowhere/reachd")
        }
    }

    /// The plist is the contract with launchd, and the first draft of it was
    /// wrong in a way only an install could show.
    ///
    /// It said `KeepAlive: {Crashed: true}` — and a `kill -9` against the
    /// installed agent did not bring the daemon back, because launchd counts
    /// a crash as the SIGSEGV/SIGABRT family and not a deliberate signal.
    /// That also misses the kernel's own `SIGKILL` under memory pressure,
    /// which is the likeliest unplanned death of a process holding several
    /// gigabytes of weights. A supervisor cannot be selective about which
    /// deaths count.
    @Test func theAgentComesBackFromAnyDeath() throws {
        let plist = try propertyList(Data(LaunchAgent.plist(executable: "/usr/local/bin/reachd").utf8))
        #expect(plist["Crashed"] == nil, "Crashed does not cover SIGKILL")
        #expect(plist["SuccessfulExit"] == nil)
        #expect(plist["KeepAlive"] as? Bool == true)
        #expect(
            plist["ThrottleInterval"] as? Int == 10,
            "unconditional restart needs a floor, or a permanently held port spins"
        )
        #expect(plist["RunAtLoad"] as? Bool == true)
        #expect(plist["ProcessType"] as? String == "Interactive")
        #expect(plist["StandardOutPath"] != nil, "print goes nowhere under launchd otherwise")
        #expect(plist["StandardErrorPath"] != nil)
    }

    @Test func theLaunchDefinitionNamesOneLoginOwnerAndOneStateRoot() throws {
        let home = URL(fileURLWithPath: "/Users/Reach Owner", isDirectory: true)
        let state = home.appendingPathComponent("Library/Application Support/Reach & Co", isDirectory: true)
        let executable = "/Applications/Reach & Tools/reachd"
        let definition = LaunchAgent.definition(
            executable: executable,
            uid: 501,
            stateDirectory: state,
            home: home
        )

        #expect(definition.uid == 501)
        #expect(definition.domain == "gui/501")
        #expect(definition.serviceTarget == "gui/501/\(LaunchAgent.label)")
        #expect(definition.executable == executable)
        #expect(definition.stateDirectory == state)
        #expect(definition.logURL.path == "/Users/Reach Owner/Library/Logs/reachd.log")

        let data = try definition.propertyListData()
        let plist = try propertyList(data)
        #expect(plist["ProgramArguments"] as? [String] == [executable, "serve"])
        let environment = try #require(plist["EnvironmentVariables"] as? [String: String])
        #expect(environment[DaemonInfo.stateEnvironmentKey] == state.path)
        #expect(LaunchAgent.installedState(inPlist: data) == .valid(
            serializedPath: state.path,
            stateDirectory: state.standardizedFileURL
        ))

        let xml = String(decoding: data, as: UTF8.self)
        #expect(xml.contains("Reach &amp; Tools"), "PropertyListSerialization must escape paths")
        #expect(xml.contains("Reach &amp; Co"))
    }

    @Test func rootEntryRefusesBeforeAStateDirectoryCanBeMutated() throws {
        let state = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-root-refusal-\(UUID())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: state) }

        #expect(throws: ServiceError.rootInstall) {
            _ = try LoginOwnedHost.selectServiceState(
                effectiveUID: 0,
                environment: [DaemonInfo.stateEnvironmentKey: "/another/cluster"],
                canonicalState: state
            )
            try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        }
        #expect(!FileManager.default.fileExists(atPath: state.path))

        #expect(throws: ServiceError.rootServeNeedsExplicitState) {
            try LoginOwnedHost.authorizeServe(effectiveUID: 0, environment: [:])
        }
        #expect(throws: ServiceError.rootServeNeedsExplicitState) {
            try LoginOwnedHost.authorizeServe(
                effectiveUID: 0,
                environment: [DaemonInfo.stateEnvironmentKey: "relative-state"]
            )
        }

        try LoginOwnedHost.authorizeServe(
            effectiveUID: 0,
            environment: [DaemonInfo.stateEnvironmentKey: state.path]
        )
        try LoginOwnedHost.authorizeServe(effectiveUID: 501, environment: [:])
    }

    @Test func serviceStateSelectionKeepsOneCanonicalAuthority() throws {
        let canonical = URL(
            fileURLWithPath: "/Users/Reach Owner/Library/Application Support/Reach",
            isDirectory: true
        )
        let normalized = canonical.standardizedFileURL

        #expect(try LoginOwnedHost.selectServiceState(
            effectiveUID: 501,
            environment: [:],
            canonicalState: canonical
        ) == normalized)
        #expect(try LoginOwnedHost.selectServiceState(
            effectiveUID: 501,
            environment: [DaemonInfo.stateEnvironmentKey: ""],
            canonicalState: canonical
        ) == normalized)
        #expect(try LoginOwnedHost.selectServiceState(
            effectiveUID: 501,
            environment: [
                DaemonInfo.stateEnvironmentKey:
                    "/Users/Reach Owner/Library/Application Support/Reach/../Reach"
            ],
            canonicalState: canonical
        ) == normalized)

        let relative = ServiceStateOverrideError(
            selected: "scratch/reach",
            supported: canonical.path
        )
        #expect(throws: relative) {
            _ = try LoginOwnedHost.selectServiceState(
                effectiveUID: 501,
                environment: [DaemonInfo.stateEnvironmentKey: "scratch/reach"],
                canonicalState: canonical
            )
        }

        let selected = "/private/tmp/another cluster"
        let divergent = ServiceStateOverrideError(
            selected: selected,
            supported: canonical.path
        )
        #expect(throws: divergent) {
            _ = try LoginOwnedHost.selectServiceState(
                effectiveUID: 501,
                environment: [DaemonInfo.stateEnvironmentKey: selected],
                canonicalState: canonical
            )
        }
        #expect(divergent.description == "service install cannot persist REACH_STATE_DIR \"\(selected)\"; the login-owned service supports only \"\(canonical.path)\". Unset REACH_STATE_DIR and try again.")
    }

    @Test func installedStateParsingDistinguishesEveryContractShape() throws {
        let canonical = "/Users/Reach Owner/Library/Application Support/Reach & Co"
        let valid = try propertyListData([
            "EnvironmentVariables": [
                DaemonInfo.stateEnvironmentKey: canonical,
                "UNRELATED": "preserved",
            ],
        ])
        #expect(LaunchAgent.installedState(inPlist: valid) == .valid(
            serializedPath: canonical,
            stateDirectory: URL(fileURLWithPath: canonical, isDirectory: true).standardizedFileURL
        ))

        #expect(try invalidReason(LaunchAgent.installedState(inPlist: Data("not plist".utf8))).contains("not a valid property list"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData(["not", "a", "dictionary"]))).contains("root is not a dictionary"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData([:]))).contains("EnvironmentVariables"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData(["EnvironmentVariables": "no"]))).contains("not a dictionary"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData(["EnvironmentVariables": [:]]))).contains("is missing"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData([
            "EnvironmentVariables": [DaemonInfo.stateEnvironmentKey: 42],
        ]))).contains("is not a string"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData([
            "EnvironmentVariables": [DaemonInfo.stateEnvironmentKey: ""],
        ]))).contains("is empty"))
        #expect(try invalidReason(LaunchAgent.installedState(inPlist: propertyListData([
            "EnvironmentVariables": [DaemonInfo.stateEnvironmentKey: "relative/path"],
        ]))).contains("is relative"))
    }

    @Test func installedStateDistinguishesMissingAndUnreadableFiles() throws {
        let plist = URL(fileURLWithPath: "/Users/cassie/Library/LaunchAgents/systems.reach.reachd.plist")
        #expect(LaunchAgent.installedState(
            at: plist,
            fileExists: { _ in false },
            readData: { _ in Issue.record("a missing plist must not be read"); return Data() }
        ) == .notInstalled)

        let unreadable = LaunchAgent.installedState(
            at: plist,
            fileExists: { _ in true },
            readData: { _ in throw CocoaError(.fileReadNoPermission) }
        )
        #expect(try invalidReason(unreadable).contains("could not read"))
    }

    @Test func invalidStatusKeepsProcessAndMeshFactsVisible() {
        let canonical = URL(fileURLWithPath: "/Users/cassie/Library/Application Support/Reach")
        let definition = LaunchAgent.definition(
            executable: "/opt/reach/reachd",
            uid: 501,
            stateDirectory: canonical,
            home: URL(fileURLWithPath: "/Users/cassie")
        )
        let loaded = "state = running\npid = 42\n"
        let invalid = LaunchAgent.status(
            definition: definition,
            installedState: .invalid("REACH_STATE_DIR is relative"),
            installedPath: "/Users/cassie/Library/LaunchAgents/\(LaunchAgent.label).plist",
            launchctlOutput: loaded,
            addresses: [[10, 86, 1, 1], [10, 86, 0, 1, 2]]
        )
        #expect(!invalid.isStateContractValid)
        #expect(invalid.lines.contains { $0.contains("state: invalid") })
        #expect(invalid.lines.contains { $0.contains("agent: state = running") })
        #expect(invalid.lines.contains { $0.contains("mesh road: missing") })

        let divergent = LaunchAgent.status(
            definition: definition,
            installedState: .valid(
                serializedPath: "/private/tmp/other",
                stateDirectory: URL(fileURLWithPath: "/private/tmp/other")
            ),
            installedPath: "/Users/cassie/Library/LaunchAgents/\(LaunchAgent.label).plist",
            launchctlOutput: loaded,
            addresses: [[10, 86, 0, 1]]
        )
        #expect(!divergent.isStateContractValid)
        #expect(divergent.lines.contains { $0.contains("login-owned service requires") })
        #expect(divergent.lines.contains { $0.contains("mesh road: present") })
    }

    @Test func statusAndDoctorShareTheExactReachMeshPredicate() {
        let accepted: [[UInt8]] = [[10, 86, 0, 1], [10, 86, 0, 222]]
        let rejected: [[UInt8]] = [
            [10, 86, 1, 1],
            [10, 87, 0, 1],
            [192, 168, 8, 210],
            [127, 0, 0, 1],
            [10, 86, 0],
            [10, 86, 0, 1, 2],
        ]
        for address in accepted {
            #expect(MeshEndpoint.isReachMeshAddress(address))
        }
        for address in rejected {
            #expect(!MeshEndpoint.isReachMeshAddress(address))
        }

        let definition = LaunchAgent.definition(
            executable: "/opt/reach/reachd",
            uid: 501,
            stateDirectory: URL(fileURLWithPath: "/Users/cassie/Reach")
        )
        let status = LaunchAgent.status(
            definition: definition,
            installedState: .notInstalled,
            installedPath: nil,
            launchctlOutput: nil,
            addresses: rejected
        )
        #expect(status.lines.contains { $0.contains("mesh road: missing") })
        #expect(HostCheck.checkMeshInterface(rejected, daemonUp: true).level == .wait)
        #expect(HostCheck.checkMeshInterface(accepted, daemonUp: true).level == .pass)
    }

    @Test func serviceStatusSeparatesProcessStateFromMeshReadiness() {
        let definition = LaunchAgent.definition(
            executable: "/opt/reach/reachd",
            uid: 501,
            stateDirectory: URL(fileURLWithPath: "/Users/cassie/Reach State", isDirectory: true),
            home: URL(fileURLWithPath: "/Users/cassie", isDirectory: true)
        )
        let loaded = "state = running\npid = 42\n"
        let ready = LaunchAgent.status(
            definition: definition,
            installedState: .valid(
                serializedPath: definition.stateDirectory.path,
                stateDirectory: definition.stateDirectory.standardizedFileURL
            ),
            installedPath: "/Users/cassie/Library/LaunchAgents/\(LaunchAgent.label).plist",
            launchctlOutput: loaded,
            addresses: [[127, 0, 0, 1], [10, 86, 0, 1]]
        )
        #expect(ready.isStateContractValid)
        #expect(ready.lines.contains { $0.contains("login uid 501, domain gui/501") })
        #expect(ready.lines.contains { $0.contains("explicit REACH_STATE_DIR") })
        #expect(ready.lines.contains { $0.contains("agent: state = running") })
        #expect(ready.lines.contains { $0.contains("mesh road: present") && $0.contains("10.86.0.1") })

        let missing = LaunchAgent.status(
            definition: definition,
            installedState: .notInstalled,
            installedPath: nil,
            launchctlOutput: loaded,
            addresses: [[127, 0, 0, 1], [192, 168, 8, 210]]
        )
        #expect(missing.isStateContractValid)
        #expect(missing.lines.contains { $0.contains("expected if installed") })
        #expect(missing.lines.contains { $0.contains("plist: not installed") })
        #expect(missing.lines.contains { $0.contains("mesh road: missing") && $0.contains("away readiness is incomplete") })
    }
}
