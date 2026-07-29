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
/// EnrollGrant → EnrollComplete. Mutual authentication is asymmetric by
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

    /// Serves one enrollment stream to completion. The first frame decides
    /// which ceremony this is: a device (token-authorized) or an app
    /// (grant-authorized, parked for the keeper's ruling).
    public func serve(stream: ReachTransport.QUICStream) async {
        var iterator = stream.frames.makeAsyncIterator()
        do {
            guard let first = try await iterator.next() else { return }
            switch first.type {
            case .enrollBegin:
                try await serveDevice(begin: try first.decode(EnrollBegin.self), stream: stream, iterator: &iterator)
            case .appEnrollBegin:
                try await serveApp(begin: try first.decode(AppEnrollBegin.self), stream: stream, iterator: &iterator)
            default:
                try await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected EnrollBegin or AppEnrollBegin"))
                stream.cancel()
            }
        } catch {
            Log.error("enrollment stream failed: \(error)")
            stream.cancel()
        }
    }

    private func serveDevice(
        begin: EnrollBegin,
        stream: ReachTransport.QUICStream,
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator
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
            ))
            stream.cancel()
            return
        }

        // Where this device will be told to find the mesh, settled before
        // anything is minted. A grant nobody can act on is worse than a
        // refusal, and refusing here leaves no half-enrolled device, no
        // issued certificate and no peer block behind — though note the token
        // above is already spent, so this refusal costs a fresh `reachd pair`.
        let endpoint: String
        do {
            endpoint = try wgHost.currentEndpoint()
        } catch {
            Log.error("enrollment refused — no mesh endpoint: \(error)")
            try await stream.send(ErrorFrame(code: "enroll-endpoint", message: "\(error)"))
            stream.cancel()
            return
        }

        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try await stream.send(EnrollChallenge(nonce: nonce))

        guard let requestRaw = try await iterator.next(), requestRaw.type == .enrollCertRequest else {
            try await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected EnrollCertRequest"))
            stream.cancel()
            return
        }
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
            try await stream.send(ErrorFrame(code: "enroll-pop", message: "proof of possession failed"))
            stream.cancel()
            return
        }

        let record = try await devices.enroll(name: begin.deviceName, devicePubX963: request.devicePubDER, wgPub: request.wgPubKey)
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
        ))

        guard let completeRaw = try await iterator.next(), completeRaw.type == .enrollComplete else {
            stream.cancel()
            return
        }
        _ = try completeRaw.decode(EnrollComplete.self)
        await devices.activate(record.id)
        // The peer waits until the device has confirmed it holds the grant.
        // Admitting it earlier meant a re-pair that failed after the grant
        // had already evicted the block the phone was using — two peers must
        // never claim one /32, so installing the new key deletes the old one,
        // and a device that never completed then has no working mesh and no
        // way back to the one it had. Nothing in the grant depends on this
        // having run: it carries the host's public key and the assigned
        // address, both known well before here.
        try await wgHost.addPeer(publicKey: request.wgPubKey, allowedIP: record.assignedIP)
        // The endpoint is logged because it is the one thing in the grant
        // that cannot be re-derived later: the phone carries it into its
        // tunnel config, and this line is the record of what it was told.
        Log.info("device enrolled: \(begin.deviceName) → \(record.assignedIP)\(record.admin ? " (admin)" : ""), mesh endpoint \(endpoint)")
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
        iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator
    ) async throws {
        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        try await stream.send(EnrollChallenge(nonce: nonce))

        guard let requestRaw = try await iterator.next(), requestRaw.type == .appEnrollCertRequest else {
            try await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected AppEnrollCertRequest"))
            stream.cancel()
            return
        }
        let request = try requestRaw.decode(AppEnrollCertRequest.self)

        let signed = nonce + request.appPubX963
        guard
            let publicKey = try? P256.Signing.PublicKey(x963Representation: request.appPubX963),
            let signature = try? P256.Signing.ECDSASignature(derRepresentation: request.popSig),
            publicKey.isValidSignature(signature, for: signed)
        else {
            try await stream.send(ErrorFrame(code: "enroll-pop", message: "proof of possession failed"))
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
            try await stream.send(ErrorFrame(code: "grant-denied", message: "the keeper refused"))
            await desk.collected(fingerprint)
            stream.cancel()
        case .timedOut:
            try await stream.send(ErrorFrame(code: "grant-timeout", message: "no ruling within the window"))
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
            ))
            guard let completeRaw = try await iterator.next(), completeRaw.type == .enrollComplete else {
                stream.cancel()
                return
            }
            _ = try completeRaw.decode(EnrollComplete.self)
            // Only a confirmed delivery clears the held verdict — anything
            // short of EnrollComplete leaves it for the app's next knock.
            await desk.collected(fingerprint)
            Log.info("app enrolled: \(begin.bundleID), granted under device \(ruler.uuidString.lowercased())")
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

    public func enroll(name: String, devicePubX963: Data, wgPub: Data) throws -> Device {
        // The Secure Enclave key IS the device: a re-pair arrives with the
        // same device key and a fresh wg key, and keeps its identity —
        // id, address, and the admin grant. (The wg key can never match
        // across scans; it is minted per ceremony and never persisted.)
        if let existing = devices.firstIndex(where: { $0.devicePubX963 == devicePubX963 }) {
            devices[existing].name = name
            devices[existing].wgPub = wgPub
            persist()
            return devices[existing]
        }
        let host = 2 + devices.count
        let device = Device(
            id: UUID(),
            name: name,
            devicePubX963: devicePubX963,
            wgPub: wgPub,
            assignedIP: "10.86.0.\(host)",
            admin: devices.isEmpty,
            active: false,
            enrolledAt: Date()
        )
        devices.append(device)
        persist()
        return device
    }

    public func activate(_ id: UUID) {
        if let index = devices.firstIndex(where: { $0.id == id }) {
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

/// The Mac end of the mesh, as reachd manages it in the pre-LaunchDaemon
/// window: keys and the wg-quick config live under the state paths; new
/// peers append to the config, and applying it is the operator's one
/// visible sudo (`wg-quick down/up reach0` or `wg syncconf`).
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

    private let confURL: URL

    public nonisolated func currentEndpoint() throws -> String {
        try endpointResolver()
    }

    public init(
        keysDirectory: URL = DaemonInfo.stateDirectory.appendingPathComponent("wg", isDirectory: true),
        confPath: String = HostCheck.defaultWireGuardConf,
        endpoint: @escaping @Sendable () throws -> String
    ) throws {
        confURL = URL(fileURLWithPath: confPath)
        let fm = FileManager.default
        let pubURL = keysDirectory.appendingPathComponent("server.pub")
        let keyURL = keysDirectory.appendingPathComponent("server.key")
        if !fm.fileExists(atPath: pubURL.path) {
            // Fresh host: mint the mesh keypair and the interface skeleton.
            try fm.createDirectory(at: keysDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let key = Curve25519.KeyAgreement.PrivateKey()
            try key.rawRepresentation.base64EncodedString().write(to: keyURL, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
            try key.publicKey.rawRepresentation.base64EncodedString().write(to: pubURL, atomically: true, encoding: .utf8)
            if !fm.fileExists(atPath: confPath) {
                try? fm.createDirectory(atPath: (confPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                let skeleton = """
                [Interface]
                PrivateKey = \(key.rawRepresentation.base64EncodedString())
                Address = 10.86.0.1/24
                ListenPort = 51820

                """
                try skeleton.write(toFile: confPath, atomically: true, encoding: .utf8)
                try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: confPath)
            }
        }
        let pubText = try String(contentsOf: pubURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let pub = Data(base64Encoded: pubText), pub.count == 32 else {
            throw CAError.stateMissing("server.pub")
        }
        serverPublicKey = pub
        endpointResolver = endpoint
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

    /// Installs the peer: idempotent when the key is already present, and
    /// a re-paired device's fresh key REPLACES the stale block holding its
    /// address (two peers must never claim one /32). Returns whether the
    /// config changed (the operator then applies it).
    @discardableResult
    public func addPeer(publicKey: Data, allowedIP: String) throws -> Bool {
        let base64 = publicKey.base64EncodedString()
        // Absent and unreadable are different answers, and collapsing them
        // was the same mistake `DaemonConfig.load` used to make — left in
        // place here for the one other file the operator edits by hand. An
        // unreadable conf read as "" makes the rewrite below emit a bare
        // [Peer] block with no [Interface], so the host's own key line is
        // destroyed by a pairing that reports success. Refuse instead, and
        // name the file; `init` is what creates a missing one, not this.
        let text: String
        if FileManager.default.fileExists(atPath: confURL.path) {
            do {
                text = try String(contentsOf: confURL, encoding: .utf8)
            } catch {
                throw CAError.stateMissing("\(confURL.path) exists but will not read: \(error)")
            }
        } else {
            text = ""
        }
        guard !text.contains(base64) else { return false }
        var chunks = text.components(separatedBy: "[Peer]")
        let head = chunks.removeFirst()
        let kept = chunks.filter { !$0.contains("AllowedIPs = \(allowedIP)/32") }
        var out = head + kept.map { "[Peer]" + $0 }.joined()
        if !out.hasSuffix("\n") { out += "\n" }
        out += """

        [Peer]
        # enrolled \(ISO8601DateFormatter().string(from: Date()))
        PublicKey = \(base64)
        AllowedIPs = \(allowedIP)/32

        """
        try out.write(to: confURL, atomically: true, encoding: .utf8)
        Log.info("wg peer installed — apply with: sudo /opt/homebrew/bin/wg-quick down reach0 && sudo /opt/homebrew/bin/wg-quick up reach0")
        return true
    }
}
