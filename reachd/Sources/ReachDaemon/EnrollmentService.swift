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
/// key in a single gesture.
public actor EnrollmentService {
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

    public init(ca: ClusterCA, tokens: TokenStore, devices: DeviceRegistry, wgHost: WireGuardHost) {
        self.ca = ca
        self.tokens = tokens
        self.devices = devices
        self.wgHost = wgHost
    }

    /// Serves one enrollment stream to completion.
    public func serve(stream: ReachTransport.QUICStream) async {
        var iterator = stream.frames.makeAsyncIterator()
        do {
            guard let beginRaw = try await iterator.next(), beginRaw.type == .enrollBegin else {
                try await stream.send(ErrorFrame(code: "enroll-sequence", message: "expected EnrollBegin"))
                stream.cancel()
                return
            }
            let begin = try beginRaw.decode(EnrollBegin.self)
            guard tokens.consume(begin.token) else {
                try await stream.send(ErrorFrame(code: "enroll-token", message: "invalid or expired token"))
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
            let certificate = try ca.issueDevice(
                publicKeyX963: request.devicePubDER,
                commonName: begin.deviceName,
                uri: "reach://device/\(record.id.uuidString.lowercased())"
            )
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)

            try await wgHost.addPeer(publicKey: request.wgPubKey, allowedIP: record.assignedIP)
            try await stream.send(EnrollGrant(
                deviceCertDER: Data(serializer.serializedBytes),
                caCertDER: try ca.certificateDER(),
                wg: WGProvision(
                    assignedIP: "\(record.assignedIP)/24",
                    serverPublicKey: wgHost.serverPublicKey,
                    endpoint: wgHost.pinnedEndpoint,
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
            Log.info("device enrolled: \(begin.deviceName) → \(record.assignedIP)\(record.admin ? " (admin)" : "")")
            stream.finishSending()
        } catch {
            Log.error("enrollment stream failed: \(error)")
            stream.cancel()
        }
    }
}

/// One-time enrollment tokens, file-backed so `reachd pair` (a separate
/// process) can mint what `reachd serve` validates. Hashes only; 10-minute
/// TTL; consumed on first presentation.
public struct TokenStore: Sendable {
    private let url: URL

    public init(directory: URL = DaemonInfo.stateDirectory) {
        url = directory.appendingPathComponent("enroll-tokens.json")
    }

    private struct Entry: Codable {
        var hash: Data
        var expires: Date
    }

    private func load() -> [Entry] {
        guard let data = try? Data(contentsOf: url),
              let entries = try? JSONDecoder().decode([Entry].self, from: data) else { return [] }
        return entries.filter { $0.expires > Date() }
    }

    private func save(_ entries: [Entry]) {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let data = try? JSONEncoder().encode(entries) {
            try? data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }

    public func mint(ttl: TimeInterval = 600) -> String {
        var bytes = Data(count: 32)
        bytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let token = bytes.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        var entries = load()
        entries.append(Entry(hash: Data(SHA256.hash(data: Data(token.utf8))), expires: Date().addingTimeInterval(ttl)))
        save(entries)
        return token
    }

    public func consume(_ token: String) -> Bool {
        let hash = Data(SHA256.hash(data: Data(token.utf8)))
        var entries = load()
        guard let index = entries.firstIndex(where: { $0.hash == hash }) else { return false }
        entries.remove(at: index)
        save(entries)
        return true
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
        // Re-enrollment of a known wg key keeps its address.
        if let existing = devices.firstIndex(where: { $0.wgPub == wgPub }) {
            devices[existing].name = name
            devices[existing].devicePubX963 = devicePubX963
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
    public nonisolated let pinnedEndpoint: String

    private let confURL: URL

    public init(
        keysDirectory: URL = DaemonInfo.stateDirectory.appendingPathComponent("wg", isDirectory: true),
        confPath: String = "/opt/homebrew/etc/wireguard/reach0.conf",
        endpoint: String
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
        pinnedEndpoint = endpoint
    }

    /// Appends the peer if its key is new; idempotent otherwise. Returns
    /// whether the config changed (the operator then applies it).
    @discardableResult
    public func addPeer(publicKey: Data, allowedIP: String) throws -> Bool {
        let base64 = publicKey.base64EncodedString()
        var text = (try? String(contentsOf: confURL, encoding: .utf8)) ?? ""
        guard !text.contains(base64) else { return false }
        text += """

        [Peer]
        # enrolled \(ISO8601DateFormatter().string(from: Date()))
        PublicKey = \(base64)
        AllowedIPs = \(allowedIP)/32

        """
        try text.write(to: confURL, atomically: true, encoding: .utf8)
        Log.info("wg peer appended — apply with: sudo /opt/homebrew/bin/wg-quick down reach0 && sudo /opt/homebrew/bin/wg-quick up reach0")
        return true
    }
}
