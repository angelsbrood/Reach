import Foundation
import FoundationModels

// MARK: - Control stream

public struct Hello: WireFrame, Equatable {
    public static let frameType = FrameType.hello
    public var versions: [UInt8]
    public var client: String

    public init(versions: [UInt8] = [Wire.version], client: String) {
        self.versions = versions
        self.client = client
    }
}

public struct ModelDescriptor: Codable, Sendable, Equatable {
    public var id: String
    public var displayName: String
    public var capabilities: [String]

    public init(id: String, displayName: String, capabilities: [String]) {
        self.id = id
        self.displayName = displayName
        self.capabilities = capabilities
    }
}

public struct HelloAck: WireFrame, Equatable {
    public static let frameType = FrameType.helloAck
    public var version: UInt8
    public var cluster: String
    public var models: [ModelDescriptor]
    /// Every IPv4 address the daemon answers on — the mesh address included.
    /// A client whose dialed path has died re-dials these as candidates; the
    /// list arrives over the authenticated control stream, so trusting it
    /// adds nothing beyond what mTLS already granted. Optional on the wire:
    /// absent from older daemons.
    public var addrs: [String]?
    /// The session port those addresses answer on.
    public var port: UInt16?

    public init(
        version: UInt8 = Wire.version,
        cluster: String,
        models: [ModelDescriptor],
        addrs: [String]? = nil,
        port: UInt16? = nil
    ) {
        self.version = version
        self.cluster = cluster
        self.models = models
        self.addrs = addrs
        self.port = port
    }
}

public struct SessionOpen: WireFrame, Equatable {
    public static let frameType = FrameType.sessionOpen
    public var modelID: String

    public init(modelID: String) {
        self.modelID = modelID
    }
}

public struct SessionOpened: WireFrame, Equatable {
    public static let frameType = FrameType.sessionOpened
    public var sessionID: UUID
    /// Bearer for re-attach; the daemon stores only its hash.
    public var token: String
    public var capabilities: [String]

    public init(sessionID: UUID, token: String, capabilities: [String]) {
        self.sessionID = sessionID
        self.token = token
        self.capabilities = capabilities
    }
}

public struct SessionResume: WireFrame, Equatable {
    public static let frameType = FrameType.sessionResume

    public struct GenerationCursor: Codable, Sendable, Equatable {
        public var genID: UUID
        public var lastReceivedSeq: UInt64?

        public init(genID: UUID, lastReceivedSeq: UInt64?) {
            self.genID = genID
            self.lastReceivedSeq = lastReceivedSeq
        }
    }

    public var sessionID: UUID
    public var token: String
    public var generations: [GenerationCursor]

    public init(sessionID: UUID, token: String, generations: [GenerationCursor]) {
        self.sessionID = sessionID
        self.token = token
        self.generations = generations
    }
}

public enum WireGenerationState: String, Codable, Sendable, Equatable {
    case streaming
    case complete
    case failed
    case cancelled
    case unknown
}

public struct SessionResumed: WireFrame, Equatable {
    public static let frameType = FrameType.sessionResumed

    public struct GenerationStatus: Codable, Sendable, Equatable {
        public var genID: UUID
        public var state: WireGenerationState
        public var finalSeq: UInt64?

        public init(genID: UUID, state: WireGenerationState, finalSeq: UInt64? = nil) {
            self.genID = genID
            self.state = state
            self.finalSeq = finalSeq
        }
    }

    public var generations: [GenerationStatus]

    public init(generations: [GenerationStatus]) {
        self.generations = generations
    }
}

public struct Ping: WireFrame, Equatable {
    public static let frameType = FrameType.ping
    public var nonce: UInt64

    public init(nonce: UInt64) {
        self.nonce = nonce
    }
}

public struct Pong: WireFrame, Equatable {
    public static let frameType = FrameType.pong
    public var nonce: UInt64

    public init(nonce: UInt64) {
        self.nonce = nonce
    }
}

public struct ErrorFrame: WireFrame, Equatable {
    public static let frameType = FrameType.errorFrame
    public var code: String
    public var message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }
}

// MARK: - Grants (ruled from the keeper; minimal shape for the ceremony)

public struct GrantSubscribe: WireFrame, Equatable {
    public static let frameType = FrameType.grantSubscribe

    public init() {}
}

public struct GrantEvent: WireFrame, Equatable {
    public static let frameType = FrameType.grantEvent
    public var requestID: UUID
    /// Observed provenance of the request (remote address, upgraded to the
    /// enrolled device when the registry can bind it) — shown on the
    /// sheet as context, never treated as proof.
    public var deviceID: String
    public var bundleID: String
    /// What the app calls itself — sheet copy, same trust class as the
    /// bundle identity (TOFU until App Attest, the named stub).
    public var displayName: String
    public var appKeyFingerprint: String

    public init(requestID: UUID, deviceID: String, bundleID: String, displayName: String, appKeyFingerprint: String) {
        self.requestID = requestID
        self.deviceID = deviceID
        self.bundleID = bundleID
        self.displayName = displayName
        self.appKeyFingerprint = appKeyFingerprint
    }
}

public struct GrantRule: WireFrame, Equatable {
    public static let frameType = FrameType.grantRule
    public var requestID: UUID
    public var allow: Bool

    public init(requestID: UUID, allow: Bool) {
        self.requestID = requestID
        self.allow = allow
    }
}

// MARK: - Generation streams

public struct GenerateBegin: WireFrame {
    public static let frameType = FrameType.generateBegin
    public var sessionID: UUID
    public var genID: UUID
    public var request: WireGenerationRequest

    public init(sessionID: UUID, genID: UUID, request: WireGenerationRequest) {
        self.sessionID = sessionID
        self.genID = genID
        self.request = request
    }
}

public struct GenerateReattach: WireFrame, Equatable {
    public static let frameType = FrameType.generateReattach
    public var sessionID: UUID
    public var token: String
    public var genID: UUID
    public var fromSeq: UInt64

    public init(sessionID: UUID, token: String, genID: UUID, fromSeq: UInt64) {
        self.sessionID = sessionID
        self.token = token
        self.genID = genID
        self.fromSeq = fromSeq
    }
}

public struct GenerateCancel: WireFrame, Equatable {
    public static let frameType = FrameType.generateCancel
    public var genID: UUID

    public init(genID: UUID) {
        self.genID = genID
    }
}

public struct EvAck: WireFrame, Equatable {
    public static let frameType = FrameType.evAck
    /// Cumulative: everything at or below this sequence is received.
    public var seq: UInt64

    public init(seq: UInt64) {
        self.seq = seq
    }
}

public struct Ev: WireFrame, Equatable {
    public static let frameType = FrameType.ev
    public var seq: UInt64
    public var event: WireEvent

    public init(seq: UInt64, event: WireEvent) {
        self.seq = seq
        self.event = event
    }
}

// MARK: - Enrollment (the ceremony)

public struct EnrollBegin: WireFrame, Equatable {
    public static let frameType = FrameType.enrollBegin
    public var token: String
    public var deviceName: String

    public init(token: String, deviceName: String) {
        self.token = token
        self.deviceName = deviceName
    }
}

public struct EnrollChallenge: WireFrame, Equatable {
    public static let frameType = FrameType.enrollChallenge
    public var nonce: Data

    public init(nonce: Data) {
        self.nonce = nonce
    }
}

public struct EnrollCertRequest: WireFrame, Equatable {
    public static let frameType = FrameType.enrollCertRequest
    /// SecureEnclave P-256 public key, DER (X9.63 via SecKeyCopyExternalRepresentation is bridged daemon-side).
    public var devicePubDER: Data
    /// Curve25519 WireGuard public key, raw 32 bytes.
    public var wgPubKey: Data
    /// Proof of possession: SE signature over `nonce ‖ devicePubDER ‖ wgPubKey`
    /// — one signature binds both keys in one gesture.
    public var popSig: Data

    public init(devicePubDER: Data, wgPubKey: Data, popSig: Data) {
        self.devicePubDER = devicePubDER
        self.wgPubKey = wgPubKey
        self.popSig = popSig
    }
}

public struct WGProvision: Codable, Sendable, Equatable {
    public var assignedIP: String
    public var serverPublicKey: Data
    public var endpoint: String
    public var allowedIPs: [String]
    public var keepaliveSeconds: Int

    public init(assignedIP: String, serverPublicKey: Data, endpoint: String, allowedIPs: [String], keepaliveSeconds: Int) {
        self.assignedIP = assignedIP
        self.serverPublicKey = serverPublicKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.keepaliveSeconds = keepaliveSeconds
    }
}

public struct EnrollGrant: WireFrame, Equatable {
    public static let frameType = FrameType.enrollGrant
    public var deviceCertDER: Data
    public var caCertDER: Data
    public var wg: WGProvision

    public init(deviceCertDER: Data, caCertDER: Data, wg: WGProvision) {
        self.deviceCertDER = deviceCertDER
        self.caCertDER = caCertDER
        self.wg = wg
    }
}

public struct EnrollComplete: WireFrame, Equatable {
    public static let frameType = FrameType.enrollComplete
    public var ok: Bool

    public init(ok: Bool) {
        self.ok = ok
    }
}

// MARK: - App enrollment (the grant sheet's wire half)

/// An app asking to use the cluster. No token: authorization is a human
/// ruling on the keeper, delivered while this stream waits parked.
public struct AppEnrollBegin: WireFrame, Equatable {
    public static let frameType = FrameType.appEnrollBegin
    public var bundleID: String
    public var displayName: String

    public init(bundleID: String, displayName: String) {
        self.bundleID = bundleID
        self.displayName = displayName
    }
}

/// The app's key and its proof of possession over `nonce ‖ appPubX963`.
/// One key only — apps do not join the mesh; they ride the device's.
public struct AppEnrollCertRequest: WireFrame, Equatable {
    public static let frameType = FrameType.appEnrollCertRequest
    /// P-256 public key, X9.63. Software-backed in v0 (the named stub);
    /// Secure Enclave app keys are funded scope.
    public var appPubX963: Data
    public var popSig: Data

    public init(appPubX963: Data, popSig: Data) {
        self.appPubX963 = appPubX963
        self.popSig = popSig
    }
}

/// The ruled grant: an app-scoped certificate and the issuing CA. The URI
/// SAN reads `reach://app/<device>/<bundleID>`, where `<device>` is the
/// RULING device — the authority the grant hangs from, which in v0 IS the
/// binding (attestation stubbed as local approval, per the named stubs).
public struct AppEnrollGrant: WireFrame, Equatable {
    public static let frameType = FrameType.appEnrollGrant
    public var appCertDER: Data
    public var caCertDER: Data

    public init(appCertDER: Data, caCertDER: Data) {
        self.appCertDER = appCertDER
        self.caCertDER = caCertDER
    }
}
