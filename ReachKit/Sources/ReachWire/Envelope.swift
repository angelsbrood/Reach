import Foundation

/// Frame type discriminator carried in every envelope.
public enum FrameType: UInt8, Codable, Sendable, CaseIterable {
    // Control stream.
    case hello = 1
    case helloAck = 2
    case sessionOpen = 3
    case sessionOpened = 4
    // 5 and 6 were `SessionResume`/`SessionResumed` and are reserved rather
    // than reused. Nothing ever sent one: the frames, their per-generation
    // cursors and `WireGenerationState.unknown` were daemon-side only, and
    // `SessionResumed.finalSeq` was off by one against the Ev sequence space
    // — a cursor no client could have resumed from, which is how we know none
    // ever tried. `GenerateReattach` does the whole job in one trip.
    // Renumbering would make a v0 daemon read a new frame as a resume.
    case grantSubscribe = 7
    case grantEvent = 8
    case grantRule = 9
    case ping = 10
    case pong = 11
    case errorFrame = 12

    // Generation streams (one bidirectional stream per generation).
    case generateBegin = 20
    case generateReattach = 21
    case generateCancel = 22
    case evAck = 23
    case ev = 24

    // Enrollment (the ceremony's channel, server-auth-only TLS).
    case enrollBegin = 30
    case enrollChallenge = 31
    case enrollCertRequest = 32
    case enrollGrant = 33
    case enrollComplete = 34
    case enrollConfirmed = 35

    // App enrollment (same channel; authorized by a grant ruling, not a token).
    // Moved off 35–37 when the device ceremony grew its sixth frame: the bands
    // are documented as growable without renumbering their neighbours, and the
    // device band was flush against this one, so the claim was true only until
    // it was tested. Renumbering costs nothing — the raw values are read in
    // exactly two places, both in this file, and nothing on disk carries a
    // type byte.
    case appEnrollBegin = 40
    case appEnrollCertRequest = 41
    case appEnrollGrant = 42

    /// The first dialect that may send this type. Exhaustive on purpose: a
    /// future enum case cannot compile until its compatibility gate is named.
    public var introducedInVersion: UInt8 {
        switch self {
        case .hello, .helloAck, .sessionOpen, .sessionOpened,
             .grantSubscribe, .grantEvent, .grantRule, .ping, .pong, .errorFrame,
             .generateBegin, .generateReattach, .generateCancel, .evAck, .ev,
             .enrollBegin, .enrollChallenge, .enrollCertRequest, .enrollGrant,
             .enrollComplete, .enrollConfirmed, .appEnrollBegin,
             .appEnrollCertRequest, .appEnrollGrant:
            Wire.baselineVersion
        }
    }
}

/// A frame that can ride the wire. Bodies are JSON for v0; the envelope is
/// `[u32 BE length][u8 frameType][body]`, where length counts the type byte
/// plus the body.
public protocol WireFrame: Codable, Sendable {
    static var frameType: FrameType { get }
    static var introducedInVersion: UInt8 { get }
}

public extension WireFrame {
    static var introducedInVersion: UInt8 { frameType.introducedInVersion }
}

/// A frame as read off the wire, before its body is decoded.
public struct RawFrame: Sendable {
    public let type: FrameType
    public let body: Data

    public init(type: FrameType, body: Data) {
        self.type = type
        self.body = body
    }

    public func decode<F: WireFrame>(_ as: F.Type = F.self) throws -> F {
        guard F.frameType == type else { throw WireError.unexpectedFrame(type) }
        do {
            return try JSONDecoder().decode(F.self, from: body)
        } catch {
            throw WireError.malformedFrame("\(type): \(error)")
        }
    }

    /// A peer may know a frame type in source and still have negotiated an
    /// older dialect that is not allowed to receive it.
    public func requireSupported(by version: UInt8) throws {
        try WireError.require(type: type, negotiatedVersion: version)
    }
}

public enum WireError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case frameTooLarge(UInt32)
    case unknownFrameType(UInt8)
    case malformedFrame(String)
    case unexpectedFrame(FrameType)
    case frameRequiresVersion(type: FrameType, introduced: UInt8, negotiated: UInt8)

    public var description: String {
        switch self {
        case .frameTooLarge(let bytes):
            "a frame declared \(bytes) bytes, past the 16 MiB cap"
        case .unknownFrameType(let type):
            "frame type \(type) is not in this protocol version's vocabulary"
        case .malformedFrame(let detail):
            "a frame did not decode: \(detail)"
        case .unexpectedFrame(let type):
            "received \(type) where the exchange expected something else"
        case .frameRequiresVersion(let type, let introduced, let negotiated):
            "\(type) belongs to protocol generation \(introduced), but this exchange negotiated generation \(negotiated)"
        }
    }

    public var errorDescription: String? { description }

    public static func require(type: FrameType, negotiatedVersion: UInt8) throws {
        try require(
            type: type,
            introducedInVersion: type.introducedInVersion,
            negotiatedVersion: negotiatedVersion
        )
    }

    public static func require(
        type: FrameType,
        introducedInVersion: UInt8,
        negotiatedVersion: UInt8
    ) throws {
        guard introducedInVersion <= negotiatedVersion else {
            throw WireError.frameRequiresVersion(
                type: type,
                introduced: introducedInVersion,
                negotiated: negotiatedVersion
            )
        }
    }
}

public enum FrameCodec {
    /// Upper bound on a single frame; far beyond text-generation scale, and
    /// a hard stop against nonsense lengths from a broken or hostile peer.
    public static let maxFrameLength: UInt32 = 16 * 1024 * 1024

    public static func encode(
        _ frame: some WireFrame,
        for negotiatedVersion: UInt8 = Wire.baselineVersion
    ) throws -> Data {
        try WireError.require(
            type: type(of: frame).frameType,
            introducedInVersion: type(of: frame).introducedInVersion,
            negotiatedVersion: negotiatedVersion
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let body = try encoder.encode(frame)
        let (frameLength, overflow) = body.count.addingReportingOverflow(1)
        guard !overflow, frameLength <= Int(maxFrameLength) else {
            throw WireError.frameTooLarge(overflow ? .max : UInt32(clamping: frameLength))
        }
        var out = Data(capacity: 4 + frameLength)
        var length = UInt32(frameLength).bigEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(type(of: frame).frameType.rawValue)
        out.append(body)
        return out
    }
}

/// Incremental reassembler: feed arbitrary chunks from the stream, get whole
/// frames out. One per stream direction.
public struct FrameReassembler: Sendable {
    private var buffer = Data()

    public init() {}

    public mutating func feed(_ data: Data) throws -> [RawFrame] {
        buffer.append(data)
        var frames: [RawFrame] = []
        while true {
            guard buffer.count >= 5 else { break }
            let length = buffer.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            guard length >= 1 else { throw WireError.malformedFrame("zero-length frame") }
            guard length <= FrameCodec.maxFrameLength else { throw WireError.frameTooLarge(length) }
            guard buffer.count >= 4 + Int(length) else { break }
            let typeByte = buffer[buffer.index(buffer.startIndex, offsetBy: 4)]
            guard let type = FrameType(rawValue: typeByte) else {
                throw WireError.unknownFrameType(typeByte)
            }
            let bodyStart = buffer.index(buffer.startIndex, offsetBy: 5)
            let bodyEnd = buffer.index(buffer.startIndex, offsetBy: 4 + Int(length))
            frames.append(RawFrame(type: type, body: Data(buffer[bodyStart..<bodyEnd])))
            buffer.removeSubrange(buffer.startIndex..<bodyEnd)
        }
        return frames
    }
}
