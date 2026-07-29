import Foundation

/// Frame type discriminator carried in every envelope.
public enum FrameType: UInt8, Codable, Sendable, CaseIterable {
    // Control stream.
    case hello = 1
    case helloAck = 2
    case sessionOpen = 3
    case sessionOpened = 4
    case sessionResume = 5
    case sessionResumed = 6
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

    // App enrollment (same channel; authorized by a grant ruling, not a token).
    case appEnrollBegin = 35
    case appEnrollCertRequest = 36
    case appEnrollGrant = 37
}

/// A frame that can ride the wire. Bodies are JSON for v0; the envelope is
/// `[u32 BE length][u8 frameType][body]`, where length counts the type byte
/// plus the body.
public protocol WireFrame: Codable, Sendable {
    static var frameType: FrameType { get }
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
}

public enum WireError: Error, Sendable, CustomStringConvertible, LocalizedError {
    case frameTooLarge(UInt32)
    case unknownFrameType(UInt8)
    case malformedFrame(String)
    case unexpectedFrame(FrameType)

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
        }
    }

    public var errorDescription: String? { description }
}

public enum FrameCodec {
    /// Upper bound on a single frame; far beyond text-generation scale, and
    /// a hard stop against nonsense lengths from a broken or hostile peer.
    public static let maxFrameLength: UInt32 = 16 * 1024 * 1024

    public static func encode(_ frame: some WireFrame) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let body = try encoder.encode(frame)
        var out = Data(capacity: 5 + body.count)
        var length = UInt32(1 + body.count).bigEndian
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
