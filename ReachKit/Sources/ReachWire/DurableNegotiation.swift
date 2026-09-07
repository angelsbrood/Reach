import Foundation

/// A typed vocabulary, not a transport dispatcher or an authorization result.
public enum DurableMessage: Sendable {
    case capabilities(DurableCapabilities), open(DurableSessionOpen), opened(DurableSessionOpened)
    case begin(DurableGenerateBegin), accepted(DurableGenerationAccepted), recover(DurableGenerateRecover)
    case batch(DurableBatch), receipt(DurableReceipt), receiptAccepted(DurableReceiptAccepted)
    case knowledge(DurableToolKnowledge), refused(DurableRefused)

    public var frameType: FrameType {
        switch self {
        case .capabilities: .durableCapabilities
        case .open: .durableSessionOpen
        case .opened: .durableSessionOpened
        case .begin: .durableGenerateBegin
        case .accepted: .durableGenerationAccepted
        case .recover: .durableGenerateRecover
        case .batch: .durableBatch
        case .receipt: .durableReceipt
        case .receiptAccepted: .durableReceiptAccepted
        case .knowledge: .durableToolKnowledge
        case .refused: .durableRefused
        }
    }

    /// Default encoding remains dialect zero and therefore refuses this entire band.
    public func encode(version: UInt8 = Wire.baselineVersion) throws -> Data {
        switch self {
        case .capabilities(let f): try FrameCodec.encode(f, for: version)
        case .open(let f): try FrameCodec.encode(f, for: version)
        case .opened(let f): try FrameCodec.encode(f, for: version)
        case .begin(let f): try FrameCodec.encode(f, for: version)
        case .accepted(let f): try FrameCodec.encode(f, for: version)
        case .recover(let f): try FrameCodec.encode(f, for: version)
        case .batch(let f): try FrameCodec.encode(f, for: version)
        case .receipt(let f): try FrameCodec.encode(f, for: version)
        case .receiptAccepted(let f): try FrameCodec.encode(f, for: version)
        case .knowledge(let f): try FrameCodec.encode(f, for: version)
        case .refused(let f): try FrameCodec.encode(f, for: version)
        }
    }

    /// Always gate before body decoding. A decoded message still proves only syntax.
    public static func decode(_ raw: RawFrame, version: UInt8 = Wire.baselineVersion) throws -> Self {
        try raw.requireSupported(by: version)
        switch raw.type {
        case .durableCapabilities: return .capabilities(try raw.decode())
        case .durableSessionOpen: return .open(try raw.decode())
        case .durableSessionOpened: return .opened(try raw.decode())
        case .durableGenerateBegin: return .begin(try raw.decode())
        case .durableGenerationAccepted: return .accepted(try raw.decode())
        case .durableGenerateRecover: return .recover(try raw.decode())
        case .durableBatch: return .batch(try raw.decode())
        case .durableReceipt: return .receipt(try raw.decode())
        case .durableReceiptAccepted: return .receiptAccepted(try raw.decode())
        case .durableToolKnowledge: return .knowledge(try raw.decode())
        case .durableRefused: return .refused(try raw.decode())
        default: throw WireError.unexpectedFrame(raw.type)
        }
    }
}

/// Pure requester-side state for ONE selected session/generation exchange.
/// `accepted` means correlated protocol selection only: no MAC, caller, store,
/// clock, prefix history or effect permission is verified here. A future adapter
/// must verify current trusted state before acting. This type has no callbacks,
/// provider, clock, identity generator, fallback, renewal or retry mechanism.
public struct DurableNegotiation: Sendable {
    public enum Phase: Sendable, Equatable { case volatile, declared, opening, selected, beginning, recovering, accepted, refused }
    public let selectedDialect: UInt8
    public let modelID: String
    public let localOptIn: Bool
    public private(set) var phase: Phase = .volatile
    public private(set) var refusal: DurableRefusalReason?
    private var profiles: [String]?
    private var opening: DurableSessionOpenPayload?
    private var session: Selection?
    private var pending: PendingGeneration?
    private var generation: DurableGenerationAcceptedPayload?
    private var clientRoot: String?
    private var receipt: DurableReceiptPayload?

    private struct Selection: Sendable {
        var session: DurableSessionReference
        var ticket: Data
    }
    private struct PendingGeneration: Sendable {
        var requestID: String
        var reference: DurableGenerationReference
        var kind: DurableAcceptanceKind
        var originalContext: Data?
        var originalContextDigest: String?
        var clientRoot: String?
        var originalTicket: Data?
    }

    public init(selectedDialect: UInt8 = Wire.baselineVersion, modelID: String, localOptIn: Bool = false) throws {
        try DurableWire.identifier(modelID)
        self.selectedDialect = selectedDialect
        self.modelID = modelID
        self.localOptIn = localOptIn
    }

    /// Observing an ordinary open always discards durable selection, even at v2.
    public mutating func observeVolatileOpen(_ open: SessionOpen) {
        phase = .volatile; opening = nil; session = nil; pending = nil
        generation = nil; clientRoot = nil; receipt = nil; refusal = nil
        profiles = nil
    }

    /// Requests alone cannot establish acceptance. Failed sends do not mutate state.
    public mutating func send(_ message: DurableMessage) throws -> Data {
        let bytes = try message.encode(version: selectedDialect)
        var next = self
        try next.advance(message, incoming: false)
        self = next
        return bytes
    }

    /// Dialect gating precedes all body decoding and state dispatch.
    /// A correlated refusal is returned as `.refused` and closes this exchange.
    public mutating func receive(_ raw: RawFrame) throws -> DurableMessage {
        let message = try DurableMessage.decode(raw, version: selectedDialect)
        var next = self
        try next.advance(message, incoming: true)
        self = next
        return message
    }

    private func requireSelection(_ reference: DurableGenerationReference, ticket: Data) throws {
        guard let session, ticket == session.ticket,
              try DurableWire.same(reference.session, session.session) else { throw DurableWireError.notAccepted }
    }

    private func requireGeneration(_ reference: DurableGenerationReference, context: String) throws {
        guard phase == .accepted, let generation,
              try DurableWire.same(reference, generation.reference),
              DurableWire.exact(context, generation.contextDigest) else { throw DurableWireError.notAccepted }
    }

    private mutating func advance(_ message: DurableMessage, incoming: Bool) throws {
        guard phase != .refused else { throw DurableWireError.notAccepted }
        switch message {
        case .capabilities(let frame):
            guard incoming, session == nil, opening == nil, pending == nil else { throw DurableWireError.correlation }
            guard DurableWire.exact(frame.payload.modelID, modelID) else { throw DurableWireError.incompatible }
            profiles = frame.payload.profiles
            phase = .declared
        case .open(let frame):
            guard !incoming, session == nil, opening == nil, pending == nil else { throw DurableWireError.correlation }
            guard localOptIn else { throw DurableWireError.localOptOut }
            guard DurableWire.exact(frame.payload.modelID, modelID), frame.payload.profile == DurableWire.profile else { throw DurableWireError.incompatible }
            guard profiles?.contains(DurableWire.profile) == true else { throw DurableWireError.unavailable }
            opening = frame.payload
            phase = .opening
        case .opened(let frame):
            let p = frame.payload
            guard incoming, localOptIn, phase == .opening, let opening,
                  profiles?.contains(DurableWire.profile) == true,
                  DurableWire.exact(p.requestID, opening.requestID),
                  DurableWire.exact(p.session.modelID, opening.modelID),
                  DurableWire.exact(p.session.profile, opening.profile) else { throw DurableWireError.correlation }
            session = Selection(session: p.session, ticket: p.ticket); self.opening = nil; phase = .selected
        case .begin(let frame):
            let p = frame.payload
            guard !incoming, phase == .selected, pending == nil, generation == nil else { throw DurableWireError.notAccepted }
            try requireSelection(p.reference, ticket: p.ticket)
            pending = PendingGeneration(requestID: p.requestID, reference: p.reference, kind: .begin)
            phase = .beginning
        case .recover(let frame):
            let p = frame.payload
            guard !incoming, [.declared, .selected, .accepted].contains(phase), pending == nil, opening == nil, receipt == nil else { throw DurableWireError.notAccepted }
            if session == nil {
                // Selected disk state supplies original credentials. This is only
                // a pending request; no replacement open or synthetic acceptance.
                guard localOptIn else { throw DurableWireError.localOptOut }
                guard DurableWire.exact(p.reference.session.modelID, modelID), p.reference.session.profile == DurableWire.profile else { throw DurableWireError.incompatible }
                guard profiles?.contains(DurableWire.profile) == true else { throw DurableWireError.unavailable }
            } else { try requireSelection(p.reference, ticket: p.ticket) }
            if let generation {
                try requireGeneration(p.reference, context: p.contextDigest)
                guard generation.context == p.context else { throw DurableWireError.correlation }
            }
            if let clientRoot, clientRoot != p.clientRoot { throw DurableWireError.correlation }
            pending = PendingGeneration(requestID: p.requestID, reference: p.reference, kind: .recover,
                                        originalContext: p.context, originalContextDigest: p.contextDigest, clientRoot: p.clientRoot,
                                        originalTicket: p.ticket)
            phase = .recovering
        case .accepted(let frame):
            let p = frame.payload
            guard incoming, let pending, DurableWire.exact(p.requestID, pending.requestID),
                  p.kind == pending.kind, try DurableWire.same(p.reference, pending.reference) else { throw DurableWireError.correlation }
            if let original = pending.originalContext, original != p.context { throw DurableWireError.correlation }
            if let digest = pending.originalContextDigest, !DurableWire.exact(digest, p.contextDigest) { throw DurableWireError.correlation }
            if session == nil {
                guard pending.kind == .recover, let ticket = pending.originalTicket else { throw DurableWireError.notAccepted }
                session = Selection(session: pending.reference.session, ticket: ticket)
            }
            generation = p; clientRoot = pending.clientRoot ?? clientRoot
            self.pending = nil; phase = .accepted
        case .batch(let frame):
            guard incoming else { throw DurableWireError.correlation }
            try requireGeneration(frame.payload.reference, context: frame.payload.contextDigest)
        case .knowledge(let frame):
            // Knowledge may travel either way; neither direction grants invocation authority.
            try requireGeneration(frame.payload.reference, context: frame.payload.contextDigest)
        case .receipt(let frame):
            let p = frame.payload
            guard !incoming, receipt == nil else { throw DurableWireError.correlation }
            try requireGeneration(p.reference, context: p.witness.context)
            if let clientRoot, clientRoot != p.witness.clientRoot { throw DurableWireError.correlation }
            clientRoot = p.witness.clientRoot; receipt = p
        case .receiptAccepted(let frame):
            let p = frame.payload
            guard incoming, let receipt, DurableWire.exact(p.requestID, receipt.requestID),
                  try DurableWire.same(p.reference, receipt.reference), try DurableWire.same(p.witness, receipt.witness) else { throw DurableWireError.correlation }
            try requireGeneration(p.reference, context: p.witness.context)
            self.receipt = nil
        case .refused(let frame):
            guard incoming else { throw DurableWireError.correlation }
            let c = frame.payload.correlation
            let expected: DurableCorrelation
            if let opening {
                expected = DurableCorrelation(requestID: opening.requestID, operation: .open)
            } else if let pending {
                expected = DurableCorrelation(requestID: pending.requestID, operation: pending.kind == .begin ? .begin : .recover,
                                              sessionID: pending.reference.session.sessionID, generationID: pending.reference.generationID)
            } else if let receipt {
                expected = DurableCorrelation(requestID: receipt.requestID, operation: .receipt,
                                              sessionID: receipt.reference.session.sessionID, generationID: receipt.reference.generationID)
            } else { throw DurableWireError.correlation }
            guard try DurableWire.same(c, expected) else { throw DurableWireError.correlation }
            refusal = frame.payload.reason; phase = .refused
            opening = nil; pending = nil; receipt = nil; session = nil; generation = nil; clientRoot = nil
        }
    }
}
