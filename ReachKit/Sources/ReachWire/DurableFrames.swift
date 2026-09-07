import Foundation

/// Inactive-v2 codec vocabulary. Validation here never admits a caller or verifies stored history.
public enum DurableWire {
    public static let version: UInt8 = 2
    public static let profile = "reach-durable-session-v1"
    public static let controlLimit = 2<<20, bulkLimit = 14<<20, contextLimit = 1<<20
    public static func bodyLimit(_ type: FrameType) -> Int { type == .durableBatch || type == .durableToolKnowledge ? bulkLimit : controlLimit }
    public static func requireBody(_ bytes: Data, type: FrameType) throws {
        guard bytes.count <= bodyLimit(type) else { throw DurableWireError.bodyTooLarge(type, bytes.count) }
    }
    static func require(_ condition: Bool) throws { if !condition { throw DurableWireError.invalid } }
    static func identifier(_ value: String) throws { try require(!value.isEmpty && value.utf8.count<=256) }
    static func profileName(_ value: String) throws { try require(!value.isEmpty && value.utf8.count<=64 && value.utf8.allSatisfy { $0<128 }) }
    static func uuid(_ value: String) throws { try require(value.utf8.count==36 && UUID(uuidString:value)?.uuidString.lowercased()==value) }
    static func digest(_ value: String) throws { try require(value.utf8.count==64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }) }
    static func ticket(_ bytes: Data) throws { try require((41...4096).contains(bytes.count)) }
    static func context(_ bytes: Data, digest: String) throws {
        // Transport shape only. A trusted adapter must verify that the declared
        // digest describes these original bytes and authenticated retained state.
        try self.digest(digest); try require(!bytes.isEmpty && bytes.count<=contextLimit)
    }
    static func utf8(_ bytes: Data, maximum: Int, nonempty: Bool) throws {
        try require(bytes.count<=maximum && (!nonempty || !bytes.isEmpty))
        guard let text=String(data:bytes,encoding:.utf8) else { throw DurableWireError.invalid }; try require(Data(text.utf8)==bytes)
    }
    static func canonical<T: Encodable>(_ value:T) throws -> Data {
        let encoder=JSONEncoder(); encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]; return try encoder.encode(value)
    }
    static func same<T: Encodable>(_ a:T,_ b:T) throws -> Bool { try canonical(a)==canonical(b) }
    static func exact(_ a:String,_ b:String) -> Bool { Data(a.utf8)==Data(b.utf8) }
}
public enum DurableWireError: Error, Sendable, Equatable {
    case invalid, bodyTooLarge(FrameType, Int), localOptOut, unavailable, incompatible, correlation, notAccepted
}
public protocol DurableWireFrame: WireFrame { func validateDurable() throws }
public protocol DurablePayload: Codable, Sendable {
    static var frameType: FrameType { get }
    func validate() throws
}
/// Its payload is flattened in JSON. Direct DTO decoding proves syntax, not negotiation or authority.
public struct DurablePacket<Payload: DurablePayload>: DurableWireFrame {
    public static var frameType: FrameType { Payload.frameType }
    public var payload: Payload
    public init(_ payload: Payload) { self.payload=payload }
    public func validateDurable() throws {
        try payload.validate(); try DurableWire.requireBody(DurableWire.canonical(payload),type:Self.frameType)
    }
    public init(from decoder: Decoder) throws { payload=try Payload(from:decoder); try validateDurable() }
    public func encode(to encoder: Encoder) throws { try validateDurable(); try payload.encode(to:encoder) }
}
public struct DurableSessionReference: Codable, Sendable, Equatable {
    public var modelID: String, profile: String, sessionID: String
    public init(modelID: String, profile: String, sessionID: String) { self.modelID=modelID; self.profile=profile; self.sessionID=sessionID }
    public func validate() throws { try DurableWire.identifier(modelID); try DurableWire.profileName(profile); try DurableWire.uuid(sessionID) }
}
public struct DurableGenerationReference: Codable, Sendable, Equatable {
    public var session: DurableSessionReference, generationID: String, operationID: String
    public init(session: DurableSessionReference, generationID: String, operationID: String) { self.session=session; self.generationID=generationID; self.operationID=operationID }
    public func validate() throws { try session.validate(); try DurableWire.identifier(generationID); try DurableWire.identifier(operationID) }
}
/// Complete S84 witness, in its independent one-based sequence space. Terminal does not mean effects completed.
public struct DurableWitness: Codable, Sendable, Equatable {
    public var version: Int, policy: String, context: String, clientRoot: String
    public var revision: UInt64, high: UInt64, terminal: Bool, prefix: String, registrations: Int, calls: String
    public init(version: Int=1, policy: String="s84-host-client-v1", context: String, clientRoot: String,
                revision: UInt64, high: UInt64, terminal: Bool, prefix: String, registrations: Int, calls: String) {
        self.version=version; self.policy=policy; self.context=context; self.clientRoot=clientRoot; self.revision=revision
        self.high=high; self.terminal=terminal; self.prefix=prefix; self.registrations=registrations; self.calls=calls
    }
    public func validate() throws {
        try DurableWire.uuid(clientRoot); for d in [context,prefix,calls] { try DurableWire.digest(d) }
        try DurableWire.require(version==1 && policy=="s84-host-client-v1" && high<=65_536 && (0...32).contains(registrations))
        try DurableWire.require(high==0 ? revision==0 && !terminal && registrations==0 : revision>0)
    }
}
public enum DurableAcceptanceKind: String, Codable, Sendable { case begin, recover }
public enum DurableKnowledgeState: String, Codable, Sendable { case unknown, known }
public enum DurableOutcomeKind: String, Codable, Sendable { case success, failure }
public struct DurableOutcome: Codable, Sendable, Equatable {
    public var version: Int, kind: DurableOutcomeKind, result: Data, digest: String
    public init(version: Int=1, kind: DurableOutcomeKind, result: Data, digest: String) { self.version=version; self.kind=kind; self.result=result; self.digest=digest }
    public func validate() throws {
        try DurableWire.digest(digest); try DurableWire.require(version==1 && result.count<=1<<20)
        try DurableWire.require(DurableWire.canonical(self).count<=1<<20)
    }
}
public enum DurableRefusalReason: String, Codable, Sendable { case unavailable, incompatible, unauthorized, expired, unknownOrLost="unknown-lost", invalid, busyOrFull="busy-full" }
public enum DurableRefusalOperation: String, Codable, Sendable { case open, begin, recover, receipt }
public struct DurableCorrelation: Codable, Sendable, Equatable {
    public var requestID: String, operation: DurableRefusalOperation, sessionID: String?, generationID: String?
    public init(requestID: String, operation: DurableRefusalOperation, sessionID: String?=nil, generationID: String?=nil) {
        self.requestID=requestID; self.operation=operation; self.sessionID=sessionID; self.generationID=generationID
    }
    private enum CodingKeys: String, CodingKey { case requestID, operation, sessionID, generationID }
    public init(from decoder: Decoder) throws {
        let c=try decoder.container(keyedBy:CodingKeys.self)
        requestID=try c.decode(String.self,forKey:.requestID); operation=try c.decode(DurableRefusalOperation.self,forKey:.operation)
        sessionID=try c.contains(.sessionID) ? c.decode(String.self,forKey:.sessionID) : nil
        generationID=try c.contains(.generationID) ? c.decode(String.self,forKey:.generationID) : nil
        try validate()
    }
    public func validate() throws {
        try DurableWire.identifier(requestID)
        if operation == .open { try DurableWire.require(sessionID==nil && generationID==nil) }
        else {
            guard let sessionID, let generationID else { throw DurableWireError.invalid }
            try DurableWire.uuid(sessionID); try DurableWire.identifier(generationID)
        }
    }
}

public typealias DurableCapabilities = DurablePacket<DurableCapabilitiesPayload>
public struct DurableCapabilitiesPayload: DurablePayload {
    public static let frameType = FrameType.durableCapabilities
    public var modelID: String
    public var profiles: [String]
    public init(modelID: String, profiles: [String]) {
        self.modelID=modelID; self.profiles=profiles
    }
    public func validate() throws {
        try DurableWire.identifier(modelID); try DurableWire.require(profiles.count<=8 && Set(profiles).count==profiles.count)
        for profile in profiles { try DurableWire.profileName(profile) }
    }
}

public typealias DurableSessionOpen = DurablePacket<DurableSessionOpenPayload>
public struct DurableSessionOpenPayload: DurablePayload {
    public static let frameType = FrameType.durableSessionOpen
    public var requestID: String
    public var modelID: String
    public var profile: String
    public var durable: Bool
    public init(requestID: String, modelID: String, profile: String, durable: Bool) {
        self.requestID=requestID; self.modelID=modelID; self.profile=profile; self.durable=durable
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try DurableWire.identifier(modelID); try DurableWire.profileName(profile); try DurableWire.require(durable)
    }
}

public typealias DurableSessionOpened = DurablePacket<DurableSessionOpenedPayload>
public struct DurableSessionOpenedPayload: DurablePayload {
    public static let frameType = FrameType.durableSessionOpened
    public var requestID: String
    public var session: DurableSessionReference
    public var ticket: Data
    public init(requestID: String, session: DurableSessionReference, ticket: Data) {
        self.requestID=requestID; self.session=session; self.ticket=ticket
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try session.validate(); try DurableWire.ticket(ticket)
    }
}

public typealias DurableGenerateBegin = DurablePacket<DurableGenerateBeginPayload>
public struct DurableGenerateBeginPayload: DurablePayload {
    public static let frameType = FrameType.durableGenerateBegin
    public var requestID: String
    public var reference: DurableGenerationReference
    public var ticket: Data
    public var request: WireGenerationRequest
    public init(requestID: String, reference: DurableGenerationReference, ticket: Data, request: WireGenerationRequest) {
        self.requestID=requestID; self.reference=reference; self.ticket=ticket; self.request=request
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try reference.validate(); try DurableWire.ticket(ticket)
    }
}

public typealias DurableGenerationAccepted = DurablePacket<DurableGenerationAcceptedPayload>
public struct DurableGenerationAcceptedPayload: DurablePayload {
    public static let frameType = FrameType.durableGenerationAccepted
    public var requestID: String
    public var reference: DurableGenerationReference
    public var kind: DurableAcceptanceKind
    public var context: Data
    public var contextDigest: String
    public init(requestID: String, reference: DurableGenerationReference, kind: DurableAcceptanceKind, context: Data, contextDigest: String) {
        self.requestID=requestID; self.reference=reference; self.kind=kind; self.context=context; self.contextDigest=contextDigest
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try reference.validate(); try DurableWire.context(context,digest:contextDigest)
    }
}

public typealias DurableGenerateRecover = DurablePacket<DurableGenerateRecoverPayload>
public struct DurableGenerateRecoverPayload: DurablePayload {
    public static let frameType = FrameType.durableGenerateRecover
    public var requestID: String
    public var reference: DurableGenerationReference
    public var ticket: Data
    public var context: Data
    public var contextDigest: String
    public var clientRoot: String
    public var witness: DurableWitness
    public init(requestID: String, reference: DurableGenerationReference, ticket: Data, context: Data, contextDigest: String, clientRoot: String, witness: DurableWitness) {
        self.requestID=requestID; self.reference=reference; self.ticket=ticket; self.context=context; self.contextDigest=contextDigest; self.clientRoot=clientRoot; self.witness=witness
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try reference.validate(); try DurableWire.ticket(ticket); try DurableWire.context(context,digest:contextDigest)
        try DurableWire.uuid(clientRoot); try witness.validate(); try DurableWire.require(witness.clientRoot==clientRoot && witness.context==contextDigest)
    }
}

public typealias DurableBatch = DurablePacket<DurableBatchPayload>
public struct DurableBatchPayload: DurablePayload {
    public static let frameType = FrameType.durableBatch
    public var reference: DurableGenerationReference
    public var contextDigest: String
    public var first: UInt64
    public var count: Int
    public var commit: String
    public var skip: Int
    public var bytes: Data
    public init(reference: DurableGenerationReference, contextDigest: String, first: UInt64, count: Int, commit: String, skip: Int, bytes: Data) {
        self.reference=reference; self.contextDigest=contextDigest; self.first=first; self.count=count; self.commit=commit; self.skip=skip; self.bytes=bytes
    }
    public func validate() throws {
        try reference.validate(); try DurableWire.digest(contextDigest); try DurableWire.digest(commit)
        try DurableWire.require(first>0 && (1...4096).contains(count) && (0..<count).contains(skip) && !bytes.isEmpty && bytes.count<=8<<20)
        let (last,overflow)=first.addingReportingOverflow(UInt64(count-1)); try DurableWire.require(!overflow && last<=65_536)
    }
}

public typealias DurableReceipt = DurablePacket<DurableReceiptPayload>
public struct DurableReceiptPayload: DurablePayload {
    public static let frameType = FrameType.durableReceipt
    public var requestID: String
    public var reference: DurableGenerationReference
    public var witness: DurableWitness
    public init(requestID: String, reference: DurableGenerationReference, witness: DurableWitness) {
        self.requestID=requestID; self.reference=reference; self.witness=witness
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try reference.validate(); try witness.validate()
    }
}

public typealias DurableReceiptAccepted = DurablePacket<DurableReceiptAcceptedPayload>
public struct DurableReceiptAcceptedPayload: DurablePayload {
    public static let frameType = FrameType.durableReceiptAccepted
    public var requestID: String
    public var reference: DurableGenerationReference
    public var witness: DurableWitness
    public init(requestID: String, reference: DurableGenerationReference, witness: DurableWitness) {
        self.requestID=requestID; self.reference=reference; self.witness=witness
    }
    public func validate() throws {
        try DurableWire.identifier(requestID); try reference.validate(); try witness.validate()
    }
}

public typealias DurableToolKnowledge = DurablePacket<DurableToolKnowledgePayload>
public struct DurableToolKnowledgePayload: DurablePayload {
    public static let frameType = FrameType.durableToolKnowledge
    public var reference: DurableGenerationReference
    public var contextDigest: String
    public var callID: Data
    public var name: Data
    public var arguments: Data
    public var state: DurableKnowledgeState
    public var outcome: DurableOutcome?
    public init(reference: DurableGenerationReference, contextDigest: String, callID: Data, name: Data, arguments: Data, state: DurableKnowledgeState, outcome: DurableOutcome?) {
        self.reference=reference; self.contextDigest=contextDigest; self.callID=callID; self.name=name; self.arguments=arguments; self.state=state; self.outcome=outcome
    }
    public func validate() throws {
        try reference.validate(); try DurableWire.digest(contextDigest)
        try DurableWire.utf8(callID,maximum:256,nonempty:true); try DurableWire.utf8(name,maximum:1024,nonempty:true); try DurableWire.utf8(arguments,maximum:8<<20,nonempty:false)
        try DurableWire.require(state == .unknown ? outcome==nil : outcome != nil); try outcome?.validate()
    }
    private enum CodingKeys: String, CodingKey { case reference, contextDigest, callID, name, arguments, state, outcome }
    public init(from decoder: Decoder) throws {
        let c=try decoder.container(keyedBy:CodingKeys.self)
        reference=try c.decode(DurableGenerationReference.self,forKey:.reference)
        contextDigest=try c.decode(String.self,forKey:.contextDigest)
        callID=try c.decode(Data.self,forKey:.callID)
        name=try c.decode(Data.self,forKey:.name)
        arguments=try c.decode(Data.self,forKey:.arguments)
        state=try c.decode(DurableKnowledgeState.self,forKey:.state)
        outcome=try c.contains(.outcome) ? c.decode(DurableOutcome.self,forKey:.outcome) : nil
        try validate()
    }
}

public typealias DurableRefused = DurablePacket<DurableRefusedPayload>
public struct DurableRefusedPayload: DurablePayload {
    public static let frameType = FrameType.durableRefused
    public var correlation: DurableCorrelation
    public var reason: DurableRefusalReason
    public init(correlation: DurableCorrelation, reason: DurableRefusalReason) {
        self.correlation=correlation; self.reason=reason
    }
    public func validate() throws {
        try correlation.validate()
    }
}
