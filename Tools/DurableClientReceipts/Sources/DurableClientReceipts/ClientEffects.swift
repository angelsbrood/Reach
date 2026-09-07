import Foundation

public struct ToolBinding {
    public let id: Data, name: Data, arguments: Data
    public init(id: Data, name: Data, arguments: Data) throws {
        guard !id.isEmpty, id.count <= 256, !name.isEmpty, name.count <= 1024, arguments.count <= ClientLimits.batch,
              [id, name, arguments].allSatisfy({ bytes in
                  guard let value = String(data: bytes, encoding: .utf8) else { return false }
                  return Data(value.utf8) == bytes
              }) else {
            throw ClientError.invalid("tool binding")
        }
        self.id = Data(id); self.name = Data(name); self.arguments = Data(arguments)
    }
    func digest(_ context: Data) -> String { crDomain("call", [context, id, name, arguments]) }
}
public enum OutcomeKind: String, Codable { case success, failure }
public struct ClientOutcome: Codable, Equatable {
    public let version: Int
    public let kind: OutcomeKind
    public let result: Data
    public let digest: String
    public init(kind: OutcomeKind, result: Data, digest: String) { version = 1; self.kind = kind; self.result = Data(result); self.digest = digest }
    public static func make(kind: OutcomeKind, result: Data, binding: ToolBinding, authority: ClientAuthority) throws -> ClientOutcome {
        guard result.count <= ClientLimits.outcome else { throw ClientError.full }
        let outcome = ClientOutcome(kind: kind, result: result, digest: crDomain("outcome", [authority.bytes, binding.id, binding.name,
            binding.arguments, Data(kind.rawValue.utf8), result]))
        _ = try outcome.checked(binding, context: authority.bytes); return outcome
    }
    func checked(_ binding: ToolBinding, context: Data) throws -> Data {
        guard version == 1, result.count <= ClientLimits.outcome, crDigest(digest),
              digest == crDomain("outcome", [context, binding.id, binding.name, binding.arguments, Data(kind.rawValue.utf8), result]) else { throw ClientError.invalid("outcome binding/digest") }
        let encoded = try crEncode(self)
        guard encoded.count <= ClientLimits.outcome else { throw ClientError.full }; return encoded
    }
}
public enum EffectKnowledge: Equatable { case unbegun, unknown, known(ClientOutcome) }
/// A one-time decision for a cooperating caller, not a capability enforcing arbitrary external code.
public struct EffectPermission { public let callDigest: String; public let ownerEpoch: UInt64 }
public enum BeginEffectResult { case fresh(EffectPermission), unknown, known(ClientOutcome) }
struct ClientCall: Codable {
    let id: Data, name: Data, arguments: Data, identity: String
    var intent = false
    var outcome: Data?
    init(context: Data, id: Data, name: Data, arguments: Data) throws {
        let binding = try ToolBinding(id: id, name: name, arguments: arguments)
        self.id = binding.id; self.name = binding.name; self.arguments = binding.arguments; identity = binding.digest(context)
    }
    func binding() throws -> ToolBinding { try .init(id: id, name: name, arguments: arguments) }
    func validate(context: Data) throws {
        let binding = try binding()
        guard identity == binding.digest(context), intent || outcome == nil else { throw ClientError.unavailable }
        if let outcome {
            guard outcome.count <= ClientLimits.outcome else { throw ClientError.unavailable }
            let value = try JSONDecoder().decode(ClientOutcome.self, from: outcome)
            guard try value.checked(binding, context: context) == outcome else { throw ClientError.unavailable }
        }
    }
    func knowledge() throws -> EffectKnowledge {
        if let outcome { return .known(try JSONDecoder().decode(ClientOutcome.self, from: outcome)) }
        return intent ? .unknown : .unbegun
    }
}
extension DurableClientReceipts {
    func callIndex(_ binding: ToolBinding, _ s: ClientSnapshot) throws -> Int {
        guard let i = s.calls.firstIndex(where: { $0.id == binding.id }), s.calls[i].identity == binding.digest(s.context),
              s.calls[i].name == binding.name, s.calls[i].arguments == binding.arguments else { throw ClientError.invalid("exact call binding") }
        return i
    }
    public func effect(_ binding: ToolBinding, handle: ClientHandle, authority a: ClientAuthority,
                       authorization auth: ClientAuthorization) throws -> EffectKnowledge {
        try precheck(a, auth); let m = try refresh(); let i = try find(handle, a, m); let s = try snapshot(m.records[i])
        let result = try s.calls[callIndex(binding, s)].knowledge(); try publish(a, auth, m); return result
    }
    public func beginEffect(_ binding: ToolBinding, handle: ClientHandle, authority a: ClientAuthority,
                            authorization auth: ClientAuthorization) throws -> BeginEffectResult {
        try precheck(a, auth); let old = try refresh(); let i = try find(handle, a, old); var s = try snapshot(old.records[i])
        let c = try callIndex(binding, s)
        switch try s.calls[c].knowledge() {
        case .known(let outcome): try publish(a, auth, old); return .known(outcome)
        case .unknown: try publish(a, auth, old); return .unknown
        case .unbegun: break
        }
        try hook(.beforeIntent)
        // IO before this point cannot authorize an effect. Intent and its global outcome credit precede the sole permission.
        try auth.check(a, now: observe(old)); s.calls[c].intent = true
        var m = old; m.revision = try crAdd(m.revision, 1)
        m = try commit(m, old: old, replacement: (i, s)); try hook(.afterIntent)
        try publish(a, auth, m); return .fresh(.init(callDigest: s.calls[c].identity, ownerEpoch: ownerEpoch))
    }
    public func recordOutcome(_ outcome: ClientOutcome, binding: ToolBinding, handle: ClientHandle,
                              authority a: ClientAuthority, authorization auth: ClientAuthorization) throws -> ClientOutcome {
        try precheck(a, auth); let old = try refresh(); let i = try find(handle, a, old); var s = try snapshot(old.records[i])
        let c = try callIndex(binding, s), bytes = try outcome.checked(binding, context: s.context)
        guard s.calls[c].intent else { throw ClientError.invalid("outcome before intent") }
        if let known = s.calls[c].outcome {
            guard known == bytes else { throw ClientError.invalid("changed outcome") }
            try publish(a, auth, old); return outcome
        }
        s.calls[c].outcome = bytes
        var m = old; m.revision = try crAdd(m.revision, 1)
        m = try commit(m, old: old, replacement: (i, s)); try hook(.afterOutcome)
        try publish(a, auth, m); return outcome
    }
}
