import Foundation
import DurableClientReceipts
import ReachWire
import Darwin

/// Synthetic source-faithful S80 event encoding and S81 envelope; no executed S82 join.
public enum ReceiptFixtures {
    public static let caller = ClientCaller(principal: "synthetic-principal", device: "synthetic-device", app: "synthetic-app")
    public static func authority(namespace: String = "fixture-session", generation: String = "generation-1",
                                 issued: UInt64 = 10, expires: UInt64 = 86_000_000_000_000,
                                 request: String = "request-1", caller: ClientCaller = caller) throws -> ClientAuthority {
        try .init(.init(caller: caller, host: "host-incarnation", store: "store-incarnation", namespace: namespace,
            generation: generation, request: request, operation: "operation-1", upstreamDigest: String(repeating: "a", count: 64),
            route: "required-tool", revision: "s83-local-v1", issued: issued, expires: expires))
    }
    public static func binding(_ id: String = "call-1", name: String = "fake", arguments: String = "{\"word\":\"é\"}") throws -> ToolBinding {
        try .init(id: Data(id.utf8), name: Data(name.utf8), arguments: Data(arguments.utf8))
    }
    public static func frame(first: UInt64 = 1, calls: Int = 2, terminal: Bool = true, commit: String = String(repeating: "b", count: 64)) throws -> ReplayEnvelope {
        var events: [WireEvent] = (1...max(1, calls)).prefix(calls).map {
            .toolCallAppendArguments(entryID: "entry", id: "call-\($0)", name: "fake", content: "{\"word\":\"é\"}", tokenCount: 1)
        }
        if terminal { events += [.usage(inputTokens: 4, outputTokens: 8), .finished(.complete)] }
        if events.isEmpty { events = [.responseAppend(entryID: "entry", text: "synthetic", segmentID: nil, tokenCount: 1)] }
        return try envelope(events, first: first, commit: commit)
    }
    public static func envelope(_ events: [WireEvent], first: UInt64 = 1, commit: String = String(repeating: "b", count: 64)) throws -> ReplayEnvelope {
        .init(firstSequence: first, count: events.count, providerCommit: commit, eventBytes: try ClientEvents.encode(events))
    }
    public static func outcome(_ a: ClientAuthority, kind: OutcomeKind = .success, result: Data = Data("verified-fake-result".utf8)) throws -> ClientOutcome {
        try .make(kind: kind, result: result, binding: binding(), authority: a)
    }
}
