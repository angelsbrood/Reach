import Foundation
import MLXGuidedGeneration
import MLXLMCommon
import ReachWire
import RequiredToolCoordinator

/// Synchronous exclusive owner of at most one native child. Empty transition
/// batches make route selection, ready delivery and subsequent prepare distinct.
public final class AllowedToolCoordinator {
    public struct Batch: Encodable {
        public let events: [WireEvent]
        public let checkpoint: AllowedToolCheckpoint
        enum CodingKeys: CodingKey { case events, checkpoint }
        public func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(events, forKey: .events); try c.encode(checkpoint.data, forKey: .checkpoint)
        }
    }
    private let runtime: AllowedToolRuntime
    private var probe: ResumableToolGeneration?
    private var guided: ResumableGuidedGeneration?
    private var d: AllowedDocument
    public private(set) var isClosed = false
    public var phase: AllowedPhase { d.control.phase }
    public var route: AllowedRoute? { d.control.route }
    private init(runtime: AllowedToolRuntime, document: AllowedDocument, probe: ResumableToolGeneration? = nil, guided: ResumableGuidedGeneration? = nil) {
        self.runtime = runtime; d = document; self.probe = probe; self.guided = guided
    }
    public static func prepare(binding: AllowedToolBinding, runtime: AllowedToolRuntime) throws -> AllowedToolCoordinator {
        try binding.validate()
        let pass = try AllowedToolReplayInput.prepare(binding: binding, kind: .probe, tokenizer: runtime.tokenizer)
        let child = try ResumableToolGeneration.prepare(model: runtime.model(pass), tokens: pass.tokens, identity: pass.identity,
            rawOptions: binding.probeOptions, cacheSpecs: binding.probeModel.cacheSpecs, codecs: runtime.probeCodecs,
            tokenizer: runtime.tokenizer, options: binding.textOptions, configuration: binding.parserConfiguration(), namespace: binding.namespace)
        do {
            let saved = try child.capture(), view = try ResumableToolGenerationCheckpointView(checkpoint: saved, validatedOperation: child)
            let c = AllowedControl(binding: binding, childDigest: allowedDigest(saved.data), probe: view)
            let live = AllowedToolCoordinator(runtime: runtime, document: .init(control: c, child: saved.data), probe: child)
            try live.validate(); _ = try live.capture(); return live
        } catch { child.close(); throw error }
    }
    public static func restore(_ saved: AllowedToolCheckpoint, expected: AllowedToolBinding, runtime: AllowedToolRuntime) throws -> AllowedToolCoordinator {
        try expected.validate()
        let d = try saved.document()
        guard try allowedEncode(d.control.binding) == allowedEncode(expected) else { throw AllowedToolError.incompatible }
        let live = AllowedToolCoordinator(runtime: runtime, document: d)
        do {
            // Reject deterministic outer joins before asking the owner for a model.
            try live.validateHistory()
            if d.control.childKind == .probe {
                let pass = try AllowedToolReplayInput.prepare(binding: expected, kind: .probe, tokenizer: runtime.tokenizer)
                live.probe = try .restore(.init(data: d.child), model: runtime.model(pass), identity: pass.identity,
                    rawOptions: expected.probeOptions, cacheSpecs: expected.probeModel.cacheSpecs, codecs: runtime.probeCodecs,
                    tokenizer: runtime.tokenizer, options: expected.textOptions, configuration: expected.parserConfiguration(), namespace: expected.namespace)
            } else {
                guard let pass = d.control.current else { throw AllowedToolError.invalid("missing retained pass input") }
                live.guided = try .restore(.init(data: d.child), model: runtime.model(pass), identity: pass.identity,
                    cacheSpecs: expected.guidedModel.cacheSpecs, codecs: runtime.guidedCodecs, tokenizer: runtime.tokenizer,
                    specification: live.specification(pass), options: expected.guidedOptions)
            }
            // Full restore above is mandatory even for interpass/ready/emitted.
            try live.validate(); return live
        } catch { live.close(); throw error }
    }
    public func capture() throws -> AllowedToolCheckpoint {
        guard !isClosed else { throw AllowedToolError.closed }; return try .init(document: d)
    }
    public func advance() throws -> Batch? {
        guard !isClosed else { throw AllowedToolError.closed }
        if phase == .finalEmitted { return nil }
        do {
            switch phase {
            case .probe: return try advanceProbe()
            case .routeReady, .interpass:
                if d.control.outcome == .unknownTool { d.control.phase = .finalEmitted; return try batch([.finished(.error(Self.unknownMessage))]) }
                return try prepareNext()
            case .guided: return try advanceGuided()
            case .callReady: return try deliverIntermediate()
            case .finalReady: return try deliverFinal()
            case .finalEmitted: return nil
            }
        } catch { close(); throw error }
    }
    public func cancel() throws -> Batch? {
        guard !isClosed else { throw AllowedToolError.closed }
        if phase == .finalEmitted { return nil }
        do {
            if phase == .finalReady { return try deliverFinal() }
            let from = phase
            if from == .probe {
                guard let probe, let b = try probe.cancel() else { throw AllowedToolError.invalid("active probe cancellation") }
                d.child = b.checkpoint.data; d.control.probe = try .init(checkpoint: b.checkpoint, validatedOperation: probe)
            } else if from == .guided {
                guard let guided, let b = try guided.cancel() else { throw AllowedToolError.invalid("active guided cancellation") }
                d.child = b.checkpoint.data
                let view = try ResumableGuidedCheckpointView(checkpoint: b.checkpoint, validatedOperation: guided, tokenizer: runtime.tokenizer)
                d.control.guided = .init(view)
            }
            d.control.childDigest = allowedDigest(d.child); d.control.cancelledFrom = from
            d.control.outcome = .cancelled; d.control.phase = .finalEmitted
            try validate(); return try batch([.finished(.cancelled)])
        } catch { close(); throw error }
    }
    private func advanceProbe() throws -> Batch {
        guard let probe, let b = try probe.advance() else { throw AllowedToolError.invalid("missing active probe") }
        var events: [WireEvent] = []
        for record in b.records {
            if case .parsed(let parsed) = record {
                d.control.records.append(parsed)
                if d.control.binding.responseSchema == nil, case .response(let bytes) = parsed, !bytes.isEmpty {
                    events.append(.responseAppend(entryID: nil, text: String(decoding: bytes, as: UTF8.self), segmentID: nil, tokenCount: 1))
                    d.control.proseDelivered += 1
                }
            }
        }
        d.child = b.checkpoint.data; d.control.childDigest = allowedDigest(d.child)
        d.control.probe = try .init(checkpoint: b.checkpoint, validatedOperation: probe)
        if d.control.probe.terminalReason != nil {
            let calls = d.control.proposals
            if !calls.isEmpty {
                d.control.route = .calls; d.control.phase = .routeReady
                if calls.contains(where: { call in !d.control.binding.tools.contains { $0.name == call.function.name } }) { d.control.outcome = .unknownTool }
            } else if d.control.binding.responseSchema != nil { d.control.route = .schema; d.control.phase = .routeReady }
            else { d.control.route = .prose; d.control.phase = .finalReady; d.control.outcome = .complete }
        }
        try validate(); return try batch(events)
    }
    private func expectedPass(index: Int) throws -> AllowedPreparedPass {
        let c = d.control
        if c.route == .schema { return try AllowedToolReplayInput.prepare(binding: c.binding, kind: .schema, tokenizer: runtime.tokenizer) }
        guard c.route == .calls, c.proposals.indices.contains(index) else { throw AllowedToolError.invalid("replay selection/index") }
        return try AllowedToolReplayInput.prepare(binding: c.binding, kind: .tool, index: index, proposal: c.proposals[index], tokenizer: runtime.tokenizer)
    }
    private func specification(_ pass: AllowedPreparedPass) throws -> ResumableGrammarSpecification {
        if pass.kind == .schema { return try d.control.binding.specification(tool: nil) }
        guard d.control.proposals.indices.contains(pass.index),
              let index = d.control.binding.tools.firstIndex(where: { $0.name == d.control.proposals[pass.index].function.name }) else { throw AllowedToolError.invalid("selected tool") }
        return try d.control.binding.specification(tool: index)
    }
    private func prepareNext() throws -> Batch {
        let pass = try expectedPass(index: d.control.deliveredCalls), b = d.control.binding
        let source = try specification(pass)
        // Only one full retained child. Discard the prior owner/value before prepare.
        probe?.close(); guided?.close(); probe = nil; guided = nil; d.child = Data()
        let child = try ResumableGuidedGeneration.prepare(model: runtime.model(pass), tokens: pass.tokens, identity: pass.identity,
            cacheSpecs: b.guidedModel.cacheSpecs, codecs: runtime.guidedCodecs, tokenizer: runtime.tokenizer, specification: source, options: b.guidedOptions)
        guided = child
        let saved = try child.capture(), view = try ResumableGuidedCheckpointView(checkpoint: saved, validatedOperation: child, tokenizer: runtime.tokenizer)
        d.child = saved.data; d.control.childDigest = allowedDigest(d.child); d.control.childKind = pass.kind
        d.control.current = pass; d.control.guided = .init(view); d.control.whole = Data(); d.control.schemaReturnedBytes = 0
        d.control.phase = .guided
        try validate(); return try batch([])
    }
    private func advanceGuided() throws -> Batch {
        guard let guided, let pass = d.control.current, let b = try guided.advance() else { throw AllowedToolError.invalid("missing active guided pass") }
        var events: [WireEvent] = []
        for record in b.records {
            if case .text(let bytes) = record, !bytes.isEmpty {
                guard bytes.count <= 256*1024 - d.control.whole.count else { throw AllowedToolError.oversized }
                d.control.whole.append(bytes)
                if pass.kind == .schema {
                    d.control.schemaReturnedBytes += bytes.count
                    events.append(.responseAppend(entryID: nil, text: String(decoding: bytes, as: UTF8.self), segmentID: nil, tokenCount: 1))
                }
            }
        }
        d.child = b.checkpoint.data; d.control.childDigest = allowedDigest(d.child)
        let view = try ResumableGuidedCheckpointView(checkpoint: b.checkpoint, validatedOperation: guided, tokenizer: runtime.tokenizer)
        d.control.guided = .init(view)
        if view.terminalReason == .complete {
            let call: RequiredToolCall?
            if pass.kind == .tool {
                let name = d.control.proposals[pass.index].function.name
                let tool = d.control.binding.tools.first { $0.name == name }!
                call = try RequiredToolContract.parseEnvelope(d.control.whole, tools: [tool])
            } else { call = nil }
            d.control.completed.append(.init(index: pass.index, kind: pass.kind, inputDigest: pass.inputDigest,
                prompt: view.promptTokens, output: view.outputTokens, call: call))
            if pass.kind == .tool && pass.index + 1 < d.control.proposals.count { d.control.phase = .callReady }
            else { d.control.phase = .finalReady; d.control.outcome = .complete }
        } else if view.terminalReason == .incomplete {
            d.control.phase = .finalEmitted; d.control.outcome = .incompleteGuidance
            events.append(.finished(.error(Self.incompleteMessage)))
        }
        try validate(); return try batch(events)
    }
    private func callEvent(_ index: Int) throws -> WireEvent {
        let c = d.control
        guard c.proposals.indices.contains(index), c.completed.indices.contains(index), let call = c.completed[index].call, let id = c.proposals[index].id else {
            throw AllowedToolError.invalid("whole call delivery")
        }
        return .toolCallAppendArguments(entryID: c.binding.entryID, id: id, name: call.name, content: call.argumentsJSON, tokenCount: 1)
    }
    private func deliverIntermediate() throws -> Batch {
        let event = try callEvent(d.control.deliveredCalls)
        d.control.deliveredCalls += 1; d.control.phase = .interpass
        try validate(); return try batch([event])
    }
    private func deliverFinal() throws -> Batch {
        var events: [WireEvent] = []
        if d.control.route == .calls { events.append(try callEvent(d.control.deliveredCalls)); d.control.deliveredCalls += 1 }
        let usage = try d.control.usage()
        events += [.usage(inputTokens: usage.0, outputTokens: usage.1), .finished(.complete)]
        d.control.phase = .finalEmitted; try validate(); return try batch(events)
    }
    public static let unknownMessage = "A proposed tool name was not offered; no tool replay was started."
    public static let incompleteMessage = "An allowed-route guided pass did not reach accepted EOS within its generation budget."
    private func batch(_ events: [WireEvent]) throws -> Batch {
        let batch = Batch(events: events, checkpoint: try .init(document: d, records: events))
        guard try allowedEncode(batch).count <= AllowedToolCheckpoint.maximumBatchBytes else { throw AllowedToolError.oversized }
        return batch
    }
    public func close() { isClosed = true; probe?.close(); guided?.close(); probe = nil; guided = nil }

    private func validate() throws {
        try validateHistory()
        if d.control.childKind == .probe {
            guard let probe else { throw AllowedToolError.invalid("retained probe owner") }
            let view = try ResumableToolGenerationCheckpointView(checkpoint: .init(data: d.child), validatedOperation: probe)
            guard view == d.control.probe else { throw AllowedToolError.invalid("probe frontier join") }
        } else {
            guard let guided else { throw AllowedToolError.invalid("retained guided owner") }
            let view = try ResumableGuidedCheckpointView(checkpoint: .init(data: d.child), validatedOperation: guided, tokenizer: runtime.tokenizer)
            guard d.control.guided == AllowedGuidedSummary(view), d.control.whole == view.cumulativeEmittedBytes else {
                throw AllowedToolError.invalid("current guided whole-history/frontier join")
            }
        }
    }

    private func validateHistory() throws {
        try AllowedToolCheckpoint.bounds(d)
        let c = d.control, b = c.binding, proposals = c.proposals
        let ids = proposals.compactMap(\.id).sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        guard Set(ids).count == proposals.count, ids == c.probe.issuedIDs, c.probe.namespace == b.namespace,
              c.probe.promptTokens == b.originalTokens.count, (0...65_536).contains(c.probe.rawTokens),
              (0...c.probe.rawTokens).contains(c.probe.generationTokens), c.probe.allocationPosition <= 8192,
              c.probe.forwardedChunks <= 999_999, c.probe.parserSequence <= 1_000_000,
              (0...32).contains(c.deliveredCalls), c.deliveredCalls <= c.completed.count else { throw AllowedToolError.invalid("outer probe/ID/count history") }
        let proseCount = c.records.filter { if case .response(let bytes) = $0 { return !bytes.isEmpty }; return false }.count
        guard c.proseDelivered == (b.responseSchema == nil ? proseCount : 0) else { throw AllowedToolError.invalid("probe prose visibility cursor") }
        let normalProbe = c.probe.terminalReason == .stop || c.probe.terminalReason == .length
        guard c.probe.disposition == (normalProbe ? "normalFinished" : c.probe.terminalReason == .cancelled ? "cancelledFrozen" : "active"),
              c.probe.parserFinished == normalProbe, c.probe.parserSequence == c.probe.forwardedChunks + (normalProbe ? 1 : 0) else { throw AllowedToolError.invalid("probe summary lifecycle") }
        let selected: AllowedRoute = !proposals.isEmpty ? .calls : b.responseSchema != nil ? .schema : .prose
        guard c.route == (normalProbe ? selected : nil) else { throw AllowedToolError.invalid("route precedence") }
        let unknown = proposals.contains { p in !b.tools.contains { $0.name == p.function.name } }
        if normalProbe && unknown {
            guard c.childKind == .probe, c.phase == .routeReady || c.phase == .finalEmitted,
                  c.outcome == .unknownTool || (c.outcome == .cancelled && c.cancelledFrom == .routeReady) else { throw AllowedToolError.invalid("all-name validation before replay") }
        }
        for (i, summary) in c.completed.enumerated() {
            let pass = try expectedPass(index: i)
            guard summary.index == i, summary.kind == pass.kind, summary.inputDigest == pass.inputDigest,
                  summary.prompt == pass.tokens.count, (0..<b.guidedOptions.model.maximumTokens).contains(summary.output) else {
                throw AllowedToolError.invalid("completed input/usage contribution")
            }
            if pass.kind == .schema {
                guard i == 0, c.completed.count == 1, summary.call == nil else { throw AllowedToolError.invalid("schema summary") }
            } else {
                guard let call = summary.call, call.name == proposals[i].function.name else { throw AllowedToolError.invalid("completed call order/name") }
                let envelope = "{\"name\":\(String(decoding: try allowedEncode(call.name), as: UTF8.self)),\"arguments\":\(call.argumentsJSON)}"
                guard try RequiredToolContract.parseEnvelope(Data(envelope.utf8), tools: b.tools) == call else { throw AllowedToolError.invalid("normalized completed arguments") }
            }
        }
        _ = try c.usage()
        if c.childKind == .probe {
            guard c.current == nil, c.guided == nil, c.whole.isEmpty, c.schemaReturnedBytes == 0,
                  c.completed.isEmpty, c.deliveredCalls == 0 else { throw AllowedToolError.invalid("probe retained child shape") }
        } else {
            guard normalProbe, !unknown, let current = c.current, let v = c.guided,
                  c.childKind == current.kind, current.kind != .probe,
                  try allowedEncode(current) == allowedEncode(expectedPass(index: current.index)),
                  v.prompt == current.tokens.count, (0...65_536).contains(v.consumed),
                  (0...v.consumed).contains(v.sampled), (0...v.consumed).contains(v.forced), (0...1).contains(v.intercepted),
                  v.sampled + v.forced + v.intercepted == v.consumed,
                  (v.consumed...65_536).contains(v.accepted), v.accepted-v.consumed <= 4096,
                  c.completed.count == current.index + (v.terminal == .complete ? 1 : 0),
                  c.schemaReturnedBytes == (current.kind == .schema ? c.whole.count : 0) else { throw AllowedToolError.invalid("current input/frontier/history join") }
            if v.terminal == .complete {
                guard let last = c.completed.last, last.prompt == v.prompt, last.output == v.sampled+v.forced, v.intercepted == 1 else { throw AllowedToolError.invalid("completed current usage") }
                if current.kind == .tool {
                    guard last.call == (try RequiredToolContract.parseEnvelope(c.whole, tools: b.tools.filter { $0.name == proposals[current.index].function.name })) else {
                        throw AllowedToolError.invalid("current ready envelope")
                    }
                }
            }
        }
        let effective = c.outcome == .cancelled ? c.cancelledFrom : c.phase
        guard let effective else { throw AllowedToolError.invalid("cancellation origin") }
        switch effective {
        case .probe:
            guard c.childKind == .probe, c.route == nil, c.probe.terminalReason == (c.outcome == .cancelled ? .cancelled : nil) else { throw AllowedToolError.invalid("active probe phase") }
        case .routeReady:
            guard c.childKind == .probe, normalProbe, c.route == .calls || c.route == .schema else { throw AllowedToolError.invalid("route-ready phase") }
        case .guided:
            guard c.childKind != .probe, let current = c.current, c.deliveredCalls == (c.route == .calls ? current.index : 0),
                  c.guided?.terminal == (c.outcome == .cancelled ? .cancelled : nil) else { throw AllowedToolError.invalid("active guided phase") }
        case .callReady, .interpass:
            guard c.route == .calls, let current = c.current, c.guided?.terminal == .complete,
                  current.index+1 < proposals.count, c.deliveredCalls == current.index + (effective == .interpass ? 1 : 0) else { throw AllowedToolError.invalid("intermediate delivery cursor") }
        case .finalReady:
            guard c.outcome == .complete else { throw AllowedToolError.invalid("final-ready outcome") }
            try validateComplete(emitted: false)
        case .finalEmitted:
            switch c.outcome {
            case .complete: try validateComplete(emitted: true)
            case .unknownTool: guard unknown, c.childKind == .probe, normalProbe else { throw AllowedToolError.invalid("unknown tool ending") }
            case .incompleteGuidance:
                guard c.childKind != .probe, c.guided?.terminal == .incomplete,
                      c.deliveredCalls == (c.route == .calls ? c.current!.index : 0) else { throw AllowedToolError.invalid("incomplete ending") }
            default: throw AllowedToolError.invalid("emitted outcome")
            }
        }
        if c.outcome == .cancelled {
            guard c.phase == .finalEmitted, ![AllowedPhase.finalReady, .finalEmitted].contains(effective) else { throw AllowedToolError.invalid("cancellation phase") }
        } else {
            guard c.cancelledFrom == nil,
                  [.finalReady, .finalEmitted].contains(c.phase) || c.outcome == nil || (c.phase == .routeReady && c.outcome == .unknownTool) else { throw AllowedToolError.invalid("outcome phase") }
        }
    }
    private func validateComplete(emitted: Bool) throws {
        let c = d.control
        switch c.route {
        case .prose:
            guard c.childKind == .probe, c.probe.terminalReason == .stop || c.probe.terminalReason == .length else { throw AllowedToolError.invalid("prose complete") }
        case .schema:
            guard c.childKind == .schema, c.guided?.terminal == .complete, c.completed.count == 1, c.deliveredCalls == 0 else { throw AllowedToolError.invalid("schema complete") }
        case .calls:
            guard c.childKind == .tool, c.guided?.terminal == .complete, c.completed.count == c.proposals.count,
                  c.deliveredCalls == c.proposals.count - (emitted ? 0 : 1) else { throw AllowedToolError.invalid("final call prefix") }
        case nil: throw AllowedToolError.invalid("complete without route")
        }
    }
}
