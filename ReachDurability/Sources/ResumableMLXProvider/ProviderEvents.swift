import Foundation
import MLXLMCommon
import MLXGuidedGeneration
import ReachWire

enum ProviderEvents {
    static let incomplete = "Guided response did not reach accepted EOS within its generation budget."
    static func text(_ bytes: Data, entryID: String?, segmentID: String?) throws -> WireEvent {
        guard let text = String(data: bytes, encoding: .utf8), Data(text.utf8) == bytes else { throw ProviderError.invalid("non-UTF8 child text") }
        return .responseAppend(entryID: entryID, text: text, segmentID: segmentID, tokenCount: 1)
    }
    static func ordinary(_ records: [ResumableTextRecord], _ b: ProviderTextBinding) throws -> [WireEvent] {
        var events: [WireEvent] = []
        for record in records {
            switch record {
            case .text(let bytes): if !bytes.isEmpty { events.append(try text(bytes, entryID: b.entryID, segmentID: b.segmentID)) }
            case .terminal(let end):
                if end.reason == .cancelled { events.append(.finished(.cancelled)) }
                else { events += [.usage(inputTokens: end.promptTokens, outputTokens: end.generationTokens), .finished(.complete)] }
            }
        }
        return events
    }
    static func guided(_ records: [ResumableGuidedRecord], _ b: ProviderGuidedBinding) throws -> [WireEvent] {
        var events: [WireEvent] = []
        for record in records {
            switch record {
            case .text(let bytes): if !bytes.isEmpty { events.append(try text(bytes, entryID: b.entryID, segmentID: b.segmentID)) }
            case .terminal(let end):
                switch end.reason {
                case .complete:
                    let count = end.sampledTokens.addingReportingOverflow(end.forcedTokens)
                    guard !count.overflow, count.partialValue >= 0 else { throw ProviderError.overflow }
                    events += [.usage(inputTokens: end.promptTokens, outputTokens: count.partialValue), .finished(.complete)]
                case .incomplete: events.append(.finished(.error(incomplete)))
                case .cancelled: events.append(.finished(.cancelled))
                }
            }
        }
        return events
    }
    static func ending(_ events: [WireEvent]) throws -> WireFinishReason? {
        let ends = events.compactMap { if case .finished(let reason) = $0 { return reason }; return nil }
        guard ends.count <= 1 else { throw ProviderError.invalid("multiple terminal events") }
        if let end = ends.first {
            guard try providerEncode(events.last) == providerEncode(Optional(WireEvent.finished(end))) else { throw ProviderError.invalid("terminal event order") }
        }
        return ends.first
    }
    static func encode(_ events: [WireEvent]) throws -> Data {
        guard events.count <= 4096 else { throw ProviderError.oversized }
        for event in events {
            switch event {
            case .responseAppend(let entry, _, let segment, let count):
                try providerOptionalID(entry); try providerOptionalID(segment)
                guard count == 1 else { throw ProviderError.invalid("chunk count convention") }
            case .toolCallAppendArguments(let entry, let id, let name, _, let count):
                try providerOptionalID(entry); try providerID(id)
                guard !name.isEmpty, name.utf8.count <= 1024, count == 1 else { throw ProviderError.invalid("whole tool event") }
            case .usage(let input, let output):
                guard input >= 0, output >= 0, input <= 33*65_536, output <= 33*65_536 else { throw ProviderError.invalid("semantic usage") }
            case .finished(.error(let message)):
                guard !message.isEmpty, message.utf8.count <= 4096 else { throw ProviderError.invalid("bounded error") }
            case .finished: break
            default: throw ProviderError.unsupported("event projection")
            }
        }
        let end = try ending(events)
        let usage = events.filter { if case .usage = $0 { return true }; return false }.count
        if case .complete? = end {
            guard usage == 1, events.count >= 2, case .usage = events[events.count-2] else { throw ProviderError.invalid("success usage tail") }
        } else if usage != 0 { throw ProviderError.invalid("non-success usage") }
        let bytes = try providerEncode(events)
        guard bytes.count <= ProviderCandidate.maximumControlBytes else { throw ProviderError.oversized }
        return bytes
    }
    static func decode(_ bytes: Data) throws -> [WireEvent] {
        guard bytes.count <= ProviderCandidate.maximumControlBytes else { throw ProviderError.oversized }
        let events = try JSONDecoder().decode([WireEvent].self, from: bytes)
        guard try encode(events) == bytes else { throw ProviderError.invalid("event encoding") }
        return events
    }
}
