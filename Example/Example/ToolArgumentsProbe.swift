import Foundation
import FoundationModels

/// Launch-environment-only acceptance types. They are absent from normal UI
/// and never alter the filmed prompt or the ordinary clock tool.
@Generable
struct ToolArgumentsProbeLeaf {
    @Guide(.pattern(/^[A-Z]{2}-[0-9]{4}$/))
    var code: String

    @Guide(.range(73 ... 73))
    var count: Int

    @Guide(.count(3))
    var checkpoints: [Int]
}

@Generable
struct ToolArgumentsProbePayload {
    var primary: ToolArgumentsProbeLeaf

    @Guide(.count(2))
    var alternatives: [ToolArgumentsProbeLeaf]
}

@Generable
struct ToolArgumentsProbeArguments {
    var payload: ToolArgumentsProbePayload
    var auditNote: String
}

final class ToolArgumentsProbeLedger: @unchecked Sendable {
    nonisolated private let lock = NSLock()
    nonisolated(unsafe) private var accepted = 0

    nonisolated func record(_ arguments: ToolArgumentsProbeArguments) {
        let leaves = [arguments.payload.primary] + arguments.payload.alternatives
        guard arguments.payload.alternatives.count == 2,
              leaves.allSatisfy({
                  $0.code.wholeMatch(of: /^[A-Z]{2}-[0-9]{4}$/) != nil
                      && $0.count == 73
                      && $0.checkpoints.count == 3
              })
        else { return }
        lock.lock()
        accepted += 1
        lock.unlock()
    }

    nonisolated var acceptedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return accepted
    }
}

struct ToolArgumentsProbeTool: Tool {
    let name = "record_audit"
    let description = "Record the requested audit. Always call this tool for an audit request."
    let ledger: ToolArgumentsProbeLedger

    func call(arguments: ToolArgumentsProbeArguments) async throws -> String {
        ledger.record(arguments)
        // The acceptance ends at the adopting-app boundary it measures. A
        // follow-up prose turn would test a second model decision, not whether
        // the whole constrained object decoded and reached this tool.
        throw ToolArgumentsProbeStop.afterValidCall
    }
}

enum ToolArgumentsProbeStop: Error {
    case afterValidCall
}
