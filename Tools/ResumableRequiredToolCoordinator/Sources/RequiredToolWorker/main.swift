import Foundation
import MLX
import RequiredToolCoordinator
import RequiredToolFixtures

struct Expected: Codable {
    let rows: [RTObserved]
    let inputs: [[Int]]
    let offsets: [Int]
    let logits: [[Float]]
    let final: Data
    let weights: String
    let producerPID: Int32
}

func worker() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    try check(args.count == 4, "usage: produce|restore case checkpoint expected")
    let mode = args[0], name = args[1], selection = try rtCase(name)
    try check(["produce", "restore"].contains(mode), "worker mode")
    let item = try rtFixture(selection.fixture), setup = try RTSetup(item)
    let live: RequiredToolCoordinator, saved: RequiredToolCheckpoint
    var prefix: [RTObserved] = [], prefixCalls = 0
    if mode == "produce" {
        live = try setup.prepare(); prefix = try rtPrefix(live, item: item, boundary: selection.boundary)
        saved = try live.capture(); prefixCalls = setup.model.calls
    } else {
        saved = try .init(data: boundedRead(args[2], maximum: RequiredToolCheckpoint.maximumBytes))
        live = try setup.restore(saved)
        try check(setup.model.calls == 0 && setup.model.prepares == 0 && setup.model.inputs.isEmpty, "restore has zero model/prefill work")
        try check(try live.capture() == saved, "restore preserves exact C0 IDs and state")
    }
    defer { live.close() }
    try check(try rtAtBoundary(saved, item: item, boundary: selection.boundary), "actual saved boundary")
    let cut = try rtSnapshot(saved)
    let suffix = try rtDrain(live, item: item, cancelReady: selection.cancelReady), final = try live.capture()
    let calls = setup.model.calls
    try check(try live.advance() == nil && live.cancel() == nil && setup.model.calls == calls, "no terminal redelivery/work")
    if cut.phase == .ready || cut.phase == .emitted {
        try check(calls == prefixCalls, "ready/emitted continuation does no model work")
    }
    if mode == "produce" {
        try rtAssertResult(prefix + suffix, setup: setup, final: final)
        let expected = Expected(rows: suffix, inputs: Array(setup.model.inputs.dropFirst(prefixCalls)),
            offsets: Array(setup.model.priorOffsets.dropFirst(prefixCalls)), logits: Array(setup.model.outputs.dropFirst(prefixCalls)),
            final: final.data, weights: setup.model.weightsIdentity, producerPID: ProcessInfo.processInfo.processIdentifier)
        let bytes = try encoder().encode(expected)
        try check(bytes.count <= 32 * 1024 * 1024 && bytes.count + saved.data.count <= 64 * 1024 * 1024, "fixture byte ceilings")
        try saved.data.write(to: URL(fileURLWithPath: args[2]), options: .atomic)
        try bytes.write(to: URL(fileURLWithPath: args[3]), options: .atomic)
    } else {
        // Native continuation is complete before expected suffix evidence is read.
        let expected = try JSONDecoder().decode(Expected.self, from: boundedRead(args[3], maximum: 32 * 1024 * 1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier, "distinct sequential workers")
        try check(suffix == expected.rows && setup.model.inputs == expected.inputs && setup.model.priorOffsets == expected.offsets,
            "exact event/ID/usage/terminal/frontier/input/offset suffix")
        try check(setup.model.weightsIdentity == expected.weights && setup.model.outputs.count == expected.logits.count, "weight/forward binding")
        for (actual, wanted) in zip(setup.model.outputs, expected.logits) {
            try check(actual.count == wanted.count, "logit shape")
            for (a, b) in zip(actual, wanted) { try check(abs(a - b) <= 1e-6 + 1e-5 * abs(b), "logit tolerance") }
        }
        try rtCompare(final.data, expected.final)
    }
    try check(Memory.peakMemory <= 128 * 1024 * 1024, "tiny MLX tensor ceiling")
    let end = try rtSnapshot(final)
    let row: [String: Any] = ["result": "PASS", "mode": mode, "case": name, "fixture": selection.fixture, "boundary": selection.boundary,
        "pid": ProcessInfo.processInfo.processIdentifier, "checkpoint_sha256": sgHash(saved.data), "checkpoint_bytes": saved.data.count,
        "binding_sha256": try sgHash(encoder().encode(setup.binding)), "suffix_sha256": try sgHash(encoder().encode(suffix)),
        "suffix_batches": suffix.count, "suffix_events": suffix.flatMap(\.events).count,
        "consumed_at_cut": cut.consumed, "accepted_at_cut": cut.accepted, "pending_at_cut": cut.pending,
        "incomplete_unicode_at_cut": cut.incompleteUnicode, "newline_reset_at_cut": cut.newlineReset, "phase_at_cut": cut.phase.rawValue,
        "ending": end.outcome!.rawValue, "sampled": end.sampled, "forced": end.forced, "intercepted": end.intercepted,
        "model_calls": setup.model.calls, "prefix_calls": prefixCalls, "prepare_calls": setup.model.prepares,
        "restore_model_calls": 0, "restore_id_allocations": 0, "id_policy": "explicit immutable IDs; no generator API",
        "entry_id": setup.binding.entryID, "call_id": setup.binding.callID, "model_kind": item.kind,
        "weight_bytes": setup.model.weightBytes, "mlx_peak_bytes": Memory.peakMemory]
    print(String(decoding: try JSONSerialization.data(withJSONObject: row, options: .sortedKeys), as: UTF8.self))
}
do { try Device.withDefaultDevice(Device(.gpu)) { try worker() } }
catch { FileHandle.standardError.write(Data("REQUIRED_TOOL_WORKER_FAIL: \(error)\n".utf8)); exit(1) }
