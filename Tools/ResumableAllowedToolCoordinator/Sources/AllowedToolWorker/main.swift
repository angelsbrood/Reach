import AllowedToolCoordinator
import Foundation
import MLX
import AllowedToolFixtures

struct Expected: Codable {
    let rows: [ATObserved]
    let traces: [ATModelTrace]
    let final: Data
    let producerPID: Int32
}
func worker() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    try check(args.count == 4, "usage: produce|restore case checkpoint expected")
    let mode = args[0], name = args[1], selected = try atCase(name), setup = try ATSetup(atFixture(selected.fixture))
    try check(["produce", "restore"].contains(mode), "worker mode")
    let live: AllowedToolCoordinator, saved: AllowedToolCheckpoint
    var prefix: [ATObserved] = [], previousCalls: [Int] = []
    if mode == "produce" {
        live = try setup.prepare(); prefix = try atPrefix(live, boundary: selected.boundary)
        saved = try live.capture(); previousCalls = setup.factory.models.map { $0.1.calls }
    } else {
        saved = try .init(data: boundedRead(args[2], maximum: AllowedToolCheckpoint.maximumBytes))
        live = try setup.restore(saved)
        try check(setup.factory.calls == 0 && setup.factory.prepares == 0, "restore has zero model/prefill work")
        try check(setup.factory.models.count == 1, "restore constructs retained model only, no next-pass prepare")
        try check(try live.capture() == saved, "exact restored checkpoint/IDs/history")
    }
    defer { live.close() }
    let cut = try atSnapshot(saved)
    try check(try atBoundary(saved, selected.boundary), "actual checkpoint boundary")
    let suffix = try atDrain(live, cancelAt: selected.cancel ? selected.boundary : nil), final = try live.capture()
    let calls = setup.factory.calls, made = setup.factory.models.count
    try check(try live.advance() == nil && live.cancel() == nil, "no terminal redelivery")
    try check(calls == setup.factory.calls && made == setup.factory.models.count, "no terminal model work")
    let traces = setup.factory.traces(dropping: previousCalls)
    if mode == "produce" {
        try atAssertOutcome(prefix + suffix, setup: setup, final: final)
        let value = Expected(rows: suffix, traces: traces, final: final.data, producerPID: ProcessInfo.processInfo.processIdentifier)
        let bytes = try encoder().encode(value)
        try check(bytes.count <= 96*1024*1024 && bytes.count+saved.data.count <= 256*1024*1024, "actual fixture encoding limits")
        try saved.data.write(to: URL(fileURLWithPath: args[2]), options: .atomic)
        try bytes.write(to: URL(fileURLWithPath: args[3]), options: .atomic)
    } else {
        // Continuation is complete before expected suffix evidence is opened.
        let expected = try JSONDecoder().decode(Expected.self, from: boundedRead(args[3], maximum: 96*1024*1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier, "distinct sequential worker")
        try check(suffix == expected.rows, "exact event/ID/usage/phase/frontier suffix")
        try atCompareTraces(traces, expected.traces); try atCompare(final.data, expected.final)
    }
    let end = try atSnapshot(final)
    try check(Memory.peakMemory <= 128*1024*1024, "tiny MLX tensor ceiling")
    let row: [String: Any] = ["result": "PASS", "case": name, "mode": mode, "fixture": selected.fixture, "boundary": selected.boundary,
        "pid": ProcessInfo.processInfo.processIdentifier, "checkpoint_sha256": sgHash(saved.data), "checkpoint_bytes": saved.data.count,
        "binding_sha256": try sgHash(encoder().encode(setup.binding)), "suffix_sha256": try sgHash(encoder().encode(suffix)),
        "suffix_batches": suffix.count, "suffix_events": suffix.flatMap(\.events).count,
        "phase_at_cut": cut.phase.rawValue, "raw_at_cut": cut.raw, "parser_state_at_cut": cut.parserState,
        "proposals_at_cut": cut.proposalIDs, "guided_index_at_cut": cut.index ?? -1, "guided_consumed_at_cut": cut.consumed,
        "pending_at_cut": cut.pending, "incomplete_unicode_at_cut": cut.incompleteUnicode, "newline_reset_at_cut": cut.newlineReset,
        "delivered_at_cut": cut.delivered, "delivered_final": end.delivered, "route": end.route?.rawValue ?? "none", "ending": end.outcome!,
        "restore_model_calls": 0, "restore_prefill_calls": 0, "restore_id_allocations": 0,
        "model_calls": setup.factory.calls, "model_passes": made, "prepare_calls": setup.factory.prepares,
        "history_authority": "outer-owned prose/order/arguments; retained native child joins only",
        "weight_bytes": setup.factory.models.map { $0.1.weightBytes }.max() ?? 0, "mlx_peak_bytes": Memory.peakMemory]
    print(String(decoding: try JSONSerialization.data(withJSONObject: row, options: .sortedKeys), as: UTF8.self))
}
do { try Device.withDefaultDevice(Device(.gpu)) { try worker() } }
catch { FileHandle.standardError.write(Data("ALLOWED_TOOL_WORKER_FAIL: \(error)\n".utf8)); exit(1) }
