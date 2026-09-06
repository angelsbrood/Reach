import Foundation
import MLX
import ProviderFixtures
import ResumableMLXProvider

struct CommittedSelection: Codable {
    let candidate: Data
    let prefix: [PFRow]
}
struct Expected: Codable {
    let suffix: [PFRow]
    let traces: [ATModelTrace]
    let final: Data
    let prefixDigest: String
    let committedIdentity: String
    let discardedIdentity: String?
    let producerPID: Int32
}
func worker() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    try check(args.count == 4, "usage: produce|restore case committed-selection expected")
    let mode = args[0], name = args[1], selected = try pfCase(name), setup = try PFSetup(selected.fixture)
    try check(["produce","restore"].contains(mode), "worker mode")
    let host: PFHost, saved: ProviderCandidate, prefix: [PFRow], counts: [Int]
    if mode == "produce" {
        host = try PFHost(setup); try host.reach(selected.cut)
        saved = host.committed; prefix = host.rows; counts = setup.traceCounts()
    } else {
        let selection = try JSONDecoder().decode(CommittedSelection.self, from: boundedRead(args[2], maximum: 192*1024*1024))
        saved = try ProviderCandidate(data: selection.candidate); prefix = selection.prefix; counts = []
        host = try PFHost(restoring: saved, prefix: prefix, setup: setup)
        try check(setup.calls == 0 && setup.prefills == 0, "restore zero model/prefill work")
        try check(setup.factories == 1 && host.live.acceptedCommit == saved.commit, "one retained child and exact committed identity")
    }
    defer { host.live.close() }
    try check(try pfBoundary(saved, rows: prefix, selected.cut), "actual committed boundary")
    try host.drain()
    let suffix = Array(host.rows.dropFirst(prefix.count)), traces = setup.traces(dropping: counts)
    let before = setup.calls, factories = setup.factories
    try check(try host.step() == nil && host.step(cancel: true) == nil, "terminal no redelivery")
    try host.live.acceptCommit(host.committed.commit, owner: host.owner)
    try check(setup.calls == before && setup.factories == factories, "terminal acknowledgement no work")
    var discarded: String?
    if mode == "produce" {
        try pfAssert(host, setup: setup)
        if selected.discard {
            let branchSetup = try PFSetup(selected.fixture), branch = try PFHost(restoring: saved, prefix: prefix, setup: branchSetup)
            defer { branch.live.close() }
            guard let later = try branch.live.advance(owner: branch.owner, current: saved.commit, credit: ResumableMLXProvider.reservationBytes) else { throw CheckFailure("uncommitted later candidate absent") }
            discarded = later.commit.identity
            try check(later.commit != saved.commit && branch.live.acceptedCommit == saved.commit, "host selects last committed, discards later pending")
        }
        let value = Expected(suffix: suffix, traces: traces, final: host.committed.data, prefixDigest: try sgHash(encoder().encode(prefix)),
            committedIdentity: saved.commit.identity, discardedIdentity: discarded, producerPID: ProcessInfo.processInfo.processIdentifier)
        let selection = try encoder().encode(CommittedSelection(candidate: saved.data, prefix: prefix)), expected = try encoder().encode(value)
        try check(selection.count <= 192*1024*1024 && expected.count <= 192*1024*1024 && selection.count+expected.count <= 512*1024*1024, "actual fixture encoding caps")
        try selection.write(to: URL(fileURLWithPath: args[2]), options: .atomic)
        try expected.write(to: URL(fileURLWithPath: args[3]), options: .atomic)
    } else {
        // The future expected suffix is opened only after actual native continuation.
        let expected = try JSONDecoder().decode(Expected.self, from: boundedRead(args[3], maximum: 192*1024*1024))
        try check(expected.producerPID != ProcessInfo.processInfo.processIdentifier, "fresh sequential restore process")
        try check(try expected.prefixDigest == sgHash(encoder().encode(prefix)) && expected.committedIdentity == saved.commit.identity, "exact retained committed prefix/identity")
        try check(suffix == expected.suffix, "exact event/ID/usage/ending suffix bytes and ordinals")
        try atCompareTraces(traces, expected.traces); try pfCompare(host.committed, ProviderCandidate(data: expected.final))
        discarded = expected.discardedIdentity
        try check(selected.discard == (discarded != nil) && discarded != saved.commit.identity, "committed selection excludes unpublished candidate")
    }
    try check(Memory.peakMemory <= 128*1024*1024, "tiny native tensor bound")
    let cut = try pfRow(saved)
    let row: [String: Any] = ["result":"PASS", "case":name, "mode":mode, "pid":ProcessInfo.processInfo.processIdentifier,
        "fixture":selected.fixture, "boundary":selected.cut, "checkpoint_sha256":sgHash(saved.data), "checkpoint_bytes":saved.data.count,
        "committed_identity":saved.commit.identity, "discarded_identity":discarded ?? "none",
        "binding_sha256":try sgHash(encoder().encode(setup.binding)), "prefix_sha256":try sgHash(encoder().encode(prefix)),
        "suffix_sha256":try sgHash(encoder().encode(suffix)), "prefix_batches":prefix.count, "suffix_batches":suffix.count,
        "suffix_events":try pfEvents(suffix).count, "phase_at_cut":cut.phase, "ordinal_at_cut":cut.ordinal,
        "terminal_at_cut":cut.terminal, "terminal_final":host.live.isTerminal,
        "restore_model_calls":0, "restore_prefill_calls":0, "restore_replacement_ids":0,
        "model_calls":setup.calls, "factory_calls":setup.factories, "mlx_peak_bytes":Memory.peakMemory,
        "history_authority":"caller-selected committed record and prior event bytes; no durable-write or real-fencing claim"]
    print(String(decoding: try JSONSerialization.data(withJSONObject: row, options: .sortedKeys), as: UTF8.self))
}
do { try Device.withDefaultDevice(Device(.gpu)) { try worker() } }
catch { FileHandle.standardError.write(Data("PROVIDER_WORKER_FAIL: \(error)\n".utf8)); exit(1) }
