import Foundation
import Darwin
import MLX
import StoreFixtures
import DurableHostStore
import ResumableMLXProvider

func emit(_ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed])
    FileHandle.standardOutput.write(data + Data([10]))
}
func pipeKeys(_ fd: Int32) throws -> StoreKeys {
    defer { _ = Darwin.close(fd) }
    var bytes = [UInt8](repeating: 0, count: 65), count = 0
    while count < bytes.count {
        let remaining = bytes.count-count
        let n = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: count), remaining) }
        if n < 0 && errno == EINTR { continue }
        try check(n >= 0, "key pipe read")
        if n == 0 { break }; count += n
    }
    try check(count == 64, "exact two-key injection")
    return try StoreKeys(metadata: Data(bytes[0..<32]), content: Data(bytes[32..<64]))
}
func ordinal(_ candidate: ProviderCandidate?) throws -> Int {
    guard let candidate else { return -1 }
    let object = try JSONSerialization.jsonObject(with: candidate.commit.data) as! [String: Any]
    return (object["ordinal"] as! NSNumber).intValue
}
func main() throws {
    let a = CommandLine.arguments
    try check(a.count == 9, "worker arguments")
    let mode = a[1], route = a[2], path = a[3], storeID = a[4], keys = try pipeKeys(Int32(a[5])!)
    let cut = a[6], cutOrdinal = Int(a[7])!, initialCursor = UInt64(a[8])!
    let setup = try PFSetup(route), identity = try StoreIdentity(storeID: storeID, provider: setup.binding)
    let store: DurableHostStore
    do {
        store = try mode == "initialize" || mode == "lock-init"
            ? DurableHostStore.initialize(at: path, identity: identity, keys: keys)
            : DurableHostStore.reopen(at: path, identity: identity, keys: keys)
    } catch StoreError.busy {
        try check(mode == "contender", "unexpected contention")
        try emit(["kind":"busy", "pid":getpid(), "factories":setup.factories]); return
    }
    defer { store.close() }
    if mode.hasPrefix("lock") || mode == "contender" || mode == "exec" {
        try check(setup.factories == 0, "lock gate no model")
        try emit(["kind":"locked", "pid":getpid(), "epoch":store.ownerEpoch, "factories":0])
        if mode == "exec" {
            // The only inherited owner is this exec'd process. No lock FD dup or fork.
            _ = readLine()
            let args = [strdup("sleep"), strdup("5"), nil]
            execv("/bin/sleep", args)
            throw CheckFailure("exec failed")
        }
        if mode != "contender" { _ = readLine() }
        return
    }
    var attempt = 0
    store.fault = { point in
        if point.rawValue == cut && attempt == cutOrdinal {
            try emit(["kind":"cut", "point":cut, "ordinal":attempt, "pid":getpid()])
            // Real death: supervisor SIGKILLs and joins this blocked owned process.
            _ = readLine(); throw CheckFailure("cut unexpectedly resumed")
        }
    }
    let state = try store.snapshot(), startOrdinal = try ordinal(state.candidate)
    let generation: DurableGeneration
    if state.candidate == nil { generation = try .start(store: store) { setup.runtime } }
    else { generation = try .recover(store: store) { setup.runtime } }
    defer { generation.close() }
    let restoreCalls = state.candidate == nil ? 0 : setup.calls
    let restorePrefills = setup.prefills, restoreFactories = state.candidate == nil ? 0 : setup.factories
    try check(restoreCalls == 0 && restorePrefills == 0, "restore must not advance model")
    try emit(["kind":"recovered", "pid":getpid(), "epoch":store.ownerEpoch, "high":state.high,
              "terminal":state.terminal, "ordinal":startOrdinal, "restore_calls":restoreCalls, "restore_factories":restoreFactories])
    var cursor = initialCursor
    for _ in 0..<501 {
        for frame in try generation.replay(after: cursor) {
            try emit(["kind":"frame", "first":frame.firstSequence, "count":frame.count, "commit":frame.providerCommit,
                      "bytes":frame.eventBytes.base64EncodedString(), "skip":frame.skipPrefix])
            guard let line = readLine(), let ack = UInt64(line) else { throw CheckFailure("publication receipt missing") }
            try check(ack >= cursor && ack >= frame.firstSequence+UInt64(frame.count)-1, "whole offered remainder delivered")
            cursor = ack
        }
        try generation.acknowledgeDelivery(through: cursor)
        let latest = try store.snapshot()
        if latest.terminal {
            let traces = try JSONSerialization.jsonObject(with: encoder().encode(setup.traces()))
            try emit(["kind":"done", "pid":getpid(), "epoch":store.ownerEpoch, "high":latest.high,
                      "ordinal":try ordinal(latest.candidate), "native_calls":setup.calls-restoreCalls,
                      "prefills":setup.prefills, "factories":setup.factories, "mlx_peak_bytes":Memory.peakMemory, "traces":traces])
            return
        }
        attempt = try ordinal(latest.candidate)+1
        try generation.advance()
    }
    throw CheckFailure("worker transition bound")
}
do { try main() }
catch { fputs("StoreWorker refused: \(error)\n", stderr); exit(1) }
