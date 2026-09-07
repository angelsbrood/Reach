import Foundation
import Darwin
import MLX
import LifecycleFixtures
import DurableSessionLifecycle
import DurableHostStore

func emit(_ value: [String: Any]) throws {
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) + Data([10]))
}
// Root keys and optional surviving ticket use an inherited anonymous pipe.
// The newly issued ticket returns only over the private stdout pipe.
func injection(_ fd: Int32) throws -> (LifecycleKeys, SessionTicket?) {
    defer { _ = Darwin.close(fd) }
    var data = Data(), buffer = [UInt8](repeating: 0, count: 1024)
    while true {
        let n = Darwin.read(fd, &buffer, buffer.count)
        if n < 0 && errno == EINTR { continue }
        try check(n >= 0, "injection read")
        if n == 0 { break }
        try check(data.count+n <= 64+LifecycleLimits.ticket, "injection bound")
        data.append(contentsOf: buffer.prefix(n))
    }
    try check(data.count >= 64, "two injected root keys")
    let keys = try LifecycleKeys(catalog: data.prefix(32), ticket: data.subdata(in: 32..<64))
    return (keys, data.count == 64 ? nil : try SessionTicket(data: data.dropFirst(64)))
}
func main() throws {
    let a = CommandLine.arguments
    if a.count == 2 && a[1] == "clock" {
        try emit(["pid":getpid(), "clock":try SystemLifecycleClock().now()]); return
    }
    try check(a.count == 10, "worker arguments")
    let mode = a[1], path = a[2], incarnation = a[3], cut = a[5], action = a[6]
    guard let fd = Int32(a[4]), let initialCursor = UInt64(a[7]), let time = UInt64(a[8]), let finalTime = UInt64(a[9]) else { throw CheckFailure("worker numbers") }
    let (keys, retainedTicket) = try injection(fd)
    let clock = try FixtureLifecycleClock(id: "supervised-v1", time: time)
    let identity = try LifecycleIdentity(incarnation: incarnation, clock: clock), auth = caller()
    let owner: DurableSessionLifecycle
    do {
        owner = try mode == "initialize" || mode == "lock-init"
            ? DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock)
            : DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock)
    } catch LifecycleError.busy {
        try check(mode == "contender", "unexpected owner contention")
        try emit(["kind":"busy", "pid":getpid(), "factories":0]); return
    }
    defer { owner.close() }
    if mode.hasPrefix("lock") || mode == "contender" {
        try emit(["kind":"locked", "pid":getpid(), "epoch":owner.ownerEpoch, "factories":0])
        if mode != "contender" { _ = readLine() }; return
    }
    let ticket: SessionTicket
    if let retainedTicket { ticket = retainedTicket }
    else {
        ticket = try owner.issueTicket(authorization: auth)
        try emit(["kind":"ticket", "bytes":ticket.data.base64EncodedString()])
    }
    // Binding construction stays on CPU; actual model factories remain lazy.
    let setup = try Device.withDefaultDevice(Device(.cpu)) { try PFSetup("ordinary") }
    owner.fault = { point in
        if point.rawValue == cut {
            try emit(["kind":"cut", "point":cut, "pid":getpid(), "native_calls":setup.calls,
                      "factories":setup.factories, "mlx_peak_bytes":Memory.peakMemory])
            _ = readLine(); throw CheckFailure("cut unexpectedly resumed")
        }
    }
    let initial = try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding)
    try emit(["kind":"recovered", "pid":getpid(), "epoch":owner.ownerEpoch, "phase":initial.phase.rawValue,
              "high":initial.high, "resumable":initial.resumable, "restore_calls":setup.calls, "restore_factories":setup.factories])
    var cursor = initialCursor
    func done(_ state: LifecycleStatus) throws {
        try emit(["kind":"done", "pid":getpid(), "epoch":owner.ownerEpoch, "phase":state.phase.rawValue,
                  "high":state.high, "native_calls":setup.calls, "prefills":setup.prefills, "factories":setup.factories,
                  "mlx_peak_bytes":Memory.peakMemory, "traces":try JSONSerialization.jsonObject(with: encoder().encode(setup.traces()))])
    }
    if action == "inspect" || initial.phase == .tombstone { try done(initial); return }
    let attached = try owner.attach(ticket: ticket, authorization: auth, generation: "g", cursor: cursor)
    guard let attachment = attached.attachment else { throw CheckFailure("live attachment") }
    if action == "cancel-empty" && initial.phase == .allocating {
        let realCut = owner.fault
        owner.fault = { if $0 == .afterPreparing { throw CheckFailure("injected empty setup stop") } }
        var stopped = false
        do { _ = try owner.step(ticket: ticket, authorization: auth, attachment: attachment) { throw CheckFailure("empty setup invoked model") } }
        catch let error as CheckFailure { stopped = String(describing: error) == "injected empty setup stop" }
        try check(stopped, "exact injected setup stop"); owner.fault = realCut
    }
    if action == "cancel" || action == "cancel-empty" {
        try done(owner.cancel(ticket: ticket, authorization: auth, attachment: attachment)); return
    }
    if action == "expire" {
        clock.time = finalTime; try owner.maintenance()
        try done(owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding)); return
    }
    for _ in 0..<501 {
        for frame in try owner.replay(ticket: ticket, authorization: auth, attachment: attachment, after: cursor) {
            try emit(["kind":"frame", "first":frame.firstSequence, "count":frame.count, "commit":frame.providerCommit,
                      "bytes":frame.eventBytes.base64EncodedString(), "skip":frame.skipPrefix])
            guard let line = readLine(), let ack = UInt64(line) else { throw CheckFailure("publication receipt") }
            try check(ack == frame.firstSequence+UInt64(frame.count)-1 && ack >= cursor, "whole offered remainder receipt"); cursor = ack
        }
        try owner.acknowledgeDelivery(ticket: ticket, authorization: auth, attachment: attachment, through: cursor)
        let state = try owner.begin(ticket: ticket, authorization: auth, generation: "g", provider: setup.binding)
        if state.phase == .terminal { try done(state); return }
        try check(action == "complete", "unexpected active replay")
        _ = try owner.step(ticket: ticket, authorization: auth, attachment: attachment) { setup.runtime }
    }
    throw CheckFailure("bounded worker steps")
}
do { try main() }
catch { fputs("LifecycleWorker refused: \(error)\n", stderr); exit(1) }
