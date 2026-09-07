import Foundation
import DurableClientReceipts
import ClientReceiptFixtures
import Darwin

struct Configuration: Decodable {
    let path: String, rootID: String, key: Data, namespace: String, action: String, boundary: String
    let create: Bool
    let time: UInt64, issued: UInt64, expires: UInt64
}
func emit(_ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    FileHandle.standardOutput.write(data+Data([10]))
}
func pause(_ point: String, configured: String) throws {
    if configured == point { try emit(["signal": point]); guard readLine() == "continue" else { exit(4) } }
}
do {
    guard let line = readLine(), line.utf8.count <= 16384 else { exit(2) }
    let c = try JSONDecoder().decode(Configuration.self, from: Data(line.utf8))
    let clock = try FixtureClientClock(id: "worker", time: c.time)
    let environment = try ClientEnvironment(rootID: c.rootID, clock: clock)
    let a = try ReceiptFixtures.authority(namespace: c.namespace, issued: c.issued, expires: c.expires)
    let auth = ClientAuthorization(caller: a.context.caller)
    var armed = false
    let client: DurableClientReceipts
    do {
        client = try .init(path: c.path, create: c.create, environment: environment, metadataKey: c.key, clock: clock) { point in
            if armed { try pause(point.rawValue, configured: c.boundary) }
        }
    } catch ClientError.busy { try emit(["busy": true]); exit(0) }
    defer { client.close() }
    if c.action == "hold" { try emit(["signal": "locked"]); _ = readLine(); exit(0) }
    if c.action == "maintenance" {
        armed = true; try client.maintenance()
        var expired = false
        do { _ = try client.open(a, authorization: auth) } catch ClientError.expired { expired = true }
        try emit(["expired": expired]); exit(0)
    }
    let h = try client.open(a, authorization: auth)
    armed = true
    if c.action == "accept" || c.action == "setup" { _ = try client.accept(ReceiptFixtures.frame(), requestedCursor: 0, handle: h, authority: a, authorization: auth) }
    if c.action == "begin" || c.action == "effect" || c.action == "retry" {
        let result = try client.beginEffect(ReceiptFixtures.binding(), handle: h, authority: a, authorization: auth)
        if case .fresh = result {
            if c.action == "retry" { try emit(["unexpectedFresh": true]); exit(3) }
            if c.action == "effect" {
                // Only the surviving Python supervisor performs this independent fake effect.
                try emit(["signal": "fake-effect"])
                guard readLine() == "effect-recorded" else { exit(4) }
                try pause("afterFakeEffect", configured: c.boundary)
                _ = try client.recordOutcome(ReceiptFixtures.outcome(a), binding: ReceiptFixtures.binding(), handle: h, authority: a, authorization: auth)
            }
        }
    }
    let r = try client.receipt(h, authority: a, authorization: auth)
    var state = "absent", exact = false
    if r.registeredCalls > 0 {
        switch try client.effect(ReceiptFixtures.binding(), handle: h, authority: a, authorization: auth) {
        case .unbegun: state = "unbegun"
        case .unknown: state = "unknown"
        case .known(let value): state = "known"; exact = try value == ReceiptFixtures.outcome(a)
        }
    }
    try emit(["high": r.high, "calls": r.registeredCalls, "terminal": r.terminal, "state": state,
              "exactOutcome": exact, "epoch": client.ownerEpoch])
} catch {
    // Do not stringify key/context-bearing values or protocol messages.
    try? emit(["refused": true]); exit(1)
}
