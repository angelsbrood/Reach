import Foundation
import DurableClientReceipts
import HostClientContract
import Darwin

do {
    let config = try HandoffPipe.read()
    guard config.action == "open", let path = config.path, let root = config.root, let key = config.key,
          let bytes = config.context, let time = config.time, let fresh = config.create else { throw HandoffError.invalid }
    let a = try ClientAuthority(HandoffContract.decode(ClientContext.self, bytes, maximum: HandoffContract.context))
    let auth = ClientAuthorization(caller: a.context.caller)
    let clock = try FixtureClientClock(id: "s84-client-worker", time: time), environment = try ClientEnvironment(rootID: root, clock: clock)
    var boundary = ""
    func pause(_ point: String) throws {
        if boundary == point {
            var message = HandoffMessage("boundary"); message.boundary = point; try HandoffPipe.write(message)
            guard try HandoffPipe.read().action == "continue" else { throw HandoffError.invalid }
        }
    }
    let (owner, handle) = try DurableClientReceipts.openHostJoin(at: path, fresh: fresh, environment: environment,
        metadataKey: key, clock: clock, authority: a, authorization: auth) { try pause($0.rawValue) }
    defer { owner.close() }
    func tool() throws -> ToolBinding {
        for batch in try owner.inbox(handle, authority: a, authorization: auth) {
            for event in try ClientEvents.decode(batch) {
                if case .toolCallAppendArguments(_, let id, let name, let args, _) = event {
                    return try .init(id: Data(id.utf8), name: Data(name.utf8), arguments: Data(args.utf8))
                }
            }
        }
        throw HandoffError.invalid
    }
    var initial = HandoffMessage("ready"); initial.witness = try owner.hostWitness(handle, authority: a, authorization: auth)
    try HandoffPipe.write(initial)
    while true {
        let request = try HandoffPipe.read(); boundary = request.boundary ?? ""
        if let time = request.time { clock.time = time }; if let allowed = request.allowed { auth.allowed = allowed }
        if request.action == "close" { try HandoffPipe.write(.init("closed")); break }
        do {
            var response = HandoffMessage("ok")
            switch request.action {
            case "accept":
                guard let frame = request.frame, let cursor = request.cursor else { throw HandoffError.invalid }
                response.witness = try owner.acceptHostBatch(frame, requestedCursor: cursor, handle: handle, authority: a, authorization: auth)
                try pause("afterWitness")
            case "witness": response.witness = try owner.hostWitness(handle, authority: a, authorization: auth)
            case "begin", "effect":
                let binding = try tool()
                switch try owner.beginEffect(binding, handle: handle, authority: a, authorization: auth) {
                case .fresh:
                    response.state = "fresh"
                    if request.action == "effect" {
                        try HandoffPipe.write(.init("fake-effect"))
                        guard try HandoffPipe.read().action == "effect-recorded" else { throw HandoffError.invalid }
                        try pause("afterFakeEffect")
                        let outcome = try ClientOutcome.make(kind: .success, result: Data("s84-known-result".utf8), binding: binding, authority: a)
                        _ = try owner.recordOutcome(outcome, binding: binding, handle: handle, authority: a, authorization: auth)
                        response.state = "known"; response.result = outcome.result
                    }
                case .unknown: response.state = "unknown"
                case .known(let outcome): response.state = "known"; response.result = outcome.result
                }
            case "state":
                switch try owner.effect(tool(), handle: handle, authority: a, authorization: auth) {
                case .unbegun: response.state = "unbegun"
                case .unknown: response.state = "unknown"
                case .known(let outcome): response.state = "known"; response.result = outcome.result
                }
            case "maintenance": try owner.maintenance()
            default: throw HandoffError.invalid
            }
            try HandoffPipe.write(response)
        } catch { try HandoffPipe.write(.init("refused")) }
    }
} catch { try? HandoffPipe.write(.init("unavailable")); exit(1) }
