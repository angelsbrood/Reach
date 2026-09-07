import Foundation
import Darwin
import MLX
import LifecycleFixtures
import DurableSessionLifecycle
import ResumableMLXProvider
import HostClientContract

do {
    let config = try HandoffPipe.read()
    guard config.action == "open", let path = config.path, let root = config.root, let key = config.key,
          let ticketKey = config.ticketKey, let time = config.time, let fresh = config.create else { throw HandoffError.invalid }
    let clock = try FixtureLifecycleClock(id: "s84-host-worker", time: time)
    let identity = try LifecycleIdentity(incarnation: root, clock: clock), keys = try LifecycleKeys(catalog: key, ticket: ticketKey), auth = caller()
    var boundary = ""
    func pause(_ point: String) throws {
        if boundary == point {
            var message = HandoffMessage("boundary"); message.boundary = point; try HandoffPipe.write(message)
            guard try HandoffPipe.read().action == "continue" else { throw HandoffError.invalid }
        }
    }
    let owner = try fresh ? DurableSessionLifecycle.initialize(at: path, identity: identity, keys: keys, clock: clock) :
        DurableSessionLifecycle.reopen(at: path, identity: identity, keys: keys, clock: clock)
    defer { owner.close() }
    owner.fault = { try pause($0.rawValue) }
    let ticket = try fresh ? owner.issueTicket(authorization: auth, lifetime: config.lifetime ?? LifecycleLimits.session) : SessionTicket(data: config.ticket ?? Data())
    var attachment: LifecycleAttachment?, setup: PFSetup?
    func status(_ state: LifecycleStatus) -> HandoffMessage {
        var r = HandoffMessage("ok"); r.high = state.high; r.phase = state.phase.rawValue; r.terminal = state.providerEnding != nil
        r.disposition = state.disposition; r.calls = setup?.calls ?? 0; r.factories = setup?.factories ?? 0; r.peak = Memory.peakMemory; return r
    }
    var initial = HandoffMessage("ready"); initial.ticket = ticket.data; try HandoffPipe.write(initial)
    while true {
        let request = try HandoffPipe.read(); boundary = request.boundary ?? ""
        if let time = request.time { clock.time = time }; if let allowed = request.allowed { auth.allowed = allowed }
        if request.action == "close" { try HandoffPipe.write(.init("closed")); break }
        do {
            var response = HandoffMessage("ok")
            switch request.action {
            case "begin":
                guard let route = request.route, let name = request.generation else { throw HandoffError.invalid }
                setup = try Device.withDefaultDevice(Device(.cpu)) { try PFSetup(route) }
                setup!.binding.operationID = "s84-operation:"+name; setup!.binding.requestID = "s84-request:"+name
                let s = try owner.begin(ticket: ticket, authorization: auth, generation: name, provider: setup!.binding)
                attachment = s.attachment; response = status(s)
                if let attachment { response.context = try owner.exportClientContext(ticket: ticket, authorization: auth, attachment: attachment) }
            case "attach":
                guard let name = request.generation, let w = request.witness, let root = request.expectedRoot, let route = request.route else { throw HandoffError.invalid }
                setup = try Device.withDefaultDevice(Device(.cpu)) { try PFSetup(route) }
                setup!.binding.operationID = "s84-operation:"+name; setup!.binding.requestID = "s84-request:"+name
                let s = try owner.attachClient(ticket: ticket, authorization: auth, generation: name, witness: w, expectedClientRoot: root)
                attachment = s.attachment; response = status(s)
                if let attachment { response.context = try owner.exportClientContext(ticket: ticket, authorization: auth, attachment: attachment) }
            case "step":
                guard let attachment, let setup else { throw HandoffError.invalid }
                let s = try owner.step(ticket: ticket, authorization: auth, attachment: attachment) { setup.runtime }
                response = status(s); try pause("afterStep")
            case "replay":
                guard let attachment, let cursor = request.cursor else { throw HandoffError.invalid }
                let frames = try owner.replayForClient(ticket: ticket, authorization: auth, attachment: attachment, after: cursor)
                for frame in frames {
                    var r = HandoffMessage("batch"); r.frame = frame; try HandoffPipe.write(r)
                    guard try HandoffPipe.read().action == "next" else { throw HandoffError.invalid }
                }
                response.action = "replay-end"
            case "receipt":
                guard let w = request.witness, let root = request.expectedRoot, let name = request.generation else { throw HandoffError.invalid }
                let s = try owner.acceptClientWitness(w, expectedClientRoot: root, ticket: ticket, authorization: auth,
                    generation: name, attachment: attachment)
                response = status(s); try pause("afterReceipt")
            case "validate":
                guard let attachment, let setup else { throw HandoffError.invalid }
                try assertOutcome(owner.replay(ticket: ticket, authorization: auth, attachment: attachment, after: 0), setup: setup)
            case "maintenance": try owner.maintenance()
            default: throw HandoffError.invalid
            }
            guard Memory.peakMemory <= 128<<20 else { throw HandoffError.oversized }; try HandoffPipe.write(response)
        } catch { try HandoffPipe.write(.init("refused")) }
    }
} catch { try? HandoffPipe.write(.init("unavailable")); exit(1) }
