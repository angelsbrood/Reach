import Foundation
import ClockPolicy
import Darwin

// Line-delimited canonical JSON on controller-owned pipes; no sockets or arbitrary time inputs.
final class Channel {
    func read<T: Codable>(_ type: T.Type) throws -> T {
        var data = Data()
        while true {
            guard let byte = try FileHandle.standardInput.read(upToCount: 1), !byte.isEmpty
            else { throw Refusal.missing }
            if byte[0] == 10 { return try Wire.decode(type, data) }
            guard data.count < Wire.maximumBytes else { throw Refusal.capacity }
            data.append(byte)
        }
    }
    func write<T: Encodable>(_ value: T) throws {
        var data = try Wire.encode(value); data.append(10)
        try FileHandle.standardOutput.write(contentsOf: data)
    }
}

struct Hello: Codable { let profile: Profile; let identity: Identity; let sample: Sample }
struct Request: Codable {
    let kind: String
    var subjects: [String]?
    var challenge: Data?
    var event: String?
    var evidence: Data?
}
struct Reply: Codable {
    let kind: String
    var originals: [Originals]?
    var certificate: Data?
    var sample: Sample?
    var error: String?
}

func serve() throws {
    let witness = try Witness(clock: SystemClock())
    let channel = Channel()
    try channel.write(Hello(profile: .qualification, identity: witness.identity, sample: witness.observe()))
    while true {
        let request = try channel.read(Request.self)
        do {
            switch request.kind {
            case "fixtures":
                guard let subjects = request.subjects, subjects.count == 3,
                      Set(subjects).count == 3 else { throw Refusal.binding }
                // Fixed campaign durations; the command has no pin, deadline or clock override.
                let caps: [(UInt64, UInt64)] = [(180, 600), (600, 240), (600, 600)]
                var pairs: [Originals] = []
                for (subject, cap) in zip(subjects, caps) {
                    let h = try witness.register(subject: subject, role: .host, cap: cap.0 * 1_000_000_000)
                    let c = try witness.register(subject: subject, role: .client, cap: cap.1 * 1_000_000_000)
                    pairs.append(try Originals(pin: witness.identity, host: h, client: c))
                }
                try channel.write(Reply(kind: "fixtures", originals: pairs))
            case "certificate":
                guard let challenge = request.challenge else { throw Refusal.missing }
                try channel.write(Reply(kind: "certificate", certificate: witness.respond(to: challenge)))
            case "sample": try channel.write(Reply(kind: "sample", sample: witness.observe()))
            case "quit": try channel.write(Reply(kind: "bye")); return
            default: throw Refusal.binding
            }
        } catch {
            try channel.write(Reply(kind: "refusal", error: String(describing: error)))
        }
    }
}

do {
    let args = Array(CommandLine.arguments.dropFirst())
    switch args.first {
    case "witness" where args.count == 1: try serve()
    case "freshness" where args.count == 1: try freshness()
    case "receiver" where args.count == 3: try receiver(phase: args[1], root: args[2])
    default:
        throw NSError(domain: "usage: clock-qualification witness | freshness | receiver seed|postboot|replacement OWNED_ROOT", code: 2)
    }
} catch {
    let text = "REFUSE: \(error)\n"
    try? FileHandle.standardError.write(contentsOf: Data(text.utf8))
    exit(1)
}
