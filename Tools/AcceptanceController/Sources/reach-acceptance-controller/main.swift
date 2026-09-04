import AcceptanceControllerCore
import Foundation
import Darwin

private func fail(_ code: Int32, _ message: String) -> Never {
    _ = ReceiptWriter.write(Data(message.utf8), descriptor: STDERR_FILENO)
    Darwin.exit(code)
}

private func parseRun(_ arguments: [String]) throws -> (URL, URL, URL) {
    guard arguments.count == 6 else { throw ControllerError.usage("run-options") }
    var values: [String: String] = [:]
    var index = 0
    while index < arguments.count {
        let option = arguments[index]
        guard ["--scratch", "--spec", "--packet"].contains(option), values[option] == nil else {
            throw ControllerError.usage("run-option")
        }
        values[option] = arguments[index + 1]
        index += 2
    }
    guard let scratch = values["--scratch"], let spec = values["--spec"], let packet = values["--packet"],
          scratch.hasPrefix("/"), spec.hasPrefix("/"), packet.hasPrefix("/") else {
        throw ControllerError.usage("absolute-paths")
    }
    return (URL(fileURLWithPath: scratch), URL(fileURLWithPath: spec), URL(fileURLWithPath: packet))
}

private func executableURL() -> URL {
    URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.resolvingSymlinksInPath()
}

private func runFixture(_ name: String) -> Never {
    let environment = ProcessInfo.processInfo.environment
    let id = environment["REACH_ACTION_ID"] ?? "fixture"
    let ordinal = Int(environment["REACH_ACTION_ORDINAL"] ?? "0") ?? 0
    func emit(_ envelope: ResultEnvelope, exit code: Int32 = 0) -> Never {
        do {
            let data = try CanonicalJSON.encode(envelope)
            guard ReceiptWriter.write(data, descriptor: STDOUT_FILENO) else { Darwin.exit(70) }
            Darwin.exit(code)
        } catch { fail(70, "fixture-encoding") }
    }
    switch name {
    case "ok-a":
        emit(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .ok, fields: ["label": .string("alpha"), "value": .integer(7)]))
    case "ok-b":
        emit(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .ok, fields: ["flag": .boolean(true), "label": .string("beta")]))
    case "stop":
        emit(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .stop, fields: ["edge": .string("synthetic")], reasonCode: "syntheticStop"))
    case "refusal":
        emit(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .refusal, fields: [:], reasonCode: "syntheticRefusal"))
    case "nonzero":
        emit(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .ok, fields: ["value": .integer(23)]), exit: 23)
    case "malformed":
        _ = ReceiptWriter.write(Data("{".utf8), descriptor: STDOUT_FILENO); Darwin.exit(0)
    case "invalid-utf8":
        _ = Darwin.write(STDOUT_FILENO, [UInt8(0xff)], 1); Darwin.exit(0)
    case "trailing":
        let valid = try! CanonicalJSON.encode(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .ok, fields: [:]))
        _ = ReceiptWriter.write(valid + Data("x".utf8), descriptor: STDOUT_FILENO); Darwin.exit(0)
    case "duplicate":
        let text = "{\"actionID\":\"\(id)\",\"actionID\":\"\(id)\",\"fields\":{},\"kind\":\"ok\",\"ordinal\":\(ordinal),\"reasonCode\":null,\"version\":1}"
        _ = ReceiptWriter.write(Data(text.utf8), descriptor: STDOUT_FILENO); Darwin.exit(0)
    case "unknown":
        let text = "{\"actionID\":\"\(id)\",\"extra\":true,\"fields\":{},\"kind\":\"ok\",\"ordinal\":\(ordinal),\"reasonCode\":null,\"version\":1}"
        _ = ReceiptWriter.write(Data(text.utf8), descriptor: STDOUT_FILENO); Darwin.exit(0)
    case "type-mismatch":
        let text = "{\"actionID\":\"\(id)\",\"fields\":{},\"kind\":\"ok\",\"ordinal\":\"bad\",\"reasonCode\":null,\"version\":1}"
        _ = ReceiptWriter.write(Data(text.utf8), descriptor: STDOUT_FILENO); Darwin.exit(0)
    case "secret":
        emit(ResultEnvelope(actionID: id, ordinal: ordinal, kind: .ok, fields: ["token": .string("Bearer synthetic")]))
    case "oversize":
        let chunk = Data(repeating: 0x61, count: 64 * 1024)
        for _ in 0..<20 { _ = chunk.withUnsafeBytes { Darwin.write(STDOUT_FILENO, $0.baseAddress, $0.count) } }
        Darwin.exit(0)
    case "timeout":
        let descendant = Process()
        descendant.executableURL = URL(fileURLWithPath: "/bin/sleep")
        descendant.arguments = ["120"]
        try? descendant.run()
        descendant.waitUntilExit()
        Darwin.exit(0)
    default:
        fail(64, "unknown-fixture")
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else { fail(64, "usage") }

switch command {
case "run":
    do {
        let parsed = try parseRun(Array(arguments.dropFirst()))
        let result = try AcceptanceController().run(
            specURL: parsed.1, scratchURL: parsed.0, packetURL: parsed.2,
            executableURL: executableURL()
        )
        guard ReceiptWriter.write(result.receipt, descriptor: STDOUT_FILENO) else { Darwin.exit(70) }
        Darwin.exit(result.exitCode)
    } catch let error as ControllerError {
        switch error {
        case .usage, .input: fail(64, error.description)
        default: fail(70, error.description)
        }
    } catch { fail(70, "controller-failure") }
case "verify":
    guard arguments.count == 3, arguments[1] == "--packet", arguments[2].hasPrefix("/") else { fail(64, "verify-usage") }
    do {
        let path = URL(fileURLWithPath: arguments[2])
        let packet = try PacketPublisher.verify(path)
        let outcomeData = try Data(contentsOf: path.appendingPathComponent("outcome.json"))
        let receipt = VerificationReceipt(
            version: 1, path: path.path, packetRootDigest: packet.rootDigest,
            outcomeDigest: SHA256.hex(outcomeData)
        )
        guard ReceiptWriter.write(try CanonicalJSON.encode(receipt), descriptor: STDOUT_FILENO) else { Darwin.exit(70) }
        Darwin.exit(0)
    } catch let error as ControllerError {
        fail(65, error.description)
    } catch { fail(70, "verifier-internal") }
case "fixture":
    guard arguments.count == 2 else { fail(64, "fixture-usage") }
    runFixture(arguments[1])
default:
    fail(64, "unknown-command")
}
