import Foundation
import Testing
@testable import ReachWire

private enum GoldenCorpusError: Error, CustomStringConvertible {
    case malformedLedger(String)
    case expectedFailure(String)

    var description: String {
        switch self {
        case .malformedLedger(let line): "malformed golden-corpus ledger row: \(line)"
        case .expectedFailure(let name): "golden-corpus invalid fixture unexpectedly decoded: \(name)"
        }
    }
}

private func corpusRoot() -> URL? {
    guard let path = ProcessInfo.processInfo.environment["REACH_WIRE_CORPUS_ROOT"], !path.isEmpty else {
        return nil
    }
    return URL(fileURLWithPath: path, isDirectory: true)
}

private func corpusFrame(_ data: Data) throws -> RawFrame {
    var reassembler = FrameReassembler()
    let frames = try reassembler.feed(data)
    return try #require(frames.count == 1 ? frames[0] : nil)
}

private func corpusReencode(_ raw: RawFrame, version: UInt8) throws -> Data {
    switch raw.type {
    case .hello: try FrameCodec.encode(try raw.decode(Hello.self), for: version)
    case .helloAck: try FrameCodec.encode(try raw.decode(HelloAck.self), for: version)
    case .sessionOpen: try FrameCodec.encode(try raw.decode(SessionOpen.self), for: version)
    case .sessionOpened: try FrameCodec.encode(try raw.decode(SessionOpened.self), for: version)
    case .grantSubscribe: try FrameCodec.encode(try raw.decode(GrantSubscribe.self), for: version)
    case .grantEvent: try FrameCodec.encode(try raw.decode(GrantEvent.self), for: version)
    case .grantRule: try FrameCodec.encode(try raw.decode(GrantRule.self), for: version)
    case .ping: try FrameCodec.encode(try raw.decode(Ping.self), for: version)
    case .pong: try FrameCodec.encode(try raw.decode(Pong.self), for: version)
    case .errorFrame: try FrameCodec.encode(try raw.decode(ErrorFrame.self), for: version)
    case .generateBegin: try FrameCodec.encode(try raw.decode(GenerateBegin.self), for: version)
    case .generateReattach: try FrameCodec.encode(try raw.decode(GenerateReattach.self), for: version)
    case .generateCancel: try FrameCodec.encode(try raw.decode(GenerateCancel.self), for: version)
    case .evAck: try FrameCodec.encode(try raw.decode(EvAck.self), for: version)
    case .ev: try FrameCodec.encode(try raw.decode(Ev.self), for: version)
    case .enrollBegin: try FrameCodec.encode(try raw.decode(EnrollBegin.self), for: version)
    case .enrollChallenge: try FrameCodec.encode(try raw.decode(EnrollChallenge.self), for: version)
    case .enrollCertRequest: try FrameCodec.encode(try raw.decode(EnrollCertRequest.self), for: version)
    case .enrollGrant: try FrameCodec.encode(try raw.decode(EnrollGrant.self), for: version)
    case .enrollComplete: try FrameCodec.encode(try raw.decode(EnrollComplete.self), for: version)
    case .enrollConfirmed: try FrameCodec.encode(try raw.decode(EnrollConfirmed.self), for: version)
    case .appEnrollBegin: try FrameCodec.encode(try raw.decode(AppEnrollBegin.self), for: version)
    case .appEnrollCertRequest: try FrameCodec.encode(try raw.decode(AppEnrollCertRequest.self), for: version)
    case .appEnrollGrant: try FrameCodec.encode(try raw.decode(AppEnrollGrant.self), for: version)
    }
}

private func corpusFailureCategory(_ error: any Error) -> String {
    switch error {
    case WireError.frameTooLarge: "frame-too-large"
    case WireError.unknownFrameType: "unknown-frame-type"
    case WireError.malformedFrame: "malformed-frame"
    case WireError.unexpectedFrame: "unexpected-frame"
    case WireError.frameRequiresVersion: "frame-requires-version"
    default: "foreign:\(String(describing: error))"
    }
}

private func rejectCorpusFixture(named name: String, data: Data) throws {
    switch name {
    case "zero-length-envelope", "oversized-incoming-envelope", "unknown-frame-type":
        var reassembler = FrameReassembler()
        _ = try reassembler.feed(data)
    case "malformed-json-body":
        _ = try corpusFrame(data).decode(Ping.self)
    case "mismatched-concrete-frame":
        _ = try corpusFrame(data).decode(Pong.self)
    case "unknown-transcript-entry":
        _ = try corpusFrame(data).decode(GenerateBegin.self)
    case "unknown-wire-event":
        _ = try corpusFrame(data).decode(Ev.self)
    case _ where name.hasPrefix("relay-"):
        _ = try corpusFrame(data).decode(HelloAck.self)
    default:
        throw GoldenCorpusError.malformedLedger(name)
    }
    throw GoldenCorpusError.expectedFailure(name)
}

@Suite struct GoldenCorpusTests {
    @Test func everyFrozenFrameDecodesAndReencodesByteIdentically() throws {
        guard let root = corpusRoot() else { return }
        let ledger = try String(
            contentsOf: root.appendingPathComponent("valid-ledger.tsv"),
            encoding: .utf8
        )
        let rows = ledger.split(separator: "\n").dropFirst()
        #expect(rows.count == 57)

        for row in rows {
            let columns = row.split(separator: "\t", omittingEmptySubsequences: false)
            guard columns.count == 4,
                  let typeByte = UInt8(columns[1]),
                  let version = UInt8(columns[2]),
                  let byteCount = Int(columns[3])
            else { throw GoldenCorpusError.malformedLedger(String(row)) }
            let name = String(columns[0])
            let encoded = try Data(contentsOf: root.appendingPathComponent("valid/\(name).frame"))
            #expect(encoded.count == byteCount, "\(name) byte count")
            let raw = try corpusFrame(encoded)
            #expect(raw.type.rawValue == typeByte, "\(name) frame type")
            #expect(try corpusReencode(raw, version: version) == encoded, "\(name) canonical bytes")
        }

        for name in ["nested-schema", "enum-schema"] {
            let data = try Data(contentsOf: root.appendingPathComponent("values/\(name).json"))
            let schema = try JSONDecoder().decode(WireGenerationSchema.self, from: data)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            #expect(try encoder.encode(schema) == data, "\(name) canonical schema")
        }
        for state in WireGenerationState.allCasesForGoldenCorpus {
            let data = try Data(contentsOf: root.appendingPathComponent("values/generation-state-\(state.rawValue).json"))
            #expect(try JSONDecoder().decode(WireGenerationState.self, from: data) == state)
        }
    }

    @Test func unknownOptionalsCanonicalizeAndInvalidFixturesKeepTheirCategories() throws {
        guard let root = corpusRoot() else { return }
        for name in [
            "hello-unknown-optional",
            "hello-ack-unknown-optional",
            "generate-begin-nested-unknown-optionals",
        ] {
            let source = try Data(contentsOf: root.appendingPathComponent("unknown/\(name).source.frame"))
            let canonical = try Data(contentsOf: root.appendingPathComponent("unknown/\(name).canonical.frame"))
            #expect(try corpusReencode(corpusFrame(source), version: 0) == canonical, "\(name) canonicalization")
        }

        let ledger = try String(
            contentsOf: root.appendingPathComponent("invalid-ledger.tsv"),
            encoding: .utf8
        )
        let expected = try Dictionary(uniqueKeysWithValues: ledger.split(separator: "\n").dropFirst().map { row in
            let columns = row.split(separator: "\t", omittingEmptySubsequences: false)
            guard columns.count == 3 else { throw GoldenCorpusError.malformedLedger(String(row)) }
            #expect(columns[1] == columns[2], "frozen invalid ledger did not settle")
            return (String(columns[0]), String(columns[1]))
        })
        let invalidDirectory = root.appendingPathComponent("invalid", isDirectory: true)
        let files = try FileManager.default.contentsOfDirectory(atPath: invalidDirectory.path)
            .filter { $0.hasSuffix(".fixture") }
            .sorted()
        #expect(files.count == 14)
        for file in files {
            let name = String(file.dropLast(".fixture".count))
            let expectedCategory = try #require(expected[name])
            let data = try Data(contentsOf: invalidDirectory.appendingPathComponent(file))
            do {
                try rejectCorpusFixture(named: name, data: data)
            } catch GoldenCorpusError.expectedFailure {
                Issue.record("\(name) unexpectedly decoded")
            } catch {
                #expect(corpusFailureCategory(error) == expectedCategory, "\(name) category")
            }
        }
    }
}

private extension WireGenerationState {
    static let allCasesForGoldenCorpus: [Self] = [.streaming, .complete, .failed, .cancelled]
}
