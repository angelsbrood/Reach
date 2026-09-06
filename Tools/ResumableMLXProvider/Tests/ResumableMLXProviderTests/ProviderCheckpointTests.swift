import XCTest
import Foundation
import MLX
import ReachWire
@testable import MLXLMCommon
@testable import MLXGuidedGeneration
@testable import RequiredToolCoordinator
import ProviderFixtures
@testable import ResumableMLXProvider

final class ProviderCheckpointTests: XCTestCase {
    func testKnownDeclarationAndBindingRefusalsBeforeWork() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["ordinary", "guided", "required", "allowed"] {
                let setup = try PFSetup(name), host = try PFHost(setup); defer { host.live.close() }
                let saved = host.committed, calls = setup.calls
                var invalid: [ProviderBinding] = []
                var b = setup.binding; b.version = 2; invalid.append(b)
                b = setup.binding; b.policy += "changed"; invalid.append(b)
                b = setup.binding; b.operationID = String(repeating: "x", count: 257); invalid.append(b)
                for width in [-1, 0] {
                    b = setup.binding
                    switch b.lane {
                    case .ordinary(var t): t.options.vocabularySize = width; b.lane = .ordinary(t)
                    case .guided(var t): t.options.model.logitWidth = width; b.lane = .guided(t)
                    case .required(var t, let tokens): t.options.model.logitWidth = width; b.lane = .required(t, tokens: tokens)
                    case .allowed(var t): t.probeOptions.vocabularySize = width; b.lane = .allowed(t)
                    }
                    invalid.append(b)
                    if case .allowed(var t) = setup.binding.lane { t.guidedOptions.model.logitWidth = width; b.lane = .allowed(t); invalid.append(b) }
                }
                for b in invalid {
                    let fresh = try PFSetup(name)
                    if case .supported = ResumableMLXProvider.assess(b) { XCTFail("unsupported declaration reported supported") }
                    XCTAssertThrowsError(try ResumableMLXProvider.prepare(binding: b, runtime: fresh.runtime, owner: "owner", credit: ResumableMLXProvider.reservationBytes))
                    XCTAssertThrowsError(try ResumableMLXProvider.restore(committed: saved, expected: b, runtime: fresh.runtime, owner: "new-owner"))
                    XCTAssertEqual(fresh.factories, 0); XCTAssertEqual(fresh.calls, 0); XCTAssertEqual(fresh.prefills, 0)
                    XCTAssertEqual(host.committed, saved); XCTAssertEqual(setup.calls, calls); XCTAssertFalse(host.live.isClosed)
                }
                var changed = setup.binding; changed.requestID += "x"
                let fresh = try PFSetup(name)
                XCTAssertThrowsError(try ResumableMLXProvider.restore(committed: saved, expected: changed, runtime: fresh.runtime, owner: "owner"))
                XCTAssertEqual(fresh.factories, 0)
                changed = setup.binding
                changed.lane = try PFSetup(name == "ordinary" ? "guided" : "ordinary").binding.lane
                XCTAssertThrowsError(try ResumableMLXProvider.restore(committed: saved, expected: changed, runtime: fresh.runtime, owner: "owner"))
                changed = setup.binding
                switch changed.lane {
                case .ordinary(var t): t.tokens[0] += 1; changed.lane = .ordinary(t)
                case .guided(var t): t.specification.source = "{}"; changed.lane = .guided(t)
                case .required(var t, let tokens): t.tools[0].schemaJSON = "{}"; changed.lane = .required(t, tokens: tokens)
                case .allowed(var t): t.tools[0].schemaJSON = "{}"; changed.lane = .allowed(t)
                }
                XCTAssertThrowsError(try ResumableMLXProvider.restore(committed: saved, expected: changed, runtime: fresh.runtime, owner: "owner"))
                XCTAssertEqual(fresh.factories, 0); XCTAssertEqual(fresh.calls, 0)
            }
        }
    }
    func testOuterJoinsAndFullTerminalNativeRestore() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            for name in ["ordinary", "guided", "required", "allowed"] {
                let setup = try PFSetup(name), host = try PFHost(setup); defer { host.live.close() }
                let c0 = host.committed; try host.drain(); let saved = host.committed, before = setup.calls
                let changes: [(inout ProviderCheckpointDocument) throws -> Void] = [
                    { $0.phase = "contradictory" }, { $0.child = Data([1,2,3]) }, { $0.child = try c0.checkpoint().child },
                    { $0.binding.requestID += "other" }]
                for mutate in changes {
                    var cp = try saved.checkpoint(); try mutate(&cp)
                    let changed = try ProviderCandidate(checkpoint: cp, events: saved.eventBytes), fresh = try PFSetup(name)
                    XCTAssertThrowsError(try fresh.restore(changed)); XCTAssertEqual(fresh.calls, 0); XCTAssertEqual(fresh.prefills, 0)
                    XCTAssertEqual(setup.calls, before); XCTAssertEqual(host.committed, saved)
                }
                if name == "required" {
                    var cp = try saved.checkpoint(), required = try RequiredToolCheckpoint(data: cp.child).document()
                    var guided = try ResumableGuidedCheckpoint(data: required.child).document()
                    guided.guided.grammar.mask.words = []
                    required.child = try ResumableGuidedCheckpoint(document: guided).data; required.control.childDigest = sgHash(required.child)
                    cp.child = try RequiredToolCheckpoint(document: required).data
                    let changed = try ProviderCandidate(checkpoint: cp, events: saved.eventBytes), fresh = try PFSetup(name)
                    XCTAssertThrowsError(try fresh.restore(changed)); XCTAssertEqual(fresh.calls, 0)
                }
            }
        }
    }
    func testCommitIdentityOverflowAndEncodedBounds() throws {
        try Device.withDefaultDevice(Device(.gpu)) {
            let setup = try PFSetup("ordinary"), host = try PFHost(setup); defer { host.live.close() }
            let saved = host.committed, before = setup.calls
            for mutation in [
                { (d: inout ProviderDescriptor) in d.operationID = "foreign" },
                { $0.ordinal = 8; $0.previousID = String(repeating: "a", count: 64) },
                { $0.checkpointDigest = String(repeating: "b", count: 64) }] {
                var d = try saved.commit.descriptor(); mutation(&d); let foreign = try ProviderCommit(d)
                XCTAssertThrowsError(try host.live.acceptCommit(foreign, owner: host.owner))
                XCTAssertThrowsError(try host.live.advance(owner: host.owner, current: foreign, credit: ResumableMLXProvider.reservationBytes))
                XCTAssertEqual(host.live.acceptedCommit, saved.commit); XCTAssertEqual(setup.calls, before)
            }
            var cp = try saved.checkpoint(); cp.ordinal = UInt64.max; cp.previousID = String(repeating: "a", count: 64)
            let maximum = try ProviderCandidate(checkpoint: cp, events: saved.eventBytes), fresh = try PFSetup("ordinary"), full = try fresh.restore(maximum)
            defer { full.close() }
            XCTAssertThrowsError(try full.advance(owner: "owner-2", current: maximum.commit, credit: ResumableMLXProvider.reservationBytes))
            XCTAssertThrowsError(try full.cancel(owner: "owner-2", current: maximum.commit, credit: ResumableMLXProvider.reservationBytes))
            XCTAssertEqual(fresh.calls, 0); XCTAssertNil(try full.pendingCandidate()); XCTAssertFalse(full.isClosed)
            for bytes in [Data(), Data(saved.data.dropLast()), Data("bad".utf8)] { XCTAssertThrowsError(try ProviderCandidate(data: bytes)) }
            var doc = try JSONDecoder().decode(ProviderCandidateDocument.self, from: saved.data)
            doc.version = 2; XCTAssertThrowsError(try ProviderCandidate(data: encoder().encode(doc)))
            doc.version = 1; doc.events = Data("[ ]".utf8)
            XCTAssertThrowsError(try ProviderCandidate(data: encoder().encode(doc)))
            cp = try saved.checkpoint(); cp.terminal = .complete
            XCTAssertThrowsError(try ProviderCandidate(checkpoint: cp, events: saved.eventBytes))
            XCTAssertThrowsError(try ProviderCandidate(data: Data(repeating: 0, count: ProviderCandidate.maximumBytes + 1)))
            cp = try saved.checkpoint(); cp.child = Data(repeating: 0, count: ResumableTextCheckpoint.maximumBytes + 1)
            XCTAssertThrowsError(try ProviderCandidate(checkpoint: cp, events: saved.eventBytes))
            XCTAssertThrowsError(try ProviderCandidate(checkpoint: saved.checkpoint(), events: Data(repeating: 0, count: ProviderCandidate.maximumControlBytes + 1)))
            XCTAssertThrowsError(try ProviderEvents.encode(Array(repeating: .responseAppend(entryID: nil, text: "x", segmentID: nil, tokenCount: 1), count: 4097)))
            XCTAssertEqual(setup.calls, before); XCTAssertEqual(host.committed, saved)
        }
    }
}
