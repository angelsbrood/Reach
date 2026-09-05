import AcceptanceControllerCore
import Foundation
import Darwin

private struct SourceEntry: Codable {
    let path: String
    let sha256: String
}
private struct RunSummary: Codable {
    let name: String
    let exitCode: Int32
    let rawT0: UInt64
    let rawT1: UInt64
    let cleanupComplete: Bool
    let receipt: RunReceipt
    let verification: VerificationReceipt
    let knownFixtureChildAbsent: Bool?
}
private struct CampaignSummary: Codable {
    let version: Int
    let sourceManifestDigest: String
    let executableDigest: String
    let runs: [RunSummary]
    let mutantVerifierExit: Int32
    let observationScope: String
}
private let sourcePaths = [
    "Package.swift", "Sources/AcceptanceControllerCore/Types.swift",
    "Sources/AcceptanceControllerCore/ResourceLedger.swift",
    "Sources/AcceptanceControllerCore/ProcessRunner.swift",
    "Sources/AcceptanceControllerCore/EvidenceStore.swift",
    "Sources/AcceptanceControllerCore/PacketPublisher.swift",
    "Sources/reach-acceptance-controller/main.swift", "CampaignDriver.swift",
    "Tests/AcceptanceControllerCoreTests/ControllerTests.swift",
    "Tests/AcceptanceControllerCoreTests/PublicationTests.swift", "BootstrapLauncher.swift",
]
private func require(_ value: Bool, _ reason: String) throws {
    guard value else { throw ControllerError.evidence(reason) }
}
private func receiptData(_ data: Data) -> Data {
    data.last == 0x0a ? Data(data.dropLast()) : data
}
private func child(_ executable: String, _ arguments: [String], cwd: URL) throws -> ProcessResult {
    let now = RawClock.now()
    let result = try ProcessRunner.run(ActionSpec(
        id: "campaign-command", ordinal: 0, executable: executable, arguments: arguments,
        workingDirectory: cwd.path, workDeadlineNanoseconds: now + 30_000_000_000,
        settlementDeadlineNanoseconds: now + 36_000_000_000))
    try require(result.cleanupComplete, "campaign-command-cleanup")
    return result
}
private func campaign(root: URL, executable: URL) throws {
    try DurableFile.createDirectory(root)
    try require(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty, "fresh-campaign-root")
    let repo = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    func sources() throws -> Data {
        try CanonicalJSON.encode(sourcePaths.map { path in
            SourceEntry(path: "Tools/AcceptanceController/" + path,
                        sha256: try SHA256.file(repo.appendingPathComponent("Tools/AcceptanceController/" + path)))
        })
    }
    let manifest = try sources(), manifestDigest = SHA256.hex(manifest)
    let binaryDigest = try SHA256.file(executable)
    try DurableFile.write(manifest, to: root.appendingPathComponent("source-manifest.json"))
    var summaries: [RunSummary] = []
    for (name, fixtures, expectedExit) in [
        ("D1", ["ok-a", "ok-b"], Int32(0)),
        ("D2", ["ok-a", "stop", "ok-b"], Int32(20)),
        ("D3", ["ok-a", "timeout", "ok-b"], Int32(20)),
    ] {
        let runRoot = root.appendingPathComponent(name)
        try DurableFile.createDirectory(runRoot)
        let packet = runRoot.appendingPathComponent("packet")
        let source = runRoot.appendingPathComponent("source-manifest.json")
        let snapshot = runRoot.appendingPathComponent("launch-snapshot.json")
        try DurableFile.write(manifest, to: source)
        let launch = try CanonicalJSON.encode(["case": .string(name), "createdAt": .integer(Int(RawClock.now())),
                                               "executableDigest": .string(binaryDigest)] as [String: AnyCodable])
        try DurableFile.write(launch, to: snapshot)
        let now = RawClock.now()
        let actions = fixtures.enumerated().map { ordinal, fixture in
            let work = now + (fixture == "timeout" ? 2_000_000_000 : 10_000_000_000)
            return ActionSpec(
                id: "action-\(ordinal)", ordinal: ordinal, executable: executable.path,
                arguments: ["fixture", fixture],
                environment: ["REACH_ACTION_ID": "action-\(ordinal)", "REACH_ACTION_ORDINAL": String(ordinal),
                              "REACH_FIXTURE_CHILD_PID_FILE": runRoot.appendingPathComponent("known-child.json").path],
                workingDirectory: runRoot.path, workDeadlineNanoseconds: work,
                settlementDeadlineNanoseconds: work + 6_000_000_000,
                allowedReasonCodes: ["syntheticStop"])
        }
        let spec = RunSpec(runID: name, scratchRoot: runRoot.path, packetPath: packet.path,
                           launchSnapshotPath: snapshot.path, launchSnapshotDigest: SHA256.hex(launch),
                           sourceManifestPath: source.path, sourceManifestDigest: manifestDigest,
                           executableDigest: binaryDigest, actions: actions)
        let specURL = runRoot.appendingPathComponent("spec.json")
        try DurableFile.write(CanonicalJSON.encode(spec), to: specURL)
        let result = try child(executable.path, ["run", "--scratch", runRoot.path, "--spec", specURL.path, "--packet", packet.path], cwd: root)
        try require(result.exitCode == expectedExit, "case-\(name)-exit")
        let receipt = try CanonicalJSON.decode(RunReceipt.self, from: receiptData(result.stdout))
        try require(receipt.outcome.outcome == (name == "D1" ? .pass : .stop), "case-outcome")
        try require(receipt.outcome.publicResults["action-0"]?["value"] == .integer(7), "typed-result-a")
        if name == "D1" {
            try require(receipt.outcome.publicResults["action-1"]?["flag"] == .boolean(true), "typed-result-b")
        }
        let records = try CanonicalJSON.decode([ActionRecord].self, from: Data(contentsOf: packet.appendingPathComponent("action-table.json")))
        var knownAbsent: Bool?
        if name != "D1" {
            try require(records.count == 3 && records[2].state == .notStarted && receipt.outcome.earliestStopOrdinal == 1, "earliest-stop")
        }
        if name == "D2" { try require(records[1].reason == "syntheticStop", "explicit-stop") }
        if name == "D3" {
            try require(records[1].termination == "timeout" && records[1].timeoutDetectedAt != nil && records[1].groupAbsentAt != nil, "timeout-record")
            let known = try CanonicalJSON.decode([String: Int32].self, from: Data(contentsOf: runRoot.appendingPathComponent("known-child.json")))
            guard let pid = known["pid"], pid > 0 else { throw ControllerError.evidence("known-child-identity") }
            try require(known["pgid"] == records[1].processID, "known-child-group")
            knownAbsent = kill(pid, 0) == -1 && errno == ESRCH
            try require(knownAbsent == true, "known-child-survived")
        }
        let verified = try child(executable.path, ["verify", "--packet", packet.path], cwd: root)
        try require(verified.exitCode == 0, "original-verifier")
        let verification = try CanonicalJSON.decode(VerificationReceipt.self, from: receiptData(verified.stdout))
        try require(receipt.packetRootDigest == verification.packetRootDigest &&
                    receipt.outcomeDigest == verification.outcomeDigest, "receipt-verifier-join")
        try DurableFile.write(receiptData(result.stdout), to: runRoot.appendingPathComponent("receipt.json"))
        try DurableFile.write(receiptData(verified.stdout), to: runRoot.appendingPathComponent("verification.json"))
        summaries.append(RunSummary(name: name, exitCode: expectedExit, rawT0: result.rawT0, rawT1: result.rawT1,
                                    cleanupComplete: result.cleanupComplete, receipt: receipt,
                                    verification: verification, knownFixtureChildAbsent: knownAbsent))
    }
    let mutantParent = root.appendingPathComponent("mutant")
    try DurableFile.createDirectory(mutantParent)
    let mutant = mutantParent.appendingPathComponent("packet")
    try FileManager.default.copyItem(at: root.appendingPathComponent("D1/packet"), to: mutant)
    let outcome = mutant.appendingPathComponent("outcome.json")
    var damaged = try Data(contentsOf: outcome); damaged.append(0x78)
    try DurableFile.write(damaged, to: outcome, exclusive: false)
    let rejected = try child(executable.path, ["verify", "--packet", mutant.path], cwd: root)
    try require(rejected.exitCode == 65, "mutant-not-rejected")
    try require(try sources() == manifest && SHA256.file(executable) == binaryDigest, "qualification-binding-changed")
    let summary = CampaignSummary(version: 1, sourceManifestDigest: manifestDigest, executableDigest: binaryDigest,
                                  runs: summaries, mutantVerifierExit: 65,
                                  observationScope: "direct children, assigned process groups and known fixture child; no global or complete descendant claim")
    try DurableFile.write(CanonicalJSON.encode(summary), to: root.appendingPathComponent("SUMMARY.json"))
    print("PASS D1=0 D2=20 D3=20 originals=verified mutant=65")
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 4, arguments[0] == "--root", arguments[2] == "--controller",
      arguments[1].hasPrefix("/"), arguments[3].hasPrefix("/") else {
    print("usage: reach-acceptance-driver --root ABSOLUTE_EMPTY_DIR --controller ABSOLUTE_BINARY")
    exit(64)
}
do {
    try campaign(root: URL(fileURLWithPath: arguments[1]), executable: URL(fileURLWithPath: arguments[3]))
} catch let error as ControllerError {
    print(error.description); exit(70)
} catch {
    print("campaign-io-failure"); exit(70)
}
