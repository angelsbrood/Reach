import AcceptanceControllerCore
import Foundation
import Darwin

private struct StartRecord: Codable {
    let version: Int
    let rawT0: UInt64
    let workDeadline: UInt64
    let settlementDeadline: UInt64
    let executableDigest: String?
    let argvDigest: String
    let argumentCount: Int
}
private struct TerminalRecord: Codable {
    let version: Int
    let rawT0: UInt64
    let rawT1: UInt64
    let termination: String
    let exitCode: Int32?
    let signal: Int32?
    let spawnError: Int32?
    let processID: Int32?
    let timeoutDetectedAt: UInt64?
    let termSentAt: UInt64?
    let killSentAt: UInt64?
    let groupAbsentAt: UInt64?
    let directChildReaped: Bool
    let cleanupComplete: Bool
    let stdoutBytes: Int
    let stderrBytes: Int
    let stdoutDigest: String
    let stderrDigest: String
    let observationScope: String
}

let args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 6, args[0] == "--record", args[2] == "--timeout-seconds", args[4] == "--",
      args[1].hasPrefix("/"), args[5].hasPrefix("/"),
      let seconds = UInt64(args[3]), seconds > 0, seconds <= 3600 else {
    print("usage: reach-acceptance-launcher --record ABSOLUTE_DIR --timeout-seconds 1...3600 -- EXECUTABLE [ARGS]")
    exit(64)
}
do {
    let root = URL(fileURLWithPath: args[1])
    try DurableFile.createDirectory(root)
    let argv = Array(args.dropFirst(5))
    let t0 = RawClock.now(), work = t0 + seconds * 1_000_000_000, settlement = work + 6_000_000_000
    let start = StartRecord(version: 1, rawT0: t0, workDeadline: work, settlementDeadline: settlement,
                            executableDigest: try? SHA256.file(URL(fileURLWithPath: argv[0])),
                            argvDigest: SHA256.hex(try CanonicalJSON.encode(argv)), argumentCount: argv.count)
    // Persist before trying to launch: interpreter failure cannot erase this edge.
    try DurableFile.write(CanonicalJSON.encode(start), to: root.appendingPathComponent("start.json"))
    try DurableFile.fsyncDirectory(root)
    let result: ProcessResult
    do {
        result = try ProcessRunner.run(ActionSpec(
            id: "outer-command", ordinal: 0, executable: argv[0], arguments: Array(argv.dropFirst()),
            environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": root.path, "TMPDIR": root.path,
                          "CLANG_MODULE_CACHE_PATH": root.path, "SWIFT_MODULECACHE_PATH": root.path],
            workingDirectory: FileManager.default.currentDirectoryPath,
            workDeadlineNanoseconds: work, settlementDeadlineNanoseconds: settlement))
    } catch {
        let terminal = TerminalRecord(version: 1, rawT0: t0, rawT1: RawClock.now(), termination: "launchSetupFailure",
                                      exitCode: nil, signal: nil, spawnError: nil, processID: nil, timeoutDetectedAt: nil,
                                      termSentAt: nil, killSentAt: nil, groupAbsentAt: nil, directChildReaped: false,
                                      cleanupComplete: true, stdoutBytes: 0, stderrBytes: 0,
                                      stdoutDigest: SHA256.hex(Data()), stderrDigest: SHA256.hex(Data()),
                                      observationScope: "setup failed before spawn; no child created")
        try DurableFile.write(CanonicalJSON.encode(terminal), to: root.appendingPathComponent("terminal.json"))
        try DurableFile.fsyncDirectory(root)
        exit(70)
    }
    let terminal = TerminalRecord(version: 1, rawT0: t0, rawT1: RawClock.now(), termination: result.termination,
                                  exitCode: result.exitCode, signal: result.signal, spawnError: result.spawnError,
                                  processID: result.processID, timeoutDetectedAt: result.timeoutDetectedAt,
                                  termSentAt: result.termSentAt, killSentAt: result.killSentAt,
                                  groupAbsentAt: result.groupAbsentAt, directChildReaped: result.directChildReaped,
                                  cleanupComplete: result.cleanupComplete, stdoutBytes: result.stdoutCount,
                                  stderrBytes: result.stderrCount, stdoutDigest: SHA256.hex(result.stdout),
                                  stderrDigest: SHA256.hex(result.stderr),
                                  observationScope: "direct child, assigned process group and capture pipes only")
    let data = try CanonicalJSON.encode(terminal)
    try DurableFile.write(data, to: root.appendingPathComponent("terminal.json"))
    try DurableFile.fsyncDirectory(root)
    guard ReceiptWriter.write(data, descriptor: STDOUT_FILENO) else { exit(70) }
    if !result.cleanupComplete { exit(70) }
    if result.spawnError != nil { exit(127) }
    if result.termination == "timeout" { exit(124) }
    if result.overflowed { exit(125) }
    exit(result.exitCode ?? (128 + (result.signal ?? 0)))
} catch {
    print("launcher-record-failure"); exit(70)
}
