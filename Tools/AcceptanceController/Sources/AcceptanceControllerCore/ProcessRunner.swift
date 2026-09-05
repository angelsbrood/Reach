import Foundation
import Darwin

public struct ProcessResult: Sendable {
    public let rawT0: UInt64
    public let rawT1: UInt64
    public let termination: String
    public let exitCode: Int32?
    public let signal: Int32?
    public let spawnError: Int32?
    public let processID: Int32?
    public let timeoutDetectedAt: UInt64?
    public let termSentAt: UInt64?
    public let killSentAt: UInt64?
    public let groupAbsentAt: UInt64?
    public let stdout: Data
    public let stderr: Data
    public let stdoutCount: Int
    public let stderrCount: Int
    public let overflowed: Bool
    public let groupAssigned: Bool
    public let directChildReaped: Bool
    public let captureComplete: Bool

    /// Covers only the direct child, its assigned group and capture pipes.
    public var cleanupComplete: Bool {
        spawnError != nil || (directChildReaped && groupAbsentAt != nil && captureComplete)
    }
}

public enum ProcessRunner {
    public static func run(_ action: ActionSpec) throws -> ProcessResult {
        guard RawClock.now() < action.workDeadlineNanoseconds,
              action.workDeadlineNanoseconds < action.settlementDeadlineNanoseconds else {
            throw ControllerError.process("deadline-expired-or-invalid")
        }
        guard action.executable.hasPrefix("/"), action.workingDirectory.hasPrefix("/"),
              !([action.executable, action.workingDirectory] + action.arguments +
                action.environment.flatMap { [$0.key, $0.value] }).contains(where: { $0.contains("\0") }) else {
            throw ControllerError.process("invalid-argument")
        }
        var out = [Int32](repeating: -1, count: 2), err = [Int32](repeating: -1, count: 2)
        guard pipe(&out) == 0 else { throw ControllerError.process("pipe") }
        defer { for fd in out where fd >= 0 { close(fd) } }
        guard pipe(&err) == 0 else { throw ControllerError.process("pipe") }
        defer { for fd in err where fd >= 0 { close(fd) } }
        var files: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        func check(_ code: Int32) throws {
            guard code == 0 else { throw ControllerError.process("spawn-setup-\(code)") }
        }
        try check(posix_spawn_file_actions_init(&files))
        defer { posix_spawn_file_actions_destroy(&files) }
        try check(posix_spawnattr_init(&attributes))
        defer { posix_spawnattr_destroy(&attributes) }
        try check(posix_spawn_file_actions_addopen(&files, STDIN_FILENO, "/dev/null", O_RDONLY, 0))
        try check(posix_spawn_file_actions_adddup2(&files, out[1], STDOUT_FILENO))
        try check(posix_spawn_file_actions_adddup2(&files, err[1], STDERR_FILENO))
        for fd in out + err { try check(posix_spawn_file_actions_addclose(&files, fd)) }
        if #available(macOS 26, *) {
            try check(posix_spawn_file_actions_addchdir(&files, action.workingDirectory))
        } else {
            try check(posix_spawn_file_actions_addchdir_np(&files, action.workingDirectory))
        }
        // Establish the ordinary child group during spawn, not after exec.
        try check(posix_spawnattr_setpgroup(&attributes, 0))
        var mask = sigset_t(); sigemptyset(&mask)
        var defaults = sigset_t(); sigemptyset(&defaults)
        for value in [SIGTERM, SIGINT, SIGPIPE] { sigaddset(&defaults, value) }
        try check(posix_spawnattr_setsigmask(&attributes, &mask))
        try check(posix_spawnattr_setsigdefault(&attributes, &defaults))
        try check(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_CLOEXEC_DEFAULT)))
        let arguments = ([action.executable] + action.arguments).map { strdup($0) } + [nil]
        let environment = action.environment.keys.sorted().map { strdup("\($0)=\(action.environment[$0]!)") } + [nil]
        defer { for pointer in arguments + environment { free(pointer) } }
        var pid: pid_t = 0
        let t0 = RawClock.now()
        let spawnCode = arguments.withUnsafeBufferPointer { argv in
            environment.withUnsafeBufferPointer { env in
                posix_spawn(&pid, action.executable, &files, &attributes, argv.baseAddress!, env.baseAddress!)
            }
        }
        close(out[1]); out[1] = -1
        close(err[1]); err[1] = -1
        if spawnCode != 0 {
            return ProcessResult(rawT0: t0, rawT1: RawClock.now(), termination: "spawnFailure",
                                 exitCode: nil, signal: nil, spawnError: spawnCode, processID: nil,
                                 timeoutDetectedAt: nil, termSentAt: nil, killSentAt: nil, groupAbsentAt: nil,
                                 stdout: Data(), stderr: Data(), stdoutCount: 0, stderrCount: 0,
                                 overflowed: false, groupAssigned: false, directChildReaped: false, captureComplete: true)
        }
        for fd in [out[0], err[0]] { _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) }
        var output = Data(), errors = Data()
        var outputCount = 0, errorCount = 0
        var outputEOF = false, errorEOF = false, captureFailed = false
        var reaped = false, waitStatus: Int32 = 0
        var timeoutAt: UInt64?, termAt: UInt64?, killAt: UInt64?, absentAt: UInt64?
        var termination = "exit"
        func drain(_ fd: Int32, data: inout Data, count: inout Int, eof: inout Bool) {
            guard !eof else { return }
            var buffer = [UInt8](repeating: 0, count: 32 * 1024)
            // A busy writer must not starve deadline and termination checks.
            for _ in 0..<8 {
                let n = read(fd, &buffer, buffer.count)
                if n == 0 { eof = true; return }
                if n < 0 {
                    if errno != EAGAIN && errno != EINTR { captureFailed = true; eof = true }
                    return
                }
                count += n
                data.append(contentsOf: buffer.prefix(min(n, max(0, 1_048_576 - data.count))))
            }
        }
        while true {
            drain(out[0], data: &output, count: &outputCount, eof: &outputEOF)
            drain(err[0], data: &errors, count: &errorCount, eof: &errorEOF)
            if !reaped {
                let waited = waitpid(pid, &waitStatus, WNOHANG)
                if waited == pid { reaped = true }
                else if waited < 0 && errno != EINTR { captureFailed = true }
            }
            let now = RawClock.now()
            let groupAbsent = kill(-pid, 0) == -1 && errno == ESRCH
            if groupAbsent, absentAt == nil { absentAt = now }
            let overflow = outputCount > 1_048_576 || errorCount > 1_048_576
            if overflow { termination = "outputOverflow" }
            if reaped && groupAbsent && outputEOF && errorEOF { break }
            if termAt == nil && (overflow || captureFailed || now >= action.workDeadlineNanoseconds || reaped) {
                if !overflow && now >= action.workDeadlineNanoseconds && !reaped {
                    timeoutAt = now; termination = "timeout"
                }
                termAt = now
                _ = kill(-pid, SIGTERM)
            }
            if let termAt, killAt == nil, now >= termAt + 2_000_000_000, !groupAbsent {
                killAt = now; _ = kill(-pid, SIGKILL)
            }
            if now >= action.settlementDeadlineNanoseconds {
                if !groupAbsent && killAt == nil { killAt = now; _ = kill(-pid, SIGKILL) }
                break // Never block indefinitely on a child or inherited pipe.
            }
            usleep(5_000)
        }
        let signal: Int32? = reaped && waitStatus & 0x7f != 0 ? waitStatus & 0x7f : nil
        let exitCode: Int32? = reaped && signal == nil ? (waitStatus >> 8) & 0xff : nil
        if termination == "exit", signal != nil { termination = "signal" }
        return ProcessResult(rawT0: t0, rawT1: RawClock.now(), termination: termination,
                             exitCode: exitCode, signal: signal, spawnError: nil, processID: pid,
                             timeoutDetectedAt: timeoutAt, termSentAt: termAt, killSentAt: killAt,
                             groupAbsentAt: absentAt, stdout: output, stderr: errors,
                             stdoutCount: outputCount, stderrCount: errorCount,
                             overflowed: outputCount > 1_048_576 || errorCount > 1_048_576,
                             groupAssigned: true, directChildReaped: reaped,
                             captureComplete: outputEOF && errorEOF && !captureFailed)
    }
}
