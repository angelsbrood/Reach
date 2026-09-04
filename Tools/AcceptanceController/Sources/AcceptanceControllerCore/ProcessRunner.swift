import Foundation
import Darwin

public struct ProcessResult: Sendable {
    public let rawT0: UInt64
    public let rawT1: UInt64
    public let termination: String
    public let exitCode: Int32?
    public let signal: Int32?
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
}

private final class CaptureBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stdout = Data()
    private var stderr = Data()
    private var stdoutCount = 0
    private var stderrCount = 0
    private var overflow = false

    func append(_ data: Data, stdout isStdout: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if isStdout { stdoutCount += data.count } else { stderrCount += data.count }
        let streamCount = isStdout ? stdoutCount : stderrCount
        if streamCount > 1_048_576 || stdoutCount + stderrCount > 4_194_304 { overflow = true }
        let targetRemaining = max(0, 1_048_576 - (isStdout ? stdout.count : stderr.count))
        if targetRemaining > 0 {
            let prefix = data.prefix(targetRemaining)
            if isStdout { stdout.append(prefix) } else { stderr.append(prefix) }
        }
        return overflow
    }

    func result() -> (Data, Data, Int, Int, Bool) {
        lock.lock(); defer { lock.unlock() }
        return (stdout, stderr, stdoutCount, stderrCount, overflow)
    }
}

public enum ProcessRunner {
    public static func run(_ action: ActionSpec) throws -> ProcessResult {
        let executable = URL(fileURLWithPath: action.executable)
        guard executable.path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw ControllerError.process("executable")
        }
        let outPipe = Pipe()
        let errPipe = Pipe()
        let process = Process()
        process.executableURL = executable
        process.arguments = action.arguments
        process.environment = action.environment
        process.currentDirectoryURL = URL(fileURLWithPath: action.workingDirectory)
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = outPipe
        process.standardError = errPipe

        let capture = CaptureBox()
        let readers = DispatchGroup()
        func drain(_ handle: FileHandle, stdout: Bool) {
            readers.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { readers.leave() }
                while true {
                    let data = handle.readData(ofLength: 32 * 1024)
                    if data.isEmpty { return }
                    _ = capture.append(data, stdout: stdout)
                }
            }
        }
        drain(outPipe.fileHandleForReading, stdout: true)
        drain(errPipe.fileHandleForReading, stdout: false)

        let t0 = RawClock.now()
        try process.run()
        let pid = process.processIdentifier
        let groupAssigned = setpgid(pid, pid) == 0 || getpgid(pid) == pid
        var timeoutAt: UInt64?
        var termAt: UInt64?
        var killAt: UInt64?
        var termination = "exit"

        while process.isRunning {
            let now = RawClock.now()
            let overflow = capture.result().4
            if overflow || now >= action.workDeadlineNanoseconds {
                timeoutAt = overflow ? nil : now
                termination = overflow ? "outputOverflow" : "timeout"
                termAt = now
                if groupAssigned { _ = kill(-pid, SIGTERM) } else { process.terminate() }
                let termLimit = min(action.settlementDeadlineNanoseconds, now + 2_000_000_000)
                while process.isRunning, RawClock.now() < termLimit { usleep(10_000) }
                if process.isRunning {
                    killAt = RawClock.now()
                    if groupAssigned { _ = kill(-pid, SIGKILL) } else { _ = kill(pid, SIGKILL) }
                }
                break
            }
            usleep(5_000)
        }
        process.waitUntilExit()
        outPipe.fileHandleForWriting.closeFile()
        errPipe.fileHandleForWriting.closeFile()
        _ = readers.wait(timeout: .now() + 2)

        var absentAt: UInt64?
        while RawClock.now() <= action.settlementDeadlineNanoseconds {
            if !groupAssigned || (kill(-pid, 0) == -1 && errno == ESRCH) {
                absentAt = RawClock.now()
                break
            }
            usleep(5_000)
        }
        let t1 = RawClock.now()
        let captured = capture.result()
        let exitCode: Int32? = process.terminationReason == .exit ? process.terminationStatus : nil
        let signal: Int32? = process.terminationReason == .uncaughtSignal ? process.terminationStatus : nil
        if termination == "exit", signal != nil { termination = "signal" }
        return ProcessResult(
            rawT0: t0,
            rawT1: t1,
            termination: termination,
            exitCode: exitCode,
            signal: signal,
            timeoutDetectedAt: timeoutAt,
            termSentAt: termAt,
            killSentAt: killAt,
            groupAbsentAt: absentAt,
            stdout: captured.0,
            stderr: captured.1,
            stdoutCount: captured.2,
            stderrCount: captured.3,
            overflowed: captured.4,
            groupAssigned: groupAssigned
        )
    }
}
