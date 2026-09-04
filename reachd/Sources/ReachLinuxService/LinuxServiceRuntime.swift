import CReachLinuxMsQuic
import Dispatch
import Foundation
import Glibc
import ReachHost
import ReachLinuxTransport

public enum LinuxServiceRuntimeError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    public enum StartupBoundary: String, Sendable, Equatable {
        case exoPreflight
        case credentialOrListener
    }

    case startupRefused(StartupBoundary, String)
    case listenerEnded
    case runtime(String)

    public var description: String {
        switch self {
        case .startupRefused(let boundary, let detail):
            "the Linux reachd \(boundary.rawValue) startup boundary refused: \(detail)"
        case .listenerEnded:
            "the Linux QUIC listener ended without a stop signal"
        case .runtime(let detail):
            "the Linux reachd service failed: \(detail)"
        }
    }

    public var errorDescription: String? { description }
}

public enum LinuxServiceExitStatus {
    public static let noRestart: Int32 = 64
    public static let unexpectedRuntimeFailure: Int32 = 1

    public static func code(for error: any Error) -> Int32 {
        if error is LinuxServiceConfigurationError {
            return noRestart
        }
        if let runtimeError = error as? LinuxServiceRuntimeError,
           case .startupRefused = runtimeError {
            return noRestart
        }
        if let transportError = error as? LinuxTransportError,
           case .startup = transportError {
            return noRestart
        }
        return unexpectedRuntimeFailure
    }
}

public struct LinuxServiceStatus: Codable, Sendable, Equatable {
    public var schemaVersion: Int
    public var pid: Int32
    public var ready: Bool
    public var modelID: String
    public var boundAddress: String
    public var boundPort: UInt16
    public var activeConnections: UInt32
    public var activeStreams: UInt32
    public var acceptedConnections: UInt32
    public var acceptedStreams: UInt32
    public var refusedConnections: UInt32
    public var refusedStreams: UInt32
    public var lastError: String?

    public init(
        configuration: LinuxServiceConfiguration,
        ready: Bool,
        metrics: LinuxTransportMetrics,
        lastError: String? = nil
    ) {
        schemaVersion = 1
        pid = getpid()
        self.ready = ready
        modelID = configuration.modelID
        boundAddress = configuration.listen.address
        boundPort = configuration.listen.port
        activeConnections = metrics.activeConnections
        activeStreams = metrics.activeStreams
        acceptedConnections = metrics.acceptedConnections
        acceptedStreams = metrics.acceptedStreams
        refusedConnections = metrics.refusedConnections
        refusedStreams = metrics.refusedStreams
        self.lastError = lastError.map(Self.boundedError)
    }

    private static func boundedError(_ source: String) -> String {
        var result = ""
        result.reserveCapacity(min(source.utf8.count, 512))
        for character in source {
            let candidate = result + String(character)
            if candidate.utf8.count > 512 { break }
            result = candidate
        }
        return result
    }
}

struct LinuxStopRequest: Sendable, Equatable {
    enum Reason: Sendable, Equatable {
        case signal(Int32)
        case failure(String)
    }

    var reason: Reason
    var deadline: LinuxShutdownDeadline
}

actor LinuxStopLatch {

    private var request: LinuxStopRequest?
    private var waiter: CheckedContinuation<LinuxStopRequest, Never>?

    func request(_ request: LinuxStopRequest) {
        guard self.request == nil else { return }
        self.request = request
        waiter?.resume(returning: request)
        waiter = nil
    }

    func wait() async -> LinuxStopRequest {
        if let request { return request }
        return await withCheckedContinuation { continuation in
            waiter = continuation
        }
    }
}

private actor LinuxStreamRegistry {
    private struct Entry: Sendable {
        var stream: LinuxSessionStream
        var task: Task<Void, Never>
    }

    private var entries: [UUID: Entry] = [:]

    func start(_ stream: LinuxSessionStream, host: SessionHost) {
        let id = UUID()
        let task = Task { [weak self] in
            await host.serve(stream)
            await self?.finished(id)
        }
        entries[id] = Entry(stream: stream, task: task)
    }

    private func finished(_ id: UUID) {
        entries.removeValue(forKey: id)
    }

    func cancelAndWait() async {
        let snapshot = Array(entries.values)
        snapshot.forEach { entry in
            entry.stream.cancel()
            entry.task.cancel()
        }
        for entry in snapshot {
            await entry.task.value
        }
        entries.removeAll()
    }

    var count: Int { entries.count }
}

private final class LinuxSignalMonitor: @unchecked Sendable {
    struct Event: Sendable {
        var signal: Int32
        var deadline: LinuxShutdownDeadline
    }

    let signals: AsyncStream<Event>
    private let term: DispatchSourceSignal
    private let interrupt: DispatchSourceSignal

    init() {
        _ = Glibc.signal(SIGTERM, SIG_IGN)
        _ = Glibc.signal(SIGINT, SIG_IGN)
        let pair = AsyncStream<Event>.makeStream(bufferingPolicy: .bufferingNewest(1))
        signals = pair.stream
        let queue = DispatchQueue(label: "reach.linux.signals")
        term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
        term.setEventHandler {
            _ = pair.continuation.yield(Event(
                signal: SIGTERM,
                deadline: .startingNow()
            ))
        }
        interrupt.setEventHandler {
            _ = pair.continuation.yield(Event(
                signal: SIGINT,
                deadline: .startingNow()
            ))
        }
        term.resume()
        interrupt.resume()
    }

    deinit {
        term.cancel()
        interrupt.cancel()
    }
}

enum LinuxStatusWriter {
    static let productionPath = "/run/reach/status.json"

    static func write(_ status: LinuxServiceStatus, path: String = productionPath) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(status)
        let destination = URL(fileURLWithPath: path)
        let temporary = destination
            .deletingLastPathComponent()
            .appendingPathComponent(".status-\(getpid())-\(UUID().uuidString)")
        do {
            try data.write(to: temporary, options: [.withoutOverwriting])
            guard chmod(temporary.path, 0o600) == 0 else {
                throw LinuxServiceConfigurationError.system("chmod(status)", errno)
            }
            guard rename(temporary.path, destination.path) == 0 else {
                throw LinuxServiceConfigurationError.system("rename(status)", errno)
            }
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
    }
}

enum LinuxShutdownBranch: String, CaseIterable, Sendable {
    case listener
    case registry
    case host
    case accept
    case signal
    case status
}

struct LinuxShutdownOperations: Sendable {
    typealias Operation = @Sendable (LinuxShutdownDeadline) async -> Result<Void, any Error>

    var listener: Operation
    var registry: Operation
    var host: Operation
    var accept: Operation
    var signal: Operation
    var status: Operation

    var ordered: [(LinuxShutdownBranch, Operation)] {
        [
            (.listener, listener),
            (.registry, registry),
            (.host, host),
            (.accept, accept),
            (.signal, signal),
            (.status, status),
        ]
    }
}

struct LinuxShutdownClock: Sendable {
    var now: @Sendable () -> UInt64
    var sleepUntil: @Sendable (UInt64) async -> Void

    static let production = LinuxShutdownClock(
        now: { reach_msquic_monotonic_now_nanoseconds() },
        sleepUntil: { deadline in
            let now = reach_msquic_monotonic_now_nanoseconds()
            guard now < deadline else { return }
            try? await Task.sleep(nanoseconds: deadline - now)
        }
    )
}

struct LinuxSweepObservation: Sendable, Equatable {
    var scheduledNanoseconds: UInt64
    var observedNanoseconds: UInt64
    var delayNanoseconds: UInt64
    var skippedDeadlines: UInt64
}

struct LinuxSweepSchedule: Sendable {
    static let intervalNanoseconds: UInt64 = 1_000_000_000

    private(set) var nextDeadline: UInt64

    init(startedAt: UInt64) {
        let (deadline, overflow) = startedAt.addingReportingOverflow(Self.intervalNanoseconds)
        nextDeadline = overflow ? UInt64.max : deadline
    }

    mutating func observed(at now: UInt64) -> LinuxSweepObservation {
        let scheduled = nextDeadline
        let delay = now >= scheduled ? now - scheduled : 0
        var skipped: UInt64 = 0
        repeat {
            let (advanced, overflow) = nextDeadline.addingReportingOverflow(
                Self.intervalNanoseconds
            )
            nextDeadline = overflow ? UInt64.max : advanced
            if nextDeadline <= now, nextDeadline != UInt64.max { skipped += 1 }
        } while nextDeadline <= now && nextDeadline != UInt64.max
        return .init(
            scheduledNanoseconds: scheduled,
            observedNanoseconds: now,
            delayNanoseconds: delay,
            skippedDeadlines: skipped
        )
    }
}

struct LinuxSweepClock: Sendable {
    var now: @Sendable () -> UInt64
    var sleepUntil: @Sendable (UInt64) async throws -> Void

    static let production = LinuxSweepClock(
        now: { reach_msquic_monotonic_now_nanoseconds() },
        sleepUntil: { deadline in
            let now = reach_msquic_monotonic_now_nanoseconds()
            guard now < deadline else { return }
            try await Task.sleep(nanoseconds: deadline - now)
        }
    )
}

final class LinuxSessionSweeper: @unchecked Sendable {
    typealias Sweep = @Sendable () async -> Int
    typealias Observer = @Sendable (LinuxSweepObservation, Int) -> Void

    private let task: Task<Void, Never>

    init(
        clock: LinuxSweepClock = .production,
        sweep: @escaping Sweep,
        observer: @escaping Observer = { observation, reaped in
            print(
                "[reachd] registry sweep delay_ns=\(observation.delayNanoseconds) " +
                "skipped=\(observation.skippedDeadlines) reaped=\(reaped)"
            )
        }
    ) {
        let startedAt = clock.now()
        task = Task {
            var schedule = LinuxSweepSchedule(startedAt: startedAt)
            while !Task.isCancelled {
                do {
                    try await clock.sleepUntil(schedule.nextDeadline)
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }
                let observation = schedule.observed(at: clock.now())
                let reaped = await sweep()
                observer(observation, reaped)
            }
        }
    }

    func cancel() {
        task.cancel()
    }

    func wait() async {
        await task.value
    }

    func cancelAndWait() async {
        cancel()
        await wait()
    }
}

private actor LinuxShutdownRace {
    enum Outcome: Sendable {
        case settled((any Error)?)
        case timedOut
    }

    private var outcome: Outcome?
    private var waiter: CheckedContinuation<Outcome, Never>?

    func resolve(_ outcome: Outcome) {
        guard self.outcome == nil else { return }
        self.outcome = outcome
        waiter?.resume(returning: outcome)
        waiter = nil
    }

    func wait() async -> Outcome {
        if let outcome { return outcome }
        return await withCheckedContinuation { continuation in
            waiter = continuation
        }
    }
}

enum LinuxShutdownCoordinator {
    static func settle(
        request: LinuxStopRequest,
        operations: LinuxShutdownOperations,
        clock: LinuxShutdownClock = .production
    ) async throws {
        let deadline = request.deadline
        let tasks = operations.ordered.map { branch, operation in
            (branch, Task { await operation(deadline) })
        }
        let race = LinuxShutdownRace()
        let settlementObserver = Task {
            var firstError: (any Error)?
            for (_, task) in tasks {
                if case .failure(let error) = await task.value, firstError == nil {
                    firstError = error
                }
            }
            if clock.now() >= deadline.monotonicNanoseconds {
                await race.resolve(.timedOut)
            } else {
                await race.resolve(.settled(firstError))
            }
        }
        let deadlineObserver = Task {
            await clock.sleepUntil(deadline.monotonicNanoseconds)
            guard !Task.isCancelled else { return }
            await race.resolve(.timedOut)
        }

        switch await race.wait() {
        case .settled(let error):
            deadlineObserver.cancel()
            if let error { throw error }
        case .timedOut:
            settlementObserver.cancel()
            deadlineObserver.cancel()
            for (_, task) in tasks { task.cancel() }
            throw LinuxTransportError.shutdownTimedOut
        }
    }
}

public enum LinuxServiceRuntime {
    public static func runProduction() async throws {
        try await run(configuration: LinuxServiceConfiguration.loadProduction())
    }

    public static func run(configuration: LinuxServiceConfiguration) async throws {
        let filling: any SlotFilling
        do {
            filling = try PortableEXOHostConfiguration(
                modelID: configuration.modelID,
                exo: EXOConfiguration(endpoint: configuration.exoEndpoint)
            ).makeFilling()
            try await filling.prewarm()
        } catch {
            throw LinuxServiceRuntimeError.startupRefused(
                .exoPreflight,
                String(describing: error)
            )
        }

        let host = SessionHost(
            filling: filling,
            helloAck: { version in
                configuration.helloAck(version: version, capabilities: filling.capabilities)
            },
            sessionOpened: { sessionID, _ in
                "session \(sessionID) opened on authenticated Linux QUIC"
            }
        )
        let listener: ReachLinuxListener
        do {
            listener = try ReachLinuxListener(configuration: configuration.listenerConfiguration)
        } catch {
            throw LinuxServiceRuntimeError.startupRefused(
                .credentialOrListener,
                String(describing: error)
            )
        }
        let latch = LinuxStopLatch()
        let registry = LinuxStreamRegistry()
        let signals = LinuxSignalMonitor()

        let initial = LinuxServiceStatus(
            configuration: configuration,
            ready: true,
            metrics: listener.metrics()
        )
        try LinuxStatusWriter.write(initial)
        try LinuxSystemdNotifier.notify("READY=1\nSTATUS=Reach Linux listener ready")
        let sweeper = LinuxSessionSweeper(sweep: { await host.sweep() })

        let acceptTask = Task {
            do {
                while let stream = try await listener.nextStream() {
                    await registry.start(stream, host: host)
                }
                if !Task.isCancelled {
                    await latch.request(LinuxStopRequest(
                        reason: .failure(LinuxServiceRuntimeError.listenerEnded.description),
                        deadline: .startingNow()
                    ))
                }
            } catch is CancellationError {
                return
            } catch {
                await latch.request(LinuxStopRequest(
                    reason: .failure(String(describing: error)),
                    deadline: .startingNow()
                ))
            }
        }
        let signalTask = Task {
            for await event in signals.signals {
                await latch.request(LinuxStopRequest(
                    reason: .signal(event.signal),
                    deadline: event.deadline
                ))
                return
            }
        }
        let statusTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { return }
                let status = LinuxServiceStatus(
                    configuration: configuration,
                    ready: true,
                    metrics: listener.metrics()
                )
                try? LinuxStatusWriter.write(status)
            }
        }

        let request = await latch.wait()
        let reason = request.reason
        let deadline = request.deadline
        try? LinuxSystemdNotifier.notify("STOPPING=1\nSTATUS=Reach Linux listener stopping")
        acceptTask.cancel()
        signalTask.cancel()
        statusTask.cancel()
        sweeper.cancel()

        var shutdownError: Error?
        do {
            try await LinuxShutdownCoordinator.settle(
                request: request,
                operations: LinuxShutdownOperations(
                    listener: { deadline in
                        do {
                            try await listener.stop(until: deadline)
                            return .success(())
                        } catch {
                            return .failure(error)
                        }
                    },
                    registry: { _ in
                        await registry.cancelAndWait()
                        return .success(())
                    },
                    host: { _ in
                        await sweeper.wait()
                        await host.shutdown()
                        return .success(())
                    },
                    accept: { _ in
                        await acceptTask.value
                        return .success(())
                    },
                    signal: { _ in
                        await signalTask.value
                        return .success(())
                    },
                    status: { _ in
                        await statusTask.value
                        return .success(())
                    }
                )
            )
        } catch {
            shutdownError = error
        }

        let finalError: String?
        switch reason {
        case .signal:
            finalError = shutdownError.map(String.init(describing:))
        case .failure(let detail):
            finalError = detail
        }
        if !deadline.hasExpired() {
            let finalStatus = LinuxServiceStatus(
                configuration: configuration,
                ready: false,
                metrics: listener.metrics(),
                lastError: finalError
            )
            try? LinuxStatusWriter.write(finalStatus)
        }

        if let shutdownError { throw shutdownError }
        if case .failure(let detail) = reason {
            throw LinuxServiceRuntimeError.runtime(detail)
        }
    }
}
