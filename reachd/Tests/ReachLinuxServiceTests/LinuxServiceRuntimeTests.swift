import Foundation
import Glibc
import ReachLinuxTransport
import Testing
@testable import ReachLinuxService

private let reachdRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()

private func productFile(_ relative: String) throws -> String {
    try String(contentsOf: reachdRoot.appendingPathComponent(relative), encoding: .utf8)
}

private func fixedConfiguration() throws -> LinuxServiceConfiguration {
    let source = #"{"schemaVersion":1,"clusterDisplayName":"Synthetic Cluster","listen":{"address":"0.0.0.0","port":4433},"advertisedRoads":[{"address":"192.0.2.10","port":4433}],"tls":{"clusterCACertificatePath":"/etc/reach/tls/ca.pem","serverCertificateChainPath":"/etc/reach/tls/server-chain.pem","serverPrivateKeyPath":"/etc/reach/tls/server-key.pem"},"modelID":"synthetic-model","exoEndpoint":"http://127.0.0.1:52415"}"#
    return try LinuxServiceConfiguration.decode(Data(source.utf8))
}

private func sourceIdentifiers(_ source: String) -> Set<String> {
    var result: Set<String> = []
    var token = ""
    func flush() {
        guard let first = token.unicodeScalars.first,
              CharacterSet.letters.union(CharacterSet(charactersIn: "_")).contains(first) else {
            token = ""
            return
        }
        result.insert(token)
        token = ""
    }
    for scalar in source.unicodeScalars {
        if CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_")).contains(scalar) {
            token.unicodeScalars.append(scalar)
        } else {
            flush()
        }
    }
    flush()
    return result
}

private func previewOnlyIdentifiers(_ header: String) -> Set<String> {
    struct Conditional {
        var parentWasPreview: Bool
        var conditionIsPreview: Bool
    }
    var conditionals: [Conditional] = []
    var inPreview = false
    var preview: Set<String> = []
    var stable: Set<String> = []
    for line in header.split(separator: "\n", omittingEmptySubsequences: false) {
        let text = String(line)
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("#if") {
            let conditional = Conditional(
                parentWasPreview: inPreview,
                conditionIsPreview: trimmed.contains("QUIC_API_ENABLE_PREVIEW_FEATURES")
            )
            conditionals.append(conditional)
            inPreview = conditional.parentWasPreview || conditional.conditionIsPreview
            continue
        }
        if trimmed.hasPrefix("#else"), let conditional = conditionals.last {
            inPreview = conditional.parentWasPreview
            continue
        }
        if trimmed.hasPrefix("#endif"), let conditional = conditionals.popLast() {
            inPreview = conditional.parentWasPreview
            continue
        }
        if inPreview {
            preview.formUnion(sourceIdentifiers(text))
        } else {
            stable.formUnion(sourceIdentifiers(text))
        }
    }
    return Set(preview.subtracting(stable).filter { identifier in
        identifier.hasPrefix("QUIC_") || identifier.first?.isUppercase == true
    })
}

private enum ShutdownFixtureError: Error, Equatable {
    case failed(LinuxShutdownBranch)
}

private enum ShutdownFixtureBehavior {
    case succeed
    case fail
    case stall
}

private final class ShutdownFixtureClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64

    init(_ value: UInt64) {
        self.value = value
    }

    func now() -> UInt64 { lock.withLock { value } }
    func set(_ value: UInt64) { lock.withLock { self.value = value } }
}

private actor ShutdownFixtureProbe {
    struct Snapshot: Sendable {
        var started: Set<LinuxShutdownBranch>
        var completed: Set<LinuxShutdownBranch>
        var cancelled: Set<LinuxShutdownBranch>
        var deadlines: [LinuxShutdownBranch: LinuxShutdownDeadline]
        var active: Int
        var peakActive: Int
    }

    private var started: Set<LinuxShutdownBranch> = []
    private var completed: Set<LinuxShutdownBranch> = []
    private var cancelled: Set<LinuxShutdownBranch> = []
    private var deadlines: [LinuxShutdownBranch: LinuxShutdownDeadline] = [:]
    private var active = 0
    private var peakActive = 0
    private var allStartedWaiters: [CheckedContinuation<Void, Never>] = []
    private var zeroWaiters: [CheckedContinuation<Void, Never>] = []

    func begin(_ branch: LinuxShutdownBranch, deadline: LinuxShutdownDeadline) {
        precondition(started.insert(branch).inserted)
        deadlines[branch] = deadline
        active += 1
        peakActive = max(peakActive, active)
        if started.count == LinuxShutdownBranch.allCases.count {
            let waiters = allStartedWaiters
            allStartedWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
    }

    func waitUntilAllStarted() async {
        guard started.count != LinuxShutdownBranch.allCases.count else { return }
        await withCheckedContinuation { allStartedWaiters.append($0) }
    }

    func finish(_ branch: LinuxShutdownBranch, wasCancelled: Bool) {
        precondition(completed.insert(branch).inserted)
        if wasCancelled { cancelled.insert(branch) }
        active -= 1
        if active == 0 {
            let waiters = zeroWaiters
            zeroWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
    }

    func waitUntilZero() async {
        guard active != 0 else { return }
        await withCheckedContinuation { zeroWaiters.append($0) }
    }

    var snapshot: Snapshot {
        Snapshot(
            started: started,
            completed: completed,
            cancelled: cancelled,
            deadlines: deadlines,
            active: active,
            peakActive: peakActive
        )
    }
}

private func shutdownFixtureOperation(
    _ branch: LinuxShutdownBranch,
    behavior: ShutdownFixtureBehavior,
    probe: ShutdownFixtureProbe
) -> LinuxShutdownOperations.Operation {
    { deadline in
        await probe.begin(branch, deadline: deadline)
        await probe.waitUntilAllStarted()
        switch behavior {
        case .succeed:
            await probe.finish(branch, wasCancelled: false)
            return .success(())
        case .fail:
            await probe.finish(branch, wasCancelled: false)
            return .failure(ShutdownFixtureError.failed(branch))
        case .stall:
            do {
                try await Task.sleep(for: .seconds(60))
                await probe.finish(branch, wasCancelled: false)
            } catch {
                await probe.finish(branch, wasCancelled: Task.isCancelled)
            }
            return .success(())
        }
    }
}

private func shutdownFixtureOperations(
    probe: ShutdownFixtureProbe,
    behaviors: [LinuxShutdownBranch: ShutdownFixtureBehavior] = [:]
) -> LinuxShutdownOperations {
    func operation(_ branch: LinuxShutdownBranch) -> LinuxShutdownOperations.Operation {
        shutdownFixtureOperation(branch, behavior: behaviors[branch] ?? .succeed, probe: probe)
    }
    return LinuxShutdownOperations(
        listener: operation(.listener),
        registry: operation(.registry),
        host: operation(.host),
        accept: operation(.accept),
        signal: operation(.signal),
        status: operation(.status)
    )
}

private func shutdownFixtureRequest(deadline: UInt64 = 20_000_000_000) -> LinuxStopRequest {
    LinuxStopRequest(
        reason: .signal(SIGTERM),
        deadline: LinuxShutdownDeadline(monotonicNanoseconds: deadline)
    )
}

private func expectShutdownTimeout(_ operation: () async throws -> Void) async {
    do {
        try await operation()
        Issue.record("expected shutdown timeout")
    } catch {
        #expect(error as? LinuxTransportError == .shutdownTimedOut)
    }
}

private final class SweepFixtureClock: @unchecked Sendable {
    private struct Waiter {
        var deadline: UInt64
        var continuation: CheckedContinuation<Void, any Error>
    }

    struct Snapshot: Sendable {
        var now: UInt64
        var requestedDeadlines: [UInt64]
        var waiting: Int
    }

    private let lock = NSLock()
    private var value: UInt64
    private var requestedDeadlines: [UInt64] = []
    private var waiters: [UUID: Waiter] = [:]

    init(_ value: UInt64) { self.value = value }

    func now() -> UInt64 { lock.withLock { value } }

    func sleep(until deadline: UInt64) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let outcome = lock.withLock { () -> Bool? in
                    requestedDeadlines.append(deadline)
                    if Task.isCancelled { return false }
                    if value >= deadline { return true }
                    waiters[id] = .init(deadline: deadline, continuation: continuation)
                    return nil
                }
                if outcome == true { continuation.resume() }
                if outcome == false { continuation.resume(throwing: CancellationError()) }
            }
        } onCancel: {
            let continuation = self.lock.withLock {
                self.waiters.removeValue(forKey: id)?.continuation
            }
            continuation?.resume(throwing: CancellationError())
        }
    }

    func advance(to newValue: UInt64) {
        let ready = lock.withLock { () -> [CheckedContinuation<Void, any Error>] in
            precondition(newValue >= value)
            value = newValue
            let ids = waiters.compactMap { id, waiter in
                waiter.deadline <= newValue ? id : nil
            }
            return ids.compactMap { waiters.removeValue(forKey: $0)?.continuation }
        }
        ready.forEach { $0.resume() }
    }

    var snapshot: Snapshot {
        lock.withLock {
            .init(now: value, requestedDeadlines: requestedDeadlines, waiting: waiters.count)
        }
    }
}

private final class SweepFixtureProbe: @unchecked Sendable {
    struct Sample: Sendable, Equatable {
        var observation: LinuxSweepObservation
        var reaped: Int
    }

    private let lock = NSLock()
    private var sweepCount = 0
    private var samples: [Sample] = []

    func sweep() async -> Int {
        lock.withLock {
            sweepCount += 1
            return sweepCount
        }
    }

    func record(_ observation: LinuxSweepObservation, reaped: Int) {
        lock.withLock { samples.append(.init(observation: observation, reaped: reaped)) }
    }

    var snapshot: (sweeps: Int, samples: [Sample]) {
        lock.withLock { (sweepCount, samples) }
    }
}

private func sweepEventually(_ predicate: @escaping @Sendable () -> Bool) async -> Bool {
    for _ in 0 ..< 5_000 {
        if predicate() { return true }
        await Task.yield()
    }
    return predicate()
}

@Suite(.serialized) struct LinuxServiceRuntimeTests {
    @Test func sessionSweeperUsesAbsoluteDeadlinesAccountsJitterAndJoinsCancellation() async {
        let startedAt: UInt64 = 10_000_000_000
        let clock = SweepFixtureClock(startedAt)
        let probe = SweepFixtureProbe()
        let sweeper = LinuxSessionSweeper(
            clock: .init(now: clock.now, sleepUntil: clock.sleep),
            sweep: probe.sweep,
            observer: probe.record
        )

        #expect(await sweepEventually {
            clock.snapshot.requestedDeadlines == [startedAt + 1_000_000_000]
        })
        clock.advance(to: startedAt + 1_000_000_000)
        #expect(await sweepEventually {
            probe.snapshot.samples.count == 1 &&
                clock.snapshot.requestedDeadlines.last == startedAt + 2_000_000_000
        })

        clock.advance(to: startedAt + 3_500_000_000)
        #expect(await sweepEventually {
            probe.snapshot.samples.count == 2 &&
                clock.snapshot.requestedDeadlines.last == startedAt + 4_000_000_000
        })
        let samples = probe.snapshot.samples
        #expect(samples == [
            .init(
                observation: .init(
                    scheduledNanoseconds: startedAt + 1_000_000_000,
                    observedNanoseconds: startedAt + 1_000_000_000,
                    delayNanoseconds: 0,
                    skippedDeadlines: 0
                ),
                reaped: 1
            ),
            .init(
                observation: .init(
                    scheduledNanoseconds: startedAt + 2_000_000_000,
                    observedNanoseconds: startedAt + 3_500_000_000,
                    delayNanoseconds: 1_500_000_000,
                    skippedDeadlines: 1
                ),
                reaped: 2
            ),
        ])

        await sweeper.cancelAndWait()
        #expect(clock.snapshot.waiting == 0)
        #expect(probe.snapshot.sweeps == 2)
        await sweeper.cancelAndWait()
        #expect(clock.snapshot.waiting == 0)
    }

    @Test func statusIsPrivacySafeBoundedAndAtomicallyReplaced() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-linux-status-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("status.json").path
        let metrics = LinuxTransportMetrics(
            rawConnections: 9,
            acceptedConnections: 4,
            activeConnections: 2,
            refusedConnections: 5,
            acceptedStreams: 6,
            activeStreams: 1,
            refusedStreams: 3,
            peakConnections: 4,
            peakStreams: 6,
            configurationAttempts: 9,
            configurationSucceeded: 4,
            configurationFailed: 5,
            lastConfigurationStatus: -7,
            connectionRegistrationsRemoved: 8,
            connectionContextReleases: 8,
            applicationConnectionCloses: 4,
            peerCertificateCallbacks: 4,
            lastPeerCertificateLength: 417,
            connectedCallbacks: 4,
            lastTLSQueryStatus: 0,
            lastTLSHandshakeInfoLength: 36,
            lastTLSProtocolVersion: 0x3000,
            lastNegotiatedALPNLength: 7,
            lastNegotiatedALPNMatch: 1,
            peerStreamCallbacks: 6,
            connectionShutdownCompletions: 8,
            lastConnectionOwnership: 1,
            lastShutdownOrigin: 3,
            lastShutdownStatus: 0,
            lastShutdownErrorCode: 19,
            lastShutdownHandshakeCompleted: 1
        )
        let status = LinuxServiceStatus(
            configuration: try fixedConfiguration(),
            ready: true,
            metrics: metrics,
            lastError: String(repeating: "é", count: 400)
        )
        #expect(status.lastError?.utf8.count == 512)
        try LinuxStatusWriter.write(status, path: path)
        var metadata = stat()
        #expect(lstat(path, &metadata) == 0)
        #expect(metadata.st_mode & 0o7777 == 0o600)
        #expect(metadata.st_nlink == 1)

        let decoded = try JSONDecoder().decode(
            LinuxServiceStatus.self,
            from: Data(contentsOf: URL(fileURLWithPath: path))
        )
        #expect(decoded == status)
        let encoded = try productStatusKeys(path)
        #expect(encoded == Set([
            "schemaVersion", "pid", "ready", "modelID", "boundAddress", "boundPort",
            "activeConnections", "activeStreams", "acceptedConnections", "acceptedStreams",
            "refusedConnections", "refusedStreams", "configurationAttempts",
            "configurationSucceeded", "configurationFailed", "lastConfigurationStatus",
            "connectionRegistrationsRemoved", "connectionContextReleases",
            "applicationConnectionCloses", "peerCertificateCallbacks",
            "lastPeerCertificateLength", "connectedCallbacks", "lastTLSQueryStatus",
            "lastTLSHandshakeInfoLength", "lastTLSProtocolVersion",
            "lastNegotiatedALPNLength", "lastNegotiatedALPNMatch", "peerStreamCallbacks",
            "connectionShutdownCompletions", "lastConnectionOwnership",
            "lastShutdownOrigin", "lastShutdownStatus", "lastShutdownErrorCode",
            "lastShutdownHandshakeCompleted", "lastError",
        ]))
        #expect(decoded.schemaVersion == 2)
        #expect(decoded.configurationAttempts == 9)
        #expect(decoded.lastConfigurationStatus == -7)
        #expect(decoded.lastTLSHandshakeInfoLength == 36)
        #expect(decoded.lastNegotiatedALPNMatch == 1)
        #expect(decoded.lastShutdownErrorCode == 19)

        var stopped = status
        stopped.ready = false
        stopped.lastError = nil
        try LinuxStatusWriter.write(stopped, path: path)
        #expect(try JSONDecoder().decode(
            LinuxServiceStatus.self,
            from: Data(contentsOf: URL(fileURLWithPath: path))
        ).ready == false)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: root.path)
        #expect(leftovers == ["status.json"])
    }

    @Test func systemdUnitPinsEveryServiceAndResourceBoundary() throws {
        let unit = try productFile("Linux/package/usr/lib/systemd/system/reachd.service")
        for required in [
            "Type=notify", "NotifyAccess=main", "User=reachd", "Group=reachd",
            "ExecStart=/usr/lib/reach/reachd-linux", "UMask=0077",
            "Restart=on-failure", "RestartPreventExitStatus=64", "RestartSec=2s",
            "StartLimitIntervalSec=60s", "StartLimitBurst=3",
            "TimeoutStartSec=10s", "TimeoutStopSec=15s",
            "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
            "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
            "PrivateDevices=true", "DevicePolicy=closed",
            "ReadOnlyPaths=/etc/reach", "ReadWritePaths=/var/lib/reach /run/reach",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "SystemCallFilter=@system-service", "SystemCallErrorNumber=EPERM",
            "LimitNOFILE=1024", "LimitNPROC=128", "TasksMax=128",
            "MemoryHigh=768M", "MemoryMax=1G",
        ] {
            #expect(unit.contains(required), "missing \(required)")
        }
        for forbidden in [
            "/bin/sh", "/bin/bash", "User=root", "ExecStartPre=", "ExecStartPost=",
            "EnvironmentFile=", "sudo", "curl", "wget", "Bonjour", "avahi",
        ] {
            #expect(!unit.contains(forbidden), "unit contains \(forbidden)")
        }
    }

    @Test func expectedStartupRefusalsAreNoRestartButRuntimeFailureRestarts() {
        let expected: [any Error] = [
            LinuxServiceConfigurationError.invalid("fixture"),
            LinuxServiceConfigurationError.unsafeFile("fixture"),
            LinuxServiceRuntimeError.startupRefused(.exoPreflight, "fixture"),
            LinuxServiceRuntimeError.startupRefused(.credentialOrListener, "fixture"),
            LinuxTransportError.startup("fixture"),
        ]
        for error in expected {
            #expect(LinuxServiceExitStatus.code(for: error) == LinuxServiceExitStatus.noRestart)
        }
        #expect(LinuxServiceExitStatus.code(for: LinuxServiceRuntimeError.runtime("fixture")) ==
            LinuxServiceExitStatus.unexpectedRuntimeFailure)
        #expect(LinuxServiceExitStatus.noRestart == 64)
        #expect(LinuxServiceExitStatus.unexpectedRuntimeFailure == 1)
    }

    @Test func firstStopRequestKeepsItsOriginalAbsoluteDeadline() async {
        let latch = LinuxStopLatch()
        let first = LinuxStopRequest(
            reason: .signal(SIGTERM),
            deadline: LinuxShutdownDeadline(monotonicNanoseconds: 20_000_000_000)
        )
        await latch.request(first)
        await latch.request(LinuxStopRequest(
            reason: .failure("later"),
            deadline: LinuxShutdownDeadline(monotonicNanoseconds: 35_000_000_000)
        ))
        #expect(await latch.wait() == first)
    }

    @Test func shutdownHappyPathStartsAllBranchesAndSettlesBeforeTheOneDeadline() async throws {
        let request = shutdownFixtureRequest()
        let probe = ShutdownFixtureProbe()
        let clock = ShutdownFixtureClock(request.deadline.monotonicNanoseconds - 1)
        try await LinuxShutdownCoordinator.settle(
            request: request,
            operations: shutdownFixtureOperations(probe: probe),
            clock: LinuxShutdownClock(
                now: clock.now,
                sleepUntil: { _ in try? await Task.sleep(for: .seconds(60)) }
            )
        )
        await probe.waitUntilZero()
        let snapshot = await probe.snapshot
        #expect(snapshot.started == Set(LinuxShutdownBranch.allCases))
        #expect(snapshot.completed == Set(LinuxShutdownBranch.allCases))
        #expect(snapshot.cancelled.isEmpty)
        #expect(snapshot.active == 0)
        #expect(snapshot.peakActive == LinuxShutdownBranch.allCases.count)
        #expect(snapshot.deadlines.values.allSatisfy { $0 == request.deadline })
    }

    @Test func everyShutdownBranchTimesOutAtTheSameDeadlineAndLeavesNoFixtureTask() async {
        for stalled in LinuxShutdownBranch.allCases {
            let request = shutdownFixtureRequest()
            let probe = ShutdownFixtureProbe()
            let clock = ShutdownFixtureClock(request.deadline.monotonicNanoseconds - 1)
            await expectShutdownTimeout {
                try await LinuxShutdownCoordinator.settle(
                    request: request,
                    operations: shutdownFixtureOperations(
                        probe: probe,
                        behaviors: [stalled: .stall]
                    ),
                    clock: LinuxShutdownClock(
                        now: clock.now,
                        sleepUntil: { deadline in
                            await probe.waitUntilAllStarted()
                            clock.set(deadline)
                        }
                    )
                )
            }
            await probe.waitUntilZero()
            let snapshot = await probe.snapshot
            #expect(snapshot.started == Set(LinuxShutdownBranch.allCases))
            #expect(snapshot.completed == Set(LinuxShutdownBranch.allCases))
            #expect(snapshot.cancelled == [stalled])
            #expect(snapshot.active == 0)
            #expect(snapshot.peakActive == LinuxShutdownBranch.allCases.count)
            #expect(snapshot.deadlines.values.allSatisfy { $0 == request.deadline })
        }
    }

    @Test func deadlineEqualityAndTimeoutPrecedenceAreFailClosed() async {
        let equalityRequest = shutdownFixtureRequest()
        let equalityProbe = ShutdownFixtureProbe()
        let equalityClock = ShutdownFixtureClock(equalityRequest.deadline.monotonicNanoseconds)
        await expectShutdownTimeout {
            try await LinuxShutdownCoordinator.settle(
                request: equalityRequest,
                operations: shutdownFixtureOperations(probe: equalityProbe),
                clock: LinuxShutdownClock(
                    now: equalityClock.now,
                    sleepUntil: { _ in try? await Task.sleep(for: .seconds(60)) }
                )
            )
        }
        await equalityProbe.waitUntilZero()
        #expect(await equalityProbe.snapshot.active == 0)

        let precedenceRequest = shutdownFixtureRequest()
        let precedenceProbe = ShutdownFixtureProbe()
        let precedenceClock = ShutdownFixtureClock(precedenceRequest.deadline.monotonicNanoseconds - 1)
        await expectShutdownTimeout {
            try await LinuxShutdownCoordinator.settle(
                request: precedenceRequest,
                operations: shutdownFixtureOperations(
                    probe: precedenceProbe,
                    behaviors: [.listener: .fail, .host: .stall]
                ),
                clock: LinuxShutdownClock(
                    now: precedenceClock.now,
                    sleepUntil: { deadline in
                        await precedenceProbe.waitUntilAllStarted()
                        precedenceClock.set(deadline)
                    }
                )
            )
        }
        await precedenceProbe.waitUntilZero()
        let snapshot = await precedenceProbe.snapshot
        #expect(snapshot.cancelled == [.host])
        #expect(snapshot.active == 0)
    }

    @Test func inTimeShutdownFailurePreservesTheOriginalError() async {
        let request = shutdownFixtureRequest()
        let probe = ShutdownFixtureProbe()
        let clock = ShutdownFixtureClock(request.deadline.monotonicNanoseconds - 1)
        do {
            try await LinuxShutdownCoordinator.settle(
                request: request,
                operations: shutdownFixtureOperations(
                    probe: probe,
                    behaviors: [.registry: .fail]
                ),
                clock: LinuxShutdownClock(
                    now: clock.now,
                    sleepUntil: { _ in try? await Task.sleep(for: .seconds(60)) }
                )
            )
            Issue.record("expected original shutdown failure")
        } catch {
            #expect(error as? ShutdownFixtureError == .failed(.registry))
        }
        await probe.waitUntilZero()
        let snapshot = await probe.snapshot
        #expect(snapshot.active == 0)
        #expect(snapshot.cancelled.isEmpty)
    }

    @Test func installIsInertAndRemovalPreservesOperatorConfiguration() throws {
        let postinst = try productFile("Linux/package/DEBIAN/postinst")
        let prerm = try productFile("Linux/package/DEBIAN/prerm")
        let postrm = try productFile("Linux/package/DEBIAN/postrm")
        let sysusers = try productFile("Linux/package/usr/lib/sysusers.d/reachd.conf")
        let tmpfiles = try productFile("Linux/package/usr/lib/tmpfiles.d/reachd.conf")
        for forbidden in ["enable", " start", "curl", "wget", "openssl", "/etc/reach"] {
            #expect(!postinst.contains(forbidden), "postinst contains \(forbidden)")
        }
        #expect(postinst.contains("systemd-sysusers"))
        #expect(prerm.contains("disable --now reachd.service"))
        #expect(postrm.contains("/var/lib/reach /run/reach"))
        #expect(!postrm.contains("/etc/reach"))
        #expect(sysusers == "u reachd - \"Reach service\" - /usr/sbin/nologin\n")
        #expect(tmpfiles.contains("d /var/lib/reach 0700 reachd reachd -"))
        #expect(tmpfiles.contains("d /run/reach 0700 reachd reachd -"))
    }

    @Test func LinuxTargetClosureExcludesAppleAndModelStacks() throws {
        let package = try productFile("Package.swift")
        let linuxStart = try #require(package.range(of: "#if os(Linux)"))
        let linuxEnd = try #require(package.range(of: "#else", range: linuxStart.upperBound ..< package.endIndex))
        let linux = String(package[linuxStart.lowerBound ..< linuxEnd.lowerBound])
        for forbidden in [
            ".product(name: \"ReachKit\"", "ReachTransport\"", "ReachIdentity\"", "MLX", "HuggingFace",
            "Transformers", "X509", "Metal", "CoreImage", "ImageIO", "Network",
        ] {
            #expect(!linux.contains(forbidden), "Linux target closure contains \(forbidden)")
        }
        #expect(linux.contains("ReachHost"))
        #expect(linux.contains("ReachWire"))
        #expect(linux.contains("CReachLinuxMsQuic"))
        #expect(linux.contains("reachd-linux"))
    }

    @Test func CShimUsesOnlyTheSelectedPreviewSurface() throws {
        let source = try productFile("Sources/CReachLinuxMsQuic/CReachLinuxMsQuic.c")
        #expect(source.contains("#define QUIC_API_ENABLE_PREVIEW_FEATURES 1"))
        #expect(source.contains("QUIC_VERSION_SETTINGS"))
        #expect(source.contains("QUIC_PARAM_GLOBAL_VERSION_SETTINGS"))
        #expect(!source.contains("StreamMultiReceiveEnabled"))
        let header = try productFile("Sources/CReachLinuxMsQuic/vendor/msquic.h")
        let allowedPreviewIdentifiers: Set<String> = [
            "QUIC_API_ENABLE_PREVIEW_FEATURES",
            "QUIC_VERSION_SETTINGS",
            "QUIC_PARAM_GLOBAL_VERSION_SETTINGS",
            // These are the fields of the one permitted preview structure,
            // not additional preview APIs.
            "AcceptableVersions",
            "OfferedVersions",
            "FullyDeployedVersions",
            "AcceptableVersionsLength",
            "OfferedVersionsLength",
            "FullyDeployedVersionsLength",
        ]
        let unauthorizedPreviewIdentifiers = sourceIdentifiers(source)
            .intersection(previewOnlyIdentifiers(header))
            .subtracting(allowedPreviewIdentifiers)
        #expect(
            unauthorizedPreviewIdentifiers.isEmpty,
            "C shim uses unauthorized preview identifiers: \(unauthorizedPreviewIdentifiers.sorted())"
        )
        for forbidden in [
            "StreamProvideReceiveBuffers", "ConnectionPoolCreate", "ExecutionCreate",
            "QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED",
            "QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED",
            "QUIC_CONNECTION_EVENT_NETWORK_STATISTICS",
        ] {
            #expect(!source.contains(forbidden), "C shim uses \(forbidden)")
        }
        #expect(source.contains("QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION"))
        #expect(source.contains("QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION"))
        #expect(!source.contains("NO_CERTIFICATE_VALIDATION"))
        #expect(source.contains("QUIC_SERVER_NO_RESUME"))
        #expect(source.contains("DatagramReceiveEnabled = FALSE"))
        #expect(source.contains("MigrationEnabled = FALSE"))
        #expect(source.contains("QUIC_BUFFER receive_buffers[REACH_RECEIVE_DESCRIPTOR_LIMIT]"))
        #expect(source.contains("memcpy(\n            stream->receive_buffers"))
        #expect(source.contains("return QUIC_STATUS_PENDING"))
        #expect(source.contains("StreamReceiveComplete"))
        #expect(source.contains("TakePendingReceiveLocked"))
        #expect(source.contains("active_api_calls"))
        #expect(source.contains("shutdown_complete"))
        #expect(source.contains("#define REACH_RECEIVE_DESCRIPTOR_LIMIT 2U"))
    }

    private func productStatusKeys(_ path: String) throws -> Set<String> {
        let object = try JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: path))
        )
        return Set(try #require(object as? [String: Any]).keys)
    }
}
