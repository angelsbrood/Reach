import Foundation
import Testing
import ReachWire
@testable import ReachDaemon

private final class TestMappingRequest: PortMappingRequest, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var wasCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

private final class TestMappingBroker: PortMappingBroker, @unchecked Sendable {
    struct Call: Sendable, Equatable {
        var internalPort: UInt16
        var externalPort: UInt16
        var ttl: UInt32
    }

    private let lock = NSLock()
    private var callbacks: [UInt16: @Sendable (PortMappingReply) -> Void] = [:]
    private var mutableCalls: [Call] = []
    private var mutableRequests: [UInt16: TestMappingRequest] = [:]

    var calls: [Call] {
        lock.lock()
        defer { lock.unlock() }
        return mutableCalls
    }

    func request(
        internalPort: UInt16,
        externalPort: UInt16,
        ttl: UInt32,
        callback: @escaping @Sendable (PortMappingReply) -> Void
    ) throws -> any PortMappingRequest {
        let request = TestMappingRequest()
        lock.lock()
        mutableCalls.append(Call(internalPort: internalPort, externalPort: externalPort, ttl: ttl))
        callbacks[internalPort] = callback
        mutableRequests[internalPort] = request
        lock.unlock()
        return request
    }

    func reply(
        to port: UInt16,
        code: Int32 = 0,
        host: String? = "198.51.100.8",
        externalPort: UInt16? = nil,
        ttl: UInt32 = 7_200
    ) {
        lock.lock()
        let callback = callbacks[port]
        lock.unlock()
        callback?(PortMappingReply(
            errorCode: code,
            interfaceIndex: 14,
            externalAddress: host,
            internalPort: port,
            externalPort: externalPort ?? port,
            ttl: ttl
        ))
    }

    func request(for port: UInt16) -> TestMappingRequest? {
        lock.lock()
        defer { lock.unlock() }
        return mutableRequests[port]
    }
}

@Suite struct ReachabilityCoordinatorTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-mapping-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func requestsBothUDPPortsWithSystemDefaults() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = TestMappingBroker()
        let coordinator = ReachabilityCoordinator(
            sessionPort: 47337,
            stateDirectory: directory,
            broker: broker
        )

        coordinator.start()
        #expect(broker.calls == [
            .init(internalPort: 47337, externalPort: 47337, ttl: 0),
            .init(internalPort: 51820, externalPort: 51820, ttl: 0),
        ])
        #expect(coordinator.snapshot.session.state == .probing)
        #expect(coordinator.snapshot.mesh.state == .probing)
    }

    @Test func differingPortsAndMovementReplaceTheActiveEndpoint() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = TestMappingBroker()
        let coordinator = ReachabilityCoordinator(sessionPort: 47337, stateDirectory: directory, broker: broker)
        coordinator.start()

        broker.reply(to: 47337, host: "198.51.100.8", externalPort: 55001)
        #expect(coordinator.sessionEndpoint == RoadEndpoint(host: "198.51.100.8", port: 55001))
        broker.reply(to: 47337, host: "198.51.100.9", externalPort: 55002)

        #expect(coordinator.sessionEndpoint == RoadEndpoint(host: "198.51.100.9", port: 55002))
        #expect(coordinator.snapshot.session.previousEndpoint == RoadEndpoint(host: "198.51.100.8", port: 55001))
        #expect(coordinator.snapshot.session.changeCount == 1)
    }

    @Test func doubleNATIsUsableButClassified() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = TestMappingBroker()
        let coordinator = ReachabilityCoordinator(sessionPort: 47337, stateDirectory: directory, broker: broker)
        coordinator.start()
        broker.reply(to: 51820, code: -65558, host: "192.168.4.94", externalPort: 55180)

        #expect(coordinator.meshEndpoint == RoadEndpoint(host: "192.168.4.94", port: 55180))
        #expect(coordinator.snapshot.mesh.doubleNAT)
        #expect(HostCheck.mappingFinding(coordinator.snapshot.mesh).detail.contains("private outer"))
    }

    @Test func zeroAndUnsupportedRepliesAreNonfatalAndUndialable() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = TestMappingBroker()
        let coordinator = ReachabilityCoordinator(sessionPort: 47337, stateDirectory: directory, broker: broker)
        coordinator.start()
        broker.reply(to: 47337, host: nil, externalPort: 0, ttl: 0)
        broker.reply(to: 51820, code: -65564, host: nil, externalPort: 0, ttl: 0)

        #expect(coordinator.sessionEndpoint == nil)
        #expect(coordinator.snapshot.session.state == .unavailable)
        #expect(coordinator.meshEndpoint == nil)
        #expect(coordinator.snapshot.mesh.state == .unsupported)
    }

    @Test func stopDeallocatesBothMappingsAndRecordsIt() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = TestMappingBroker()
        let coordinator = ReachabilityCoordinator(sessionPort: 47337, stateDirectory: directory, broker: broker)
        coordinator.start()
        coordinator.stop()

        #expect(broker.request(for: 47337)?.wasCancelled == true)
        #expect(broker.request(for: 51820)?.wasCancelled == true)
        #expect(coordinator.snapshot.session.state == .stopped)
        #expect(coordinator.snapshot.mesh.state == .stopped)
    }

    @Test func statusFileIsPrivateAndDoctorDetectsStaleEvidence() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let broker = TestMappingBroker()
        let coordinator = ReachabilityCoordinator(sessionPort: 47337, stateDirectory: directory, broker: broker)
        coordinator.start()
        broker.reply(to: 47337)

        let url = directory.appendingPathComponent(ReachabilityCoordinator.statusFileName)
        let mode = try #require(
            (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue
        )
        #expect(mode & 0o777 == 0o600)

        let findings = HostCheck.checkReachability(in: directory, daemonUp: false, processIsAlive: { _ in false })
        #expect(findings.count == 2)
        #expect(findings.allSatisfy { $0.detail.contains("stale runtime state") })
    }
}

@Suite struct MappedMeshEndpointTests {
    @Test func pinWinsThenMappingWinsThenDerivation() {
        let mapped = RoadEndpoint(host: "198.51.100.8", port: 55180)
        var pinnedConfig = DaemonConfig()
        pinnedConfig.meshEndpoint = "203.0.113.7:51820"
        #expect(MeshEndpoint.resolve(config: pinnedConfig, mapped: mapped, addresses: []).source == .pinned)

        let automatic = MeshEndpoint.resolve(config: DaemonConfig(), mapped: mapped, addresses: [[192, 168, 8, 210]])
        #expect(automatic.source == .mapped)
        #expect(automatic.endpoint == "198.51.100.8:55180")

        let fallback = MeshEndpoint.resolve(config: DaemonConfig(), mapped: nil, addresses: [[192, 168, 8, 210]])
        #expect(fallback.source == .derived)
        #expect(fallback.endpoint == "192.168.8.210:51820")
    }
}

@Suite struct RoadAdvertisementTests {
    @Test func translatedPortAppearsOnlyInEndpointSpecificRoads() {
        let mapped = RoadEndpoint(host: "198.51.100.8", port: 55001)
        let advertisement = Daemon.roadAdvertisement(
            localAddresses: ["192.168.8.210"],
            port: 47337,
            mapped: mapped
        )
        #expect(advertisement.roads.contains(mapped))
        #expect(!advertisement.legacyAddresses.contains(mapped.host))
    }

    @Test func samePortMappingRemainsVisibleToLegacyClients() {
        let mapped = RoadEndpoint(host: "198.51.100.8", port: 47337)
        let advertisement = Daemon.roadAdvertisement(
            localAddresses: ["192.168.8.210"],
            port: 47337,
            mapped: mapped
        )
        #expect(advertisement.roads.contains(mapped))
        #expect(advertisement.legacyAddresses.contains(mapped.host))
    }
}
