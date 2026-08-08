import Darwin
import Foundation
import ReachWire
import dnssd

/// Runtime evidence for one long-lived system port-mapping request.
public struct PortMappingRuntime: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable {
        case session
        case mesh
    }

    public enum State: String, Codable, Sendable {
        case probing
        case active
        case unsupported
        case disabled
        case noRouter
        case unavailable
        case failed
        case stopped
    }

    public var kind: Kind
    public var internalPort: UInt16
    public var state: State
    public var endpoint: RoadEndpoint?
    public var ttl: UInt32?
    public var doubleNAT: Bool
    public var interfaceIndex: UInt32?
    public var errorCode: Int32?
    public var error: String?
    public var changeCount: UInt64
    public var previousEndpoint: RoadEndpoint?
    public var updatedAt: Date

    public init(kind: Kind, internalPort: UInt16, now: Date = Date()) {
        self.kind = kind
        self.internalPort = internalPort
        state = .probing
        endpoint = nil
        ttl = nil
        doubleNAT = false
        interfaceIndex = nil
        errorCode = nil
        error = nil
        changeCount = 0
        previousEndpoint = nil
        updatedAt = now
    }
}

/// Diagnostic state only. It is replaced by the running process and is never
/// read as configuration or as authority for an advertised route.
public struct ReachabilityRuntime: Codable, Sendable, Equatable {
    public var processID: Int32
    public var processStartedAt: Date
    public var updatedAt: Date
    public var session: PortMappingRuntime
    public var mesh: PortMappingRuntime

    public init(
        processID: Int32 = getpid(),
        processStartedAt: Date = Date(),
        updatedAt: Date = Date(),
        session: PortMappingRuntime,
        mesh: PortMappingRuntime
    ) {
        self.processID = processID
        self.processStartedAt = processStartedAt
        self.updatedAt = updatedAt
        self.session = session
        self.mesh = mesh
    }
}

public struct PortMappingReply: Sendable, Equatable {
    public var errorCode: Int32
    public var interfaceIndex: UInt32
    public var externalAddress: String?
    public var internalPort: UInt16
    public var externalPort: UInt16
    public var ttl: UInt32

    public init(
        errorCode: Int32,
        interfaceIndex: UInt32,
        externalAddress: String?,
        internalPort: UInt16,
        externalPort: UInt16,
        ttl: UInt32
    ) {
        self.errorCode = errorCode
        self.interfaceIndex = interfaceIndex
        self.externalAddress = externalAddress
        self.internalPort = internalPort
        self.externalPort = externalPort
        self.ttl = ttl
    }
}

public protocol PortMappingRequest: AnyObject, Sendable {
    func cancel()
}

public protocol PortMappingBroker: Sendable {
    func request(
        internalPort: UInt16,
        externalPort: UInt16,
        ttl: UInt32,
        callback: @escaping @Sendable (PortMappingReply) -> Void
    ) throws -> any PortMappingRequest
}

public struct SystemPortMappingBroker: PortMappingBroker {
    public init() {}

    public func request(
        internalPort: UInt16,
        externalPort: UInt16,
        ttl: UInt32,
        callback: @escaping @Sendable (PortMappingReply) -> Void
    ) throws -> any PortMappingRequest {
        try SystemPortMappingRequest(
            internalPort: internalPort,
            externalPort: externalPort,
            ttl: ttl,
            callback: callback
        )
    }
}

private final class NATCallbackBox: @unchecked Sendable {
    let callback: @Sendable (PortMappingReply) -> Void

    init(callback: @escaping @Sendable (PortMappingReply) -> Void) {
        self.callback = callback
    }
}

private final class SystemPortMappingRequest: PortMappingRequest, @unchecked Sendable {
    private let lock = NSLock()
    private var service: DNSServiceRef?
    private let context: Unmanaged<NATCallbackBox>

    init(
        internalPort: UInt16,
        externalPort: UInt16,
        ttl: UInt32,
        callback: @escaping @Sendable (PortMappingReply) -> Void
    ) throws {
        context = .passRetained(NATCallbackBox(callback: callback))
        var service: DNSServiceRef?
        let result = DNSServiceNATPortMappingCreate(
            &service,
            0,
            0,
            DNSServiceProtocol(kDNSServiceProtocol_UDP),
            internalPort.bigEndian,
            externalPort.bigEndian,
            ttl,
            { _, _, interfaceIndex, errorCode, externalAddress, _, internalPort, externalPort, ttl, context in
                guard let context else { return }
                let box = Unmanaged<NATCallbackBox>.fromOpaque(context).takeUnretainedValue()
                box.callback(PortMappingReply(
                    errorCode: errorCode,
                    interfaceIndex: interfaceIndex,
                    externalAddress: natIPv4(externalAddress),
                    internalPort: UInt16(bigEndian: internalPort),
                    externalPort: UInt16(bigEndian: externalPort),
                    ttl: ttl
                ))
            },
            context.toOpaque()
        )
        guard result == kDNSServiceErr_NoError, let service else {
            context.release()
            throw PortMappingStartError(code: result)
        }
        self.service = service
        let queueResult = DNSServiceSetDispatchQueue(service, DispatchQueue(label: "systems.reach.nat-map.\(internalPort)"))
        guard queueResult == kDNSServiceErr_NoError else {
            DNSServiceRefDeallocate(service)
            self.service = nil
            context.release()
            throw PortMappingStartError(code: queueResult)
        }
    }

    deinit {
        cancel()
        context.release()
    }

    func cancel() {
        lock.lock()
        let service = self.service
        self.service = nil
        lock.unlock()
        if let service { DNSServiceRefDeallocate(service) }
    }
}

private func natIPv4(_ networkAddress: UInt32) -> String? {
    guard networkAddress != 0 else { return nil }
    var address = in_addr(s_addr: networkAddress)
    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
    return String(
        decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
        as: UTF8.self
    )
}

private struct PortMappingStartError: Error, CustomStringConvertible {
    let code: Int32
    var description: String { "DNSServiceNATPortMappingCreate failed (\(code))" }
}

/// Owns the daemon's session and WireGuard mappings for the life of the
/// process. Bonjour and the status file are evidence only; authenticated
/// `HelloAck` and enrollment grants read the in-memory snapshot.
public final class ReachabilityCoordinator: @unchecked Sendable {
    public static let statusFileName = "reachability.json"

    private let lock = NSLock()
    private let persistenceLock = NSLock()
    private let broker: any PortMappingBroker
    private let statusURL: URL
    private var runtime: ReachabilityRuntime
    private var requests: [PortMappingRuntime.Kind: any PortMappingRequest] = [:]
    private var started = false

    public init(
        sessionPort: UInt16,
        meshPort: UInt16 = MeshEndpoint.port,
        stateDirectory: URL = DaemonInfo.stateDirectory,
        broker: any PortMappingBroker = SystemPortMappingBroker(),
        now: Date = Date()
    ) {
        self.broker = broker
        statusURL = stateDirectory.appendingPathComponent(Self.statusFileName)
        runtime = ReachabilityRuntime(
            processStartedAt: now,
            updatedAt: now,
            session: PortMappingRuntime(kind: .session, internalPort: sessionPort, now: now),
            mesh: PortMappingRuntime(kind: .mesh, internalPort: meshPort, now: now)
        )
    }

    public var snapshot: ReachabilityRuntime {
        lock.withLock { runtime }
    }

    public var sessionEndpoint: RoadEndpoint? {
        lock.withLock { runtime.session.state == .active ? runtime.session.endpoint : nil }
    }

    public var meshEndpoint: RoadEndpoint? {
        lock.withLock { runtime.mesh.state == .active ? runtime.mesh.endpoint : nil }
    }

    public func start() {
        lock.lock()
        guard !started else {
            lock.unlock()
            return
        }
        started = true
        let ports: [(PortMappingRuntime.Kind, UInt16)] = [
            (.session, runtime.session.internalPort),
            (.mesh, runtime.mesh.internalPort),
        ]
        let initial = runtime
        lock.unlock()
        persist(initial)

        for (kind, port) in ports {
            do {
                let request = try broker.request(internalPort: port, externalPort: port, ttl: 0) { [weak self] reply in
                    self?.receive(reply, for: kind)
                }
                lock.withLock { requests[kind] = request }
            } catch {
                recordStartFailure(error, for: kind)
            }
        }
    }

    public func stop() {
        let (requests, stopped): ([any PortMappingRequest], ReachabilityRuntime) = lock.withLock {
            guard started else { return ([], runtime) }
            started = false
            let requests = Array(self.requests.values)
            self.requests = [:]
            let now = Date()
            runtime.session.state = .stopped
            runtime.session.endpoint = nil
            runtime.session.updatedAt = now
            runtime.mesh.state = .stopped
            runtime.mesh.endpoint = nil
            runtime.mesh.updatedAt = now
            runtime.updatedAt = now
            return (requests, runtime)
        }
        requests.forEach { $0.cancel() }
        persist(stopped)
    }

    private func receive(_ reply: PortMappingReply, for kind: PortMappingRuntime.Kind) {
        let snapshot: ReachabilityRuntime? = lock.withLock {
            guard started else { return nil }
            var mapping = kind == .session ? runtime.session : runtime.mesh
            let now = Date()
            mapping.updatedAt = now
            mapping.interfaceIndex = reply.interfaceIndex
            mapping.errorCode = reply.errorCode == Int32(kDNSServiceErr_NoError) ? nil : reply.errorCode
            mapping.ttl = reply.ttl == 0 ? nil : reply.ttl

            let isUsable = reply.errorCode == Int32(kDNSServiceErr_NoError)
                || reply.errorCode == Int32(kDNSServiceErr_DoubleNAT)
            if isUsable, let host = reply.externalAddress, reply.externalPort != 0 {
                let endpoint = RoadEndpoint(host: host, port: reply.externalPort)
                if let old = mapping.endpoint, old != endpoint {
                    mapping.previousEndpoint = old
                    mapping.changeCount += 1
                }
                mapping.state = .active
                mapping.endpoint = endpoint
                mapping.doubleNAT = reply.errorCode == Int32(kDNSServiceErr_DoubleNAT)
                mapping.error = mapping.doubleNAT ? "gateway reported double NAT" : nil
            } else {
                mapping.endpoint = nil
                mapping.doubleNAT = false
                mapping.state = Self.state(for: reply.errorCode)
                mapping.error = Self.message(for: reply.errorCode, zeroEndpoint: reply.externalAddress == nil || reply.externalPort == 0)
            }

            if kind == .session { runtime.session = mapping } else { runtime.mesh = mapping }
            runtime.updatedAt = now
            return runtime
        }
        if let snapshot {
            persist(snapshot)
            let mapping = kind == .session ? snapshot.session : snapshot.mesh
            log(mapping)
        }
    }

    private func recordStartFailure(_ error: Error, for kind: PortMappingRuntime.Kind) {
        let snapshot = lock.withLock { () -> ReachabilityRuntime in
            var mapping = kind == .session ? runtime.session : runtime.mesh
            let now = Date()
            mapping.state = .failed
            mapping.error = "\(error)"
            mapping.updatedAt = now
            if let error = error as? PortMappingStartError { mapping.errorCode = error.code }
            if kind == .session { runtime.session = mapping } else { runtime.mesh = mapping }
            runtime.updatedAt = now
            return runtime
        }
        persist(snapshot)
        let mapping = kind == .session ? snapshot.session : snapshot.mesh
        log(mapping)
    }

    private static func state(for code: Int32) -> PortMappingRuntime.State {
        switch code {
        case Int32(kDNSServiceErr_NATPortMappingUnsupported), Int32(kDNSServiceErr_Unsupported): .unsupported
        case Int32(kDNSServiceErr_NATPortMappingDisabled): .disabled
        case Int32(kDNSServiceErr_NoRouter): .noRouter
        case Int32(kDNSServiceErr_NoError): .unavailable
        default: .failed
        }
    }

    private static func message(for code: Int32, zeroEndpoint: Bool) -> String {
        if code == Int32(kDNSServiceErr_NoError), zeroEndpoint { return "broker returned no usable endpoint" }
        switch code {
        case Int32(kDNSServiceErr_NATPortMappingUnsupported), Int32(kDNSServiceErr_Unsupported):
            return "router does not support PCP, NAT-PMP, or UPnP mapping"
        case Int32(kDNSServiceErr_NATPortMappingDisabled):
            return "router supports mapping but it is disabled"
        case Int32(kDNSServiceErr_NoRouter):
            return "no router is currently available"
        default:
            return "mapping broker error \(code)"
        }
    }

    private func log(_ mapping: PortMappingRuntime) {
        let name = mapping.kind.rawValue
        if mapping.state == .active, let endpoint = mapping.endpoint {
            let warning = mapping.doubleNAT ? " — warning: private outer-network road (double NAT)" : ""
            let movement = mapping.changeCount > 0 ? " — replaced a previous endpoint" : ""
            Log.info("\(name) mapping active at \(endpoint.host):\(endpoint.port), TTL \(mapping.ttl ?? 0) s\(warning)\(movement)")
        } else {
            Log.info("\(name) mapping \(mapping.state.rawValue): \(mapping.error ?? "no usable endpoint") — local and pinned roads remain available")
        }
    }

    private func persist(_ snapshot: ReachabilityRuntime) {
        persistenceLock.lock()
        defer { persistenceLock.unlock() }
        // A callback can be delayed after it leaves the state lock. Always
        // write the newest in-memory value, never the delayed snapshot.
        let snapshot = lock.withLock { runtime.updatedAt >= snapshot.updatedAt ? runtime : snapshot }
        do {
            let directory = statusURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(snapshot).write(to: statusURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: statusURL.path)
        } catch {
            Log.error("reachability evidence did not persist: \(error)")
        }
    }
}

private extension NSLock {
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
