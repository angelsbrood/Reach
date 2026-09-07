import Foundation
import Darwin
import MLX
import LifecycleFixtures
import DurableSessionLifecycle
import DurableClientReceipts
import DurableHostStore
import ResumableMLXProvider
import HostClientContract
import ReachWire

public final class JoinedFixture {
    public let root: URL, hostPath: String, clientPath: String
    public let hostClock: FixtureLifecycleClock, clientClock: FixtureClientClock
    public let hostIdentity: LifecycleIdentity, clientEnvironment: ClientEnvironment
    public let hostKeys: LifecycleKeys, clientKey: Data, auth: LifecycleAuthorization
    public var clientAuth: ClientAuthorization!
    public var host: DurableSessionLifecycle!
    public var client: DurableClientReceipts!
    public var ticket: SessionTicket!
    public var attachment: LifecycleAttachment!
    public var handle: ClientHandle!
    public var authority: ClientAuthority!
    public var setup: PFSetup!
    public var generation = ""
    public var frames: [HandoffBatch] = []
    public var clientFault: ClientFaultHook = { _ in }
    public init(route: String = "ordinary", lifetime: UInt64 = LifecycleLimits.session) throws {
        guard let base = ProcessInfo.processInfo.environment["S84_FIXTURES"] else { throw HandoffError.unavailable }
        root = URL(fileURLWithPath: base).appendingPathComponent(UUID().uuidString.lowercased())
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        hostPath = root.appendingPathComponent("host").path; clientPath = root.appendingPathComponent("client").path
        hostClock = try .init(id: "s84-host", time: 1_000_000_000); clientClock = try .init(id: "s84-client", time: 1_000_000_000)
        hostIdentity = try .init(clock: hostClock); clientEnvironment = try .init(clock: clientClock)
        hostKeys = try lifecycleKeys(); clientKey = clientRandomKey(); auth = caller()
        host = try .initialize(at: hostPath, identity: hostIdentity, keys: hostKeys, clock: hostClock)
        ticket = try host.issueTicket(authorization: auth, lifetime: lifetime)
        try newGeneration(route: route, generation: "g-1")
    }
    deinit { client?.close(); host?.close(); try? FileManager.default.removeItem(at: root) }
    public func newGeneration(route: String, generation: String) throws {
        self.generation = generation; frames = []
        setup = try Device.withDefaultDevice(Device(.cpu)) { try PFSetup(route) }
        setup.binding.operationID = "s84-operation:"+generation; setup.binding.requestID = "s84-request:"+generation
        attachment = try host.begin(ticket: ticket, authorization: auth, generation: generation, provider: setup.binding).attachment
        guard attachment != nil else { throw HandoffError.invalid }
        let bytes = try host.exportClientContext(ticket: ticket, authorization: auth, attachment: attachment)
        authority = try ClientAuthority(HandoffContract.decode(ClientContext.self, bytes, maximum: HandoffContract.context))
        clientAuth = .init(caller: authority.context.caller)
        if client == nil {
            (client, handle) = try DurableClientReceipts.openHostJoin(at: clientPath, fresh: true, environment: clientEnvironment, metadataKey: clientKey,
                clock: clientClock, authority: authority, authorization: clientAuth) { [weak self] in try self?.clientFault($0) }
        } else { handle = try client.open(authority, authorization: clientAuth) }
    }
    public func witness() throws -> HandoffWitness { try client.hostWitness(handle, authority: authority, authorization: clientAuth) }
    public func drain() throws -> HandoffWitness {
        let cursor = try witness().high
        let next = try host.replayForClient(ticket: ticket, authorization: auth, attachment: attachment, after: cursor)
        for batch in next {
            _ = try client.acceptHostBatch(batch, requestedCursor: cursor, handle: handle, authority: authority, authorization: clientAuth)
            frames.append(batch)
        }
        return try witness()
    }
    public func drive() throws -> HandoffWitness {
        for _ in 0..<600 {
            let current = try witness()
            if current.terminal { return current }
            _ = try accept(current)
            _ = try host.step(ticket: ticket, authorization: auth, attachment: attachment) { self.setup.runtime }
            _ = try drain()
            guard Memory.peakMemory <= 128<<20 else { throw HandoffError.oversized }
        }
        throw HandoffError.invalid
    }
    @discardableResult public func accept(_ witness: HandoffWitness, expectedRoot: String? = nil,
                                          hook: () throws -> Void = {}) throws -> LifecycleStatus {
        try host.acceptClientWitness(witness, expectedClientRoot: expectedRoot ?? clientEnvironment.rootID, ticket: ticket,
            authorization: auth, generation: generation, attachment: attachment, publicationHook: hook)
    }
    public func reopenClient() throws {
        client.close()
        (client, handle) = try DurableClientReceipts.openHostJoin(at: clientPath, fresh: false, environment: clientEnvironment, metadataKey: clientKey,
            clock: clientClock, authority: authority, authorization: clientAuth) { [weak self] in try self?.clientFault($0) }
    }
    public func firstTool() throws -> ToolBinding {
        for batch in try client.inbox(handle, authority: authority, authorization: clientAuth) {
            for event in try ClientEvents.decode(batch) {
                if case .toolCallAppendArguments(_, let id, let name, let arguments, _) = event {
                    return try .init(id: Data(id.utf8), name: Data(name.utf8), arguments: Data(arguments.utf8))
                }
            }
        }
        throw HandoffError.invalid
    }
    public static func allocation(_ path: String) throws -> Int {
        let root = URL(fileURLWithPath: path)
        let all = [root]+((FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)?.allObjects as? [URL]) ?? [])
        return try all.reduce(0) { total, url in
            var s = stat(); guard lstat(url.path, &s) == 0 else { throw HandoffError.unavailable }; return total+Int(s.st_blocks)*512
        }
    }
}
