import Foundation
import DurableRootKeys
import DurableStoreBootstrap
import HostClientContract

/// Private test-control vocabulary. It deliberately has no storage-key fields.
public struct BootstrapMessage: Codable {
    public var action: String
    public var root: String?, container: String?, slot: String?, password: String?, optIn: Bool?, fresh: Bool?
    public var workers: [FrozenWorker]?, policy: BootstrapPolicy?, boundary: String?, role: RootKeyRole?
    public var reference: RootKeyReference?, binding: String?, confirmation: Data?
    public var ticket: Data?, context: Data?, generation: String?, route: String?, cursor: UInt64?, time: UInt64?, allowed: Bool?
    public var frame: HandoffBatch?, witness: HandoffWitness?
    public var bootstrapID: String?, hostID: String?, clientID: String?, boot: String?
    public var state: String?, stage: String?, code: Int32?, keyCreates: Int?, keyLoads: Int?
    public var high: UInt64?, terminal: Bool?, phase: String?, disposition: String?, calls: Int?, factories: Int?, peak: Int?, result: Data?
    public var metadataPreserved: Bool?, registrationAbsent: Bool?
    public init(_ action: String) { self.action = action }
    public static func failure(_ error: Error) -> Self {
        var result = Self("refused")
        if case RootKeyError.os(let operation, let code) = error { result.stage = operation; result.code = code }
        else if case RootKeyError.duplicate = error { result.stage = "duplicate" }
        else if case BootstrapError.incomplete = error { result.stage = "incomplete" }
        else if case BootstrapError.busy = error { result.stage = "busy" }
        else { result.stage = "validation" }
        return result
    }
}
public enum BootstrapPipe {
    private static func exact(_ count: Int) throws -> Data {
        var result = Data()
        while result.count < count {
            guard let next = try FileHandle.standardInput.read(upToCount:min(65536,count-result.count)), !next.isEmpty else { throw HandoffError.closed }
            result.append(next)
        }
        return result
    }
    public static func read() throws -> BootstrapMessage {
        let header = try exact(5); guard header[0] <= 1 else { throw HandoffError.invalid }
        let size = header.dropFirst().reduce(UInt32(0)) { ($0<<8)|UInt32($1) }
        let limit = header[0] == 0 ? HandoffContract.control : HandoffContract.replayMessage
        guard size > 0, size <= limit else { throw HandoffError.oversized }
        let value = try HandoffContract.decode(BootstrapMessage.self,exact(Int(size)),maximum:limit)
        guard (value.frame == nil) == (header[0] == 0) else { throw HandoffError.invalid }
        if let frame = value.frame { _ = try frame.last() }; return value
    }
    public static func write(_ value: BootstrapMessage) throws {
        let bytes = try HandoffContract.encode(value,maximum:value.frame == nil ? HandoffContract.control : HandoffContract.replayMessage)
        var size = UInt32(bytes.count).bigEndian
        try FileHandle.standardOutput.write(contentsOf:Data([value.frame == nil ? 0 : 1])+withUnsafeBytes(of:&size) { Data($0) })
        try FileHandle.standardOutput.write(contentsOf:bytes)
    }
}
public enum BootstrapFixture {
    public static func base() throws -> String {
        guard let path = ProcessInfo.processInfo.environment["S85_FIXTURES"],
              path.hasPrefix("/private/tmp/reach-durable-store-bootstrap."), path.hasSuffix("/private/fixtures") else { throw BootstrapError.invalid }
        try RootKeyCodec.directory(path); try RootKeyCodec.require(RootKeyCodec.canonicalExisting(path) == path); return path
    }
    public static func pair(_ path: String) throws {
        try RootKeyCodec.require(RootKeyCodec.parent(path) == base())
        let leaf = String(path.split(separator:"/").last ?? "")
        try RootKeyCodec.require(!leaf.isEmpty && leaf.utf8.count <= 80 && leaf.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 })
    }
    public static func container(_ slot: String = "primary") throws -> String {
        try RootKeyCodec.require(["primary","decoy"].contains(slot)); return try base()+"/containers/"+slot+".keychain-db"
    }
    public static func policy(_ config: BootstrapMessage) throws -> BootstrapPolicy {
        if let policy = config.policy { return policy }
        if config.time != nil { return try .init(boot:RootKeyCodec.boot(),hostClock:"fixture-ns-v1:s85-host",clientClock:"fixture-ns-v1:s85-client") }
        return try .current()
    }
    public static func access(_ workers: [FrozenWorker]) throws -> [RootKeyRole:[FrozenWorker]] {
        let names = ["HostBootstrapWorker","ClientBootstrapWorker","KeychainWorker"]
        let privateRoot = try String(base().dropLast("fixtures".count))
        try RootKeyCodec.require(workers.count == 3 && Set(workers.map { String($0.path.split(separator:"/").last ?? "") }) == Set(names))
        for worker in workers { try RootKeyCodec.require(worker.path.hasPrefix(privateRoot)); try worker.validate() }
        let host = workers.filter { !$0.path.hasSuffix("/ClientBootstrapWorker") }
        return [.hostCatalog:host,.hostTicket:host,.clientMetadata:workers]
    }
    public static func identity(_ core: BootstrapCore, metrics: KeyAccessMetrics) -> BootstrapMessage {
        var message = BootstrapMessage("ready"); message.bootstrapID = core.identifier; message.hostID = core.hostID
        message.clientID = core.clientID; message.boot = core.policy.boot; message.keyCreates = metrics.creates; message.keyLoads = metrics.loads
        return message
    }
}
public final class KeyAccessMetrics {
    public var creates = 0, loads = 0, factories = 0
    public init() {}
    public func provider(_ core: BootstrapCore, access: [RootKeyRole:[FrozenWorker]] = [:]) throws -> any RootKeyProvider {
        // The persisted descriptor cannot authorize another OS container lookup.
        try RootKeyCodec.require(core.container == BootstrapFixture.container())
        factories += 1
        return Metered(MacKeychainProvider(container:try .openExisting(at:core.container),initialAccess:access),self)
    }
    private final class Metered: RootKeyProvider {
        let wrapped: any RootKeyProvider, metrics: KeyAccessMetrics
        init(_ wrapped: any RootKeyProvider, _ metrics: KeyAccessMetrics) { self.wrapped = wrapped; self.metrics = metrics }
        func create(_ reference: RootKeyReference,binding:String) throws -> RootKeyMaterial { metrics.creates += 1; return try wrapped.create(reference,binding:binding) }
        func load(_ reference: RootKeyReference,binding:String) throws -> RootKeyMaterial { metrics.loads += 1; return try wrapped.load(reference,binding:binding) }
    }
}
