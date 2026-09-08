import Foundation
import ReachWire
import DurableRootKeys
import RequestPreparationContract

public enum IndependentContract {
    public static let revision = "s95-independent-bootstrap-v1"
    public static let application = "reach.durable-independent.loopback.v1"
}
/// Public input to provisioning, authored alongside the selected artifacts.
public struct IndependentPublicModel: Codable {
    public let descriptor: RequestPreparationContract.ModelDescriptor, artifactDigest: String
    public init(descriptor: RequestPreparationContract.ModelDescriptor, artifactDigest: String) {
        self.descriptor=descriptor; self.artifactDigest=artifactDigest
    }
}
/// Canonical, bounded public agreement. It cannot carry paths or private material.
public struct IndependentPairAgreement: Codable {
    public let version: Int, pair: String, hostID: String, clientID: String
    public let profile: String, endpoint: String, port: UInt16, retentionCap: UInt64
    public let model: IndependentPublicModel
    let pins: TransportPins
    public init(model: IndependentPublicModel, certificates: TransportTLSProvision, port: UInt16, retentionCap: UInt64 = 86_400_000_000_000) throws {
        version=1; pair=UUID().uuidString.lowercased(); hostID=UUID().uuidString.lowercased(); clientID=UUID().uuidString.lowercased()
        profile=DurableWire.independentProfile; endpoint="127.0.0.1"; self.port=port; self.retentionCap=retentionCap
        self.model=model; pins=try TransportPins(certificates); try validate()
    }
    public func validate() throws {
        try model.descriptor.validate(); try pins.validate()
        guard version==1, [pair,hostID,clientID].allSatisfy(RootKeyCodec.uuid), Set([pair,hostID,clientID]).count==3,
              profile==DurableWire.independentProfile, endpoint=="127.0.0.1", (49152...65535).contains(port),
              retentionCap>0, retentionCap<=86_400_000_000_000,
              model.descriptor.model==TransportContract.model, model.descriptor.revision==ModelDescriptor.schemaToolRevision,
              PreparationEncoding.isDigest(model.artifactDigest) else { throw TransportRuntimeError.invalid }
        _=try RootKeyCodec.encode(self,limit:64<<10)
    }
    public var digest: String { get throws { try validate(); return try PreparationEncoding.digest(self) } }
    static func load(_ path: String) throws -> Self {
        let result=try RootKeyCodec.decode(Self.self,LocalFiles.read(path,maximum:64<<10),limit:64<<10)
        try result.validate(); return result
    }
    /// Issuer receives public model metadata only; no native model is materialized.
    public static func provision(publicModel: String, directory: String, port: UInt16, retentionCap: UInt64,
        issuer: (String) throws -> TransportTLSProvision) throws {
        let model=try RootKeyCodec.decode(IndependentPublicModel.self,LocalFiles.read(publicModel,maximum:64<<10),limit:64<<10)
        try LocalFiles.createDirectory(directory)
        do {
            for role in ["host","client"] { try LocalFiles.createDirectory(directory+"/"+role) }
            let agreement=try Self(model:model,certificates:issuer(directory),port:port,retentionCap:retentionCap)
            let data=try RootKeyCodec.encode(agreement,limit:64<<10)
            for role in ["host","client"] { try LocalFiles.writeNew(data,to:directory+"/"+role+"/agreement.json") }
        } catch { try FileManager.default.removeItem(atPath:directory); throw error }
    }
}
