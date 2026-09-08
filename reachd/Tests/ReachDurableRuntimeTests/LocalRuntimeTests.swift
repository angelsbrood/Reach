import Foundation
import Darwin
import XCTest
import MLX
import ReachWire
import DurableRootKeys
import DurableStoreBootstrap
import DurableSessionLifecycle
import DurableClientReceipts
import RequestPreparationContract
import WireAdapterContract
@testable import ReachDurableRuntime

final class LocalRuntimeTests:XCTestCase {
    func testGenerateAndLoadActualArtifacts() throws { try LocalDurableRuntime.withCPU {
        let path=try ArtifactFixtures.artifacts();try ArtifactFixtures.writeRequests()
        let profile=try SelectedArtifactProfile(at:path)
        XCTAssertEqual(profile.preparer.policy.descriptor.model,SelectedArtifactProfile.name)
        XCTAssertEqual(profile.preparer.policy.descriptor.weights,profile.manifest.artifacts["weights.safetensors"])
        XCTAssertEqual(profile.preparer.policy.descriptor.configuration,profile.manifest.artifacts["config.json"])
        XCTAssertEqual(profile.tokenizer.renders,0);XCTAssertTrue(profile.observations.isEmpty)
        XCTAssertLessThanOrEqual(Memory.peakMemory,128<<20)
    } }
    func testSelectedPreparationAndCombinedGrammarBinding() throws { try LocalDurableRuntime.withCPU {
        let profile=try SelectedArtifactProfile(at:ArtifactFixtures.artifacts()),policy=profile.preparer.policy
        let config=AdapterConfiguration(dialect:2,model:SelectedArtifactProfile.name,optIn:true,ready:true)
        for (name,route) in [("ordinary","ordinary"),("guided","guided"),("required","required"),("allowed","allowed"),("combined","allowed")] {
            let request=try ArtifactFixtures.request(name)
            XCTAssertEqual(try policy.route(request),route)
            let binding=try profile.preparer.prepare(request,reference:.init(session:.init(modelID:config.model,profile:config.profile,sessionID:"session"),generationID:"generation",operationID:"operation"),configuration:config)
            try profile.preparer.validateStored(binding,configuration:config)
            if name=="combined",case .allowed(let lane)=binding.lane {
                XCTAssertNotNil(lane.responseSchema);XCTAssertEqual(try PreparationEncoding.encode(lane.probeModel),try PreparationEncoding.encode(lane.guidedModel))
                XCTAssertFalse(profile.tokenizer.lastRendered.contains("Retained local answer."))
            }
        }
        XCTAssertTrue(profile.observations.isEmpty)
    } }
    func testUnsafeAndReusedRolesRefuse() throws {
        let path=try ArtifactFixtures.base()+"/unsafe-"+UUID().uuidString.lowercased()
        try LocalFiles.createDirectory(path);defer { try? FileManager.default.removeItem(atPath:path) }
        XCTAssertThrowsError(try LocalFiles.createDirectory(path))
        XCTAssertEqual(chmod(path,0o755),0);XCTAssertThrowsError(try LocalFiles.directory(path));XCTAssertEqual(chmod(path,0o700),0)
        try LocalFiles.writeNew(Data("value".utf8),to:path+"/file")
        XCTAssertEqual(chmod(path+"/file",0o644),0);XCTAssertThrowsError(try LocalFiles.read(path+"/file",maximum:20))
        XCTAssertEqual(symlink(path+"/file",path+"/link"),0);XCTAssertThrowsError(try LocalFiles.read(path+"/link",maximum:20))
    }
    func testDriftedArtifactsAndUnsupportedConfigurationRefuse() throws { try LocalDurableRuntime.withCPU {
        let source=try ArtifactFixtures.artifacts(),path=try ArtifactFixtures.base()+"/drift-"+UUID().uuidString.lowercased()
        try FileManager.default.copyItem(atPath:source,toPath:path);defer { try? FileManager.default.removeItem(atPath:path) }
        try Data("changed".utf8).write(to:URL(fileURLWithPath:path+"/template.txt"));XCTAssertThrowsError(try SelectedArtifactProfile(at:path))
        try FileManager.default.removeItem(atPath:path);try FileManager.default.copyItem(atPath:source,toPath:path)
        var config=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:path+"/config.json"))) as! [String:Any];config["hidden_size"]=32
        let bytes=try JSONSerialization.data(withJSONObject:config,options:[.sortedKeys,.withoutEscapingSlashes]);try bytes.write(to:URL(fileURLWithPath:path+"/config.json"))
        let original=try JSONDecoder().decode(ArtifactManifest.self,from:Data(contentsOf:URL(fileURLWithPath:path+"/profile.json")));var hashes=original.artifacts;hashes["config.json"]=PreparationEncoding.hash(bytes)
        try ArtifactFixtures.encode(ArtifactManifest(version:original.version,profile:original.profile,artifacts:hashes)).write(to:URL(fileURLWithPath:path+"/profile.json"))
        XCTAssertThrowsError(try SelectedArtifactProfile(at:path))
    } }
    func testUntrustedControlFieldsAndDisabledConfigurationRefuse() throws {
        let path=try ArtifactFixtures.base()+"/untrusted-"+UUID().uuidString.lowercased()+".json";defer { try? FileManager.default.removeItem(atPath:path) }
        var value=try JSONSerialization.jsonObject(with:ArtifactFixtures.encode(ArtifactFixtures.request("ordinary"))) as! [String:Any]
        value["caller"]=["principal":"replacement"];value["allowed"]=true;value["ready"]=true;value["time"]=1
        try LocalFiles.writeNew(JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]),to:path)
        XCTAssertThrowsError(try LocalDurableRuntime.request(from:path))
        XCTAssertThrowsError(try AdapterConfiguration(dialect:2,model:SelectedArtifactProfile.name,optIn:false,ready:false).validate())
    }
    func testCurrentSystemAuthorityAndRealWireCodec() throws {
        let invocation=try LocalInvocation(),host=SystemLifecycleClock(),client=SystemClientClock(),policy=try BootstrapPolicy.current()
        XCTAssertEqual(invocation.principal,"uid:"+String(getuid()));XCTAssertEqual(invocation.app,"reach.durable-local.v1")
        XCTAssertEqual(host.policy,client.policy);XCTAssertEqual(policy.hostClock,host.policy);XCTAssertGreaterThan(try host.now(),0)
        var invalid=policy;invalid.boot=UUID().uuidString.lowercased();XCTAssertThrowsError(try invalid.validate())
        let message=DurableMessage.open(.init(.init(requestID:"current-wire",modelID:SelectedArtifactProfile.name,profile:DurableWire.profile,durable:true)))
        let bytes=try message.encode(version:2);var frames=AdapterFrames();var decoded:[DurableMessage]=[]
        for byte in bytes { decoded+=try frames.receive(Data([byte]),version:2) }
        XCTAssertEqual(decoded.count,1);XCTAssertEqual(try decoded[0].encode(version:2),bytes)
    }
}
