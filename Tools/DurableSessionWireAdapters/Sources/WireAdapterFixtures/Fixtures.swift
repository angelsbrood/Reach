import Foundation
import MLX
import LifecycleFixtures
import ResumableMLXProvider
import WireAdapterContract
import ReachWire

/// Host-side fixture preparer only. Client/Keychain targets never depend on it.
public final class WireNativeFixture {
    public private(set) var setup:PFSetup?
    public private(set) var preparations=0
    public init() {}
    public func binding(_ request:WireGenerationRequest,reference:DurableGenerationReference,configuration:AdapterConfiguration) throws -> ProviderBinding {
        let route=try AdapterContract.route(request)
        var prepared=try Device.withDefaultDevice(Device(.cpu)) { try PFSetup(route) }
        prepared.binding.requestID=try AdapterContract.requestBinding(request,configuration:configuration,route:route)
        prepared.binding.operationID=reference.operationID
        setup=prepared;preparations+=1;return prepared.binding
    }
    public func runtime(_ stored:ProviderBinding,configuration:AdapterConfiguration) throws -> ProviderRuntime {
        let route=stored.lane.route.rawValue,request=try AdapterContract.request(route)
        guard stored.requestID == (try AdapterContract.requestBinding(request,configuration:configuration,route:route)) else { throw AdapterError.invalid }
        if let setup,try AdapterContract.same(setup.binding,stored) { return setup.runtime }
        var restored=try Device.withDefaultDevice(Device(.cpu)) { try PFSetup(route) }
        restored.binding.requestID=stored.requestID;restored.binding.operationID=stored.operationID
        guard try AdapterContract.same(restored.binding,stored) else { throw AdapterError.invalid }
        setup=restored;preparations+=1;return restored.runtime
    }
    public var calls:Int { setup?.calls ?? 0 }
    public var prefills:Int { setup?.prefills ?? 0 }
    public var factories:Int { setup?.factories ?? 0 }
}
