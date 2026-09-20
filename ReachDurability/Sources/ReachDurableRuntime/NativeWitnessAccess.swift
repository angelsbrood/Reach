import Foundation
import ClockPolicy
import WitnessAccess
import RecoveryAuthorityContract
import ResumableMLXProvider

/// One frozen launch selection. It owns no Verifier and cannot replace originals.
public struct NativeWitnessSelection {
    private let descriptor:Descriptor
    public init(path:String,expectedSHA256:String) throws {
        descriptor=try Descriptor.load(path:path,expectedSHA256:expectedSHA256)
    }
    public static func load(path:String?,expectedSHA256:String?) throws -> Self? {
        if path==nil && expectedSHA256==nil {return nil}
        guard let path,let expectedSHA256 else {throw AuthorityError.invalid}
        return try Self(path:path,expectedSHA256:expectedSHA256)
    }
    public func originals(subject:String) throws -> Data {try AuthorityCodec.encode(descriptor.select(subject:subject))}
    func requireArtifact(fixture:AllowedRecoveryQualificationFactory?) throws {
        guard fixture==nil else {throw AuthorityError.scope}
    }
    func validate(originals:Originals,binding:ProviderBinding,fixture:AllowedRecoveryQualificationFactory?) throws {
        try requireArtifact(fixture:fixture);try NativeRecoveryRuntime.validateFixture(binding)
        guard [.ordinary,.guided,.required].contains(binding.lane.route) else {throw AuthorityError.scope}
        let subject=try originals.records().host.subject
        guard try descriptor.select(subject:subject)==originals else {throw AuthorityError.scope}
    }
    @discardableResult func validate(_ provision:AuthorityProvision,fixture:AllowedRecoveryQualificationFactory?) throws -> ProviderBinding {
        try requireArtifact(fixture:fixture);try provision.validate()
        guard provision.native,let execution=provision.execution else {throw AuthorityError.scope}
        let binding=try AuthorityCodec.decode(ProviderBinding.self,execution.provider)
        try validate(originals:provision.originals,binding:binding,fixture:fixture)
        return binding
    }
    func requireSupportedOptions(requiredBoundary:String,allowedBoundary:String,fault:String,fixture:AllowedRecoveryQualificationFactory?) throws {
        try requireArtifact(fixture:fixture)
        guard ["none","generating","ready","emitted"].contains(requiredBoundary),allowedBoundary=="none",fault != "after-next-pass-native" else {throw AuthorityError.scope}
    }
    func exchange(_ action:GenerationAuthorityAction,clock:any PolicyClock,
                  transport:(Data,UnixEndpoint,IODeadline)throws->Data = {try SocketIO.exchange($0,endpoint:$1,deadline:$2)},
                  report:(NativeSocketReport)throws->Void = {try RecoveryAuthorityChannel.write($0)}) throws {
        var response:Data?,observed:Sample?
        do {
            let deadline=try IODeadline(start:action.clockAction.sent,clock:clock)
            try validate(action.scope.provision,fixture:nil);try deadline.check()
            let endpoint=try UnixEndpoint(path:descriptor.endpoint,uid:descriptor.uid)
            response=try transport(action.request,endpoint,deadline);try deadline.check()
            try action.receive(response!);try deadline.check()
            observed=try clock.sample();try deadline.check()
        } catch {
            action.observeWitnessLoss()
            // Diagnostic output cannot rescue an exchange or supply a certificate.
            try? report(.init(operation:action.operation,request:action.request,sent:action.clockAction.sent,
                              certificate:response,afterReceive:observed,accepted:false))
            throw error
        }
        try report(.init(operation:action.operation,request:action.request,sent:action.clockAction.sent,
                         certificate:response,afterReceive:observed,accepted:true))
    }
}

/// These are transport/verification observations, not a prospective-use decision.
/// afterReceive is a separate observation and is never represented as Verifier r1.
struct NativeSocketReport:Encodable {
    let stage="socket-authority"
    let operation:GenerationOperation,request:Data,sent:Sample,certificate:Data?,afterReceive:Sample?,accepted:Bool
}
enum NativeWitnessAccess {
    static func exchange(_ action:GenerationAuthorityAction,selection:NativeWitnessSelection?,clock:any PolicyClock) throws {
        if let selection {try selection.exchange(action,clock:clock)} else {try RecoveryAuthorityChannel.exchange(action)}
    }
    static func continueAction(_ stage:String,action:GenerationAuthorityAction,selection:NativeWitnessSelection?) throws {
        guard stage=="continue" || (selection==nil && stage=="observe") else {throw AuthorityError.state}
        if stage=="observe" {try RecoveryAuthorityChannel.observe(action)}
        try action.check()
    }
}

extension NativeRecoveryRoots {
    /// Bounded metadata only: reject socket selection/route before leases, secrets,
    /// Keychain access, native construction or executable storage operations.
    static func validateWitness(_ witness:NativeWitnessSelection?,hostReceipt:String,hostDigest:String,
                                clientReceipt:String,clientDigest:String,fixture:AllowedRecoveryQualificationFactory?,stopWithPendingGuided:Bool=false,
                                requiredBoundary:String="none",duplicateExact:Bool=false,original:Bool=false,stopAfterCalls:Int=0) throws {
        guard let witness else {return}
        try witness.requireArtifact(fixture:fixture)
        let h=try receipt(hostReceipt,expectedDigest:hostDigest).ready.core
        let c=try receipt(clientReceipt,expectedDigest:clientDigest).ready.core
        guard h.role == .host,c.role == .client,let provision=h.authority,provision==c.authority else {throw AuthorityError.scope}
        let binding=try witness.validate(provision,fixture:fixture)
        // Join cut intent to the authenticated original metadata before leases or keys.
        guard !stopWithPendingGuided || binding.lane.route == .guided,
              ["none","generating","ready","emitted"].contains(requiredBoundary),
              requiredBoundary=="none" || binding.lane.route == .required && !stopWithPendingGuided && stopAfterCalls==0,
              !duplicateExact || binding.lane.route == .required && !original && requiredBoundary=="none" && !stopWithPendingGuided && stopAfterCalls==0 else {throw AuthorityError.scope}
        // Terminal eligibility comes from the encrypted store before its factory,
        // not from receipt metadata. This only authenticates compatible intent.
    }
}
