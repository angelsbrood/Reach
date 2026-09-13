import Foundation
import Darwin
import ClockPolicy

public enum AuthorityOperation: String, Codable { case admitHost, acceptClient, authenticateHost, authenticateClient }
/// Serial local action only. No Codable, persisted evaluation, clock conformance,
/// native attachment, or receipt-time reset exists in this API.
public final class RecoveryAuthorityAction {
    public let scope: AuthorityScope, operation: AuthorityOperation
    public let clockAction: ClockPolicy.Action
    private let verifier: Verifier, process = getpid()
    private var admissionDigest: String?, finished = false
    public init(scope: AuthorityScope, operation: AuthorityOperation, clock: any PolicyClock) throws {
        try scope.validate(); self.scope=scope; self.operation=operation
        verifier=try Verifier(originals:scope.provision.originals,clock:clock)
        clockAction=try verifier.begin(purpose:.blocking)
    }
    public var request: Data { clockAction.request }
    public func receive(_ response: Data) throws { try local(); try verifier.receive(response,for:clockAction) }
    private func local() throws { guard process == getpid(), !finished else { throw AuthorityError.scope } }
    public func observeWitnessLoss() { verifier.observeWitnessLoss() }
    public func observeWitnessIdentity(_ identity: Identity) throws { try verifier.observeWitnessIdentity(identity) }
    @discardableResult public func check(scope: AuthorityScope, operation: AuthorityOperation) throws -> Evaluation {
        try local()
        guard scope == self.scope, operation == self.operation else { throw AuthorityError.scope }
        let result = try verifier.evaluate(clockAction)
        guard result.outcome == .eligible else { throw AuthorityError.ineligible }
        return result
    }
    public func bindAuthenticated(_ admission: AuthorityAdmission) throws {
        _ = try check(scope:admission.scope,operation:operation)
        let digest=try admission.digest
        guard admissionDigest == nil || admissionDigest == digest else { throw AuthorityError.scope }
        admissionDigest=digest
    }
    @discardableResult public func publication(_ admission: AuthorityAdmission) throws -> Evaluation {
        guard admissionDigest == (try admission.digest) else { throw AuthorityError.scope }
        return try check(scope:admission.scope,operation:operation)
    }
    public func confirmPublicationDigest(_ digest: String, scope: String, operation: AuthorityOperation) throws {
        try local()
        guard admissionDigest == digest, scope == (try self.scope.digest), operation == self.operation else { throw AuthorityError.scope }
    }
    public func finish() throws { try local(); try verifier.finish(clockAction); finished=true }
}
