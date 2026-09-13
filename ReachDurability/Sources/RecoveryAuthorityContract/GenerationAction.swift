import Foundation
import Darwin
import ClockPolicy

/// The same predeclared exact prepared bytes are frozen before either independent
/// original admission. This declaration never grants storage or time authority.
public struct AuthorityExecution: Codable, Equatable {
    public let version: Int, operation: String, provider: Data
    public init(operation: String, provider: Data) throws {
        version=1; self.operation=operation; self.provider=provider; try validate()
    }
    public func validate() throws {
        try AuthorityCodec.require(version == 1 && !operation.isEmpty && operation.utf8.count <= 256 &&
            !provider.isEmpty && provider.count <= 16<<10)
        _=try AuthorityCodec.encode(self)
    }
}
public enum GenerationOperation: String, Codable {
    case admitHost, acceptClient, reopen, prepare, advance, delivery, terminalReplay
}
/// Opaque, unencoded identity of the owner which opened a live resource.
/// Matching this binding checks ownership and operation only; the resource must
/// still perform its current admission/publication check for fresh eligibility.
public struct GenerationAuthorityBinding {
    private let owner: GenerationAuthorityOwner
    fileprivate init(owner: GenerationAuthorityOwner) { self.owner=owner }
    public func validate(_ action: GenerationAuthorityAction, permitting operations: [GenerationOperation]) throws {
        guard owner === action.owner, operations.contains(action.operation) else { throw AuthorityError.scope }
    }
}
/// One receiver incarnation owns the verifier, its count and its latched loss.
/// Finishing an action releases a pending challenge; it never replaces Verifier.
public final class GenerationAuthorityOwner {
    public let scope: AuthorityScope
    private let verifier: Verifier, process=getpid()
    private let validateOwnedRoots: () throws -> Void
    private weak var current: GenerationAuthorityAction?
    private var admission: String?
    public private(set) var actionCount=0
    public init(scope: AuthorityScope, clock: any PolicyClock, validateOwnedRoots: @escaping () throws -> Void = {}) throws {
        try scope.validate(); guard scope.provision.native else { throw AuthorityError.scope }
        self.scope=scope; self.validateOwnedRoots=validateOwnedRoots; verifier=try Verifier(originals:scope.provision.originals,clock:clock)
    }
    public func begin(_ operation: GenerationOperation) throws -> GenerationAuthorityAction {
        guard process == getpid(), current == nil else { throw AuthorityError.scope }
        let handle=try verifier.begin(purpose:.blocking)
        let action=GenerationAuthorityAction(owner:self,operation:operation,clockAction:handle)
        current=action; actionCount += 1; return action
    }
    public func observeWitnessLoss() { verifier.observeWitnessLoss() }
    public func observeWitnessIdentity(_ identity: Identity) throws { try verifier.observeWitnessIdentity(identity) }
    fileprivate func local(_ action: GenerationAuthorityAction) throws {
        guard process == getpid(), current === action, !action.finished else { throw AuthorityError.scope }
    }
    fileprivate func receive(_ data: Data, action: GenerationAuthorityAction) throws {
        try local(action); try verifier.receive(data,for:action.clockAction)
    }
    @discardableResult fileprivate func check(_ action: GenerationAuthorityAction) throws -> Evaluation {
        try local(action); let e=try verifier.evaluate(action.clockAction)
        guard e.outcome == .eligible else { throw AuthorityError.ineligible }
        try validateOwnedRoots()
        let final=try verifier.evaluate(action.clockAction)
        guard final.outcome == .eligible else { throw AuthorityError.ineligible }; return final
    }
    fileprivate func bind(_ a: AuthorityAdmission, action: GenerationAuthorityAction) throws {
        try check(action); guard a.scope == scope else { throw AuthorityError.scope }
        let digest=try a.digest
        guard admission == nil || admission == digest else { throw AuthorityError.scope }; admission=digest
    }
    fileprivate func publication(_ a: AuthorityAdmission, action: GenerationAuthorityAction) throws -> Evaluation {
        guard a.scope == scope, admission == (try a.digest) else { throw AuthorityError.scope }; return try check(action)
    }
    fileprivate func finish(_ action: GenerationAuthorityAction) throws {
        try local(action); try verifier.finish(action.clockAction); action.finished=true; current=nil
    }
    /// Long-lived key owners call this around blocking work, including relock.
    /// An ended, absent, stale or invalidated action cannot supply eligibility.
    @discardableResult public func checkCurrent() throws -> Evaluation {
        guard let current else { throw AuthorityError.scope }; return try check(current)
    }
}
public final class GenerationAuthorityAction {
    fileprivate let owner: GenerationAuthorityOwner
    public var scope: AuthorityScope { owner.scope }
    public let operation: GenerationOperation, clockAction: ClockPolicy.Action
    fileprivate var finished=false
    fileprivate init(owner: GenerationAuthorityOwner, operation: GenerationOperation, clockAction: ClockPolicy.Action) {
        self.owner=owner; self.operation=operation; self.clockAction=clockAction
    }
    public var request: Data { clockAction.request }
    public func bindResource() throws -> GenerationAuthorityBinding {
        try owner.local(self); return .init(owner:owner)
    }
    public func receive(_ data: Data) throws { try owner.receive(data,action:self) }
    public func observeWitnessLoss() { owner.observeWitnessLoss() }
    public func observeWitnessIdentity(_ identity: Identity) throws { try owner.observeWitnessIdentity(identity) }
    @discardableResult public func check(scope: AuthorityScope, operation: GenerationOperation) throws -> Evaluation {
        guard self.scope == scope, self.operation == operation else { throw AuthorityError.scope }; return try owner.check(self)
    }
    @discardableResult public func check() throws -> Evaluation { try owner.check(self) }
    public func bindAuthenticated(_ admission: AuthorityAdmission) throws { try owner.bind(admission,action:self) }
    @discardableResult public func publication(_ admission: AuthorityAdmission) throws -> Evaluation { try owner.publication(admission,action:self) }
    public func finish() throws { try owner.finish(self) }
}
