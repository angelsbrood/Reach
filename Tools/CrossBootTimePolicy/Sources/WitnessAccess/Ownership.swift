import Foundation
import ClockPolicy

/// One serial in-memory issuer. Closing a client does not end this lifetime.
public final class WitnessService {
    private let witness:Witness,clock:any PolicyClock,listener:SocketFD,endpoint:UnixEndpoint
    private var hasRun=false
    public let descriptor:Descriptor
    public convenience init(endpoint:UnixEndpoint,selections:[PairSelection],clock:any PolicyClock=SystemClock()) throws {
        try self.init(endpoint:endpoint,selections:selections,clock:clock,listen:{try endpoint.listen()})
    }
    // Internal socket factories permit serial, network-closed service-loop tests.
    init(endpoint:UnixEndpoint,selections:[PairSelection],clock:any PolicyClock,listen:()throws->SocketFD) throws {
        _=try Provisioning.selections(selections);try endpoint.validateRoot(empty:true)
        self.clock=clock;self.endpoint=endpoint
        let witness=try Witness(clock:clock);self.witness=witness
        let pairs=try Provisioning.issue(selections,pin:witness.identity,register:{try witness.register(subject:$0,role:$1,cap:$2)})
        descriptor=try Descriptor(endpoint:endpoint.path,uid:endpoint.uid,identity:witness.identity,pairs:pairs)
        listener=try listen()
    }
    /// The optional local observer is for explicit qualification orchestration.
    /// It receives an already signed reply; it cannot change its body or originals.
    public func run(beforeReply:((Data)throws->Void)?=nil) throws -> Never {
        try run(accept:{try self.endpoint.accept(self.listener)},beforeReply:beforeReply)
    }
    func run(accept:()throws->SocketFD?,beforeReply:((Data)throws->Void)?=nil) throws -> Never {
        guard !hasRun else {throw Refusal.invalidated};hasRun=true
        defer {listener.close()} // A failed run ends readiness even if the caller retains this object.
        while true {
            _=try witness.observe() // Fatal clock failure also ends idle readiness.
            guard let fd=try accept() else {continue}
            defer {fd.close()}
            let deadline=try IODeadline(start:clock.sample(),clock:clock)
            do {
                try deadline.check();try endpoint.peer(fd)
                let request=try SocketIO.readFrame(from:fd,deadline:deadline)
                try SocketIO.expectEOF(fd,deadline:deadline)
                let response=try witness.respond(to:request)
                try beforeReply?(response);try deadline.check()
                try SocketIO.writeFrame(response,to:fd,deadline:deadline)
            } catch {
                if let fault=deadline.clockFailure {throw fault}
                _=try witness.observe() // Malformed clients cannot reset the issuer; clock faults are fatal.
                struct Rejected:Codable {let refusal:String}
                do {
                    try SocketIO.writeFrame(Wire.encode(Rejected(refusal:String(describing:error))),to:fd,deadline:deadline)
                } catch {
                    if let fault=deadline.clockFailure {throw fault}
                }
            }
        }
    }
}

public struct AccessAction {
    let action:Action
    public let response:Data
    public var request:Data {action.request}
    public var sent:Sample {action.sent}
}

/// A separately launched receiver gets a new owner; this owner is never revived.
public final class AccessOwner {
    private let verifier:Verifier,clock:any PolicyClock,endpoint:UnixEndpoint
    public let originals:Originals
    public private(set) var lost=false
    public private(set) var attemptedRequest:Data?,attemptedSend:Sample?
    public init(descriptor:Descriptor,subject:String,clock:any PolicyClock=SystemClock()) throws {
        try descriptor.validate();originals=try descriptor.select(subject:subject)
        self.clock=clock;endpoint=try UnixEndpoint(path:descriptor.endpoint,uid:descriptor.uid)
        verifier=try Verifier(originals:originals,clock:clock)
    }
    public func exchange(purpose:Purpose = .candidate) throws -> AccessAction {
        try exchange(purpose:purpose,transport:{try SocketIO.exchange($0,endpoint:self.endpoint,deadline:$1)})
    }
    func exchange(purpose:Purpose = .candidate,transport:(Data,IODeadline)throws->Data) throws -> AccessAction {
        let action=try verifier.begin(purpose:purpose) // r0 precedes connect and every transport operation.
        attemptedRequest=action.request;attemptedSend=action.sent
        do {
            let deadline=try IODeadline(start:action.sent,clock:clock)
            let response=try transport(action.request,deadline);try deadline.check()
            try verifier.receive(response,for:action);try deadline.check() // Include parsing/signature work.
            return AccessAction(action:action,response:response)
        } catch {observeWitnessLoss();throw error}
    }
    public func evaluate(_ action:AccessAction) throws -> Evaluation {try verifier.evaluate(action.action)}
    public func finish(_ action:AccessAction) throws {try verifier.finish(action.action)}
    public func observeWitnessLoss() {lost=true;verifier.observeWitnessLoss()}
}
