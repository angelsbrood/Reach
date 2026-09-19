import Foundation
import Darwin
import ClockPolicy
import WitnessAccess

struct Options {
    let mode:String,values:[String:String]
    init() throws {
        let args=Array(CommandLine.arguments.dropFirst());guard let mode=args.first else {throw AccessError.selection}
        self.mode=mode;var values:[String:String]=[:];var i=1
        while i<args.count {
            guard args[i].hasPrefix("--"),i+1<args.count,values[args[i]]==nil else {throw AccessError.selection}
            values[args[i]]=args[i+1];i+=2
        }
        self.values=values
    }
    func value(_ name:String) throws -> String {guard let v=values["--"+name] else {throw AccessError.selection};return v}
    func number(_ name:String,default fallback:UInt64=0) throws -> UInt64 {
        guard let text=values["--"+name] else {return fallback};guard let n=UInt64(text) else {throw AccessError.selection};return n
    }
    func allow(_ names:[String]) throws {guard Set(values.keys).isSubset(of:Set(names.map{"--"+$0})) else {throw AccessError.selection}}
}
func emit<T:Encodable>(_ value:T) throws {
    try FileHandle.standardOutput.write(contentsOf:Wire.encode(value)+Data([10]))
}
func line() throws -> Data? {
    var bytes=Data()
    while true {
        let next=try FileHandle.standardInput.read(upToCount:1) ?? Data()
        if next.isEmpty {guard bytes.isEmpty else {throw AccessError.frame};return nil}
        if next[0]==10 {return bytes}
        guard bytes.count<Wire.maximumBytes else {throw AccessError.frame};bytes.append(next)
    }
}
func service(_ options:Options) throws -> Never {
    try options.allow(["endpoint","selection","descriptor","qualification-delay-index","qualification-delay-ms"])
    let index=try options.number("qualification-delay-index"),delay=try options.number("qualification-delay-ms")
    guard (index==0 && delay==0) || ((1...128).contains(index) && (1...4500).contains(delay)) else {throw AccessError.selection}
    let endpoint=try UnixEndpoint(path:options.value("endpoint"),uid:getuid())
    let selections=try Wire.decode([PairSelection].self,PublicFile.read(options.value("selection")))
    let service=try WitnessService(endpoint:endpoint,selections:selections)
    let bytes=try Wire.encode(service.descriptor);try PublicFile.writeNew(bytes,to:options.value("descriptor"))
    struct Ready:Encodable {let stage="ready",pid:Int32,descriptorSHA256:String,endpoint:String}
    try emit(Ready(pid:getpid(),descriptorSHA256:Wire.digest(bytes),endpoint:endpoint.path))
    var replies:UInt64=0
    return try service.run { response in
        replies+=1
        if replies==index {
            struct Held:Encodable {let stage="reply-held",response:Data,delayMilliseconds:UInt64}
            try emit(Held(response:response,delayMilliseconds:delay))
            usleep(useconds_t(delay*1000))
        }
    }
}
struct ReceiverCommand:Codable {let op:String}
struct ReceiverReport:Encodable {
    let stage:String,op:String,lost:Bool
    var evaluation:Evaluation?,request:Data?,response:Data?,sent:Sample?,signatureControl:Sample?,error:String?
}
func receiver(_ options:Options) throws {
    try options.allow(["descriptor","digest","subject"])
    let d=try Descriptor.load(path:options.value("descriptor"),expectedSHA256:options.value("digest"))
    let owner=try AccessOwner(descriptor:d,subject:options.value("subject"))
    struct Ready:Encodable {let stage="receiver-ready",pid:Int32,selectionSHA256:String,originals:Originals}
    try emit(Ready(pid:getpid(),selectionSHA256:options.value("digest"),originals:owner.originals))
    var current:AccessAction?,previous:AccessAction?
    while let bytes=try line() {
        let command=try Wire.decode(ReceiverCommand.self,bytes)
        do {
            var selected:AccessAction?,evaluation:Evaluation?
            switch command.op {
            case "exchange":current=try owner.exchange();selected=current;evaluation=try owner.evaluate(current!)
            case "evaluate":guard let current else {throw Refusal.missing};selected=current;evaluation=try owner.evaluate(current)
            case "evaluate-previous":guard let previous else {throw Refusal.missing};selected=previous;evaluation=try owner.evaluate(previous)
            case "finish":guard let action=current else {throw Refusal.missing};try owner.finish(action);previous=action;current=nil
            default:throw AccessError.selection
            }
            let signature=try selected.map {try Verifier.signatureOnlyControl($0.response,originals:owner.originals)}
            try emit(ReceiverReport(stage:evaluation.map{$0.outcome == .eligible ? "eligible" : "expired"} ?? "finished",op:command.op,lost:owner.lost,
                evaluation:evaluation,request:selected?.request,response:selected?.response,sent:selected?.sent,signatureControl:signature))
        } catch {
            try emit(ReceiverReport(stage:"refused",op:command.op,lost:owner.lost,request:owner.attemptedRequest,sent:owner.attemptedSend,error:String(describing:error)))
        }
    }
}

@main struct Main {
    static func main() {
        do {
            let options=try Options()
            switch options.mode {
            case "service":try service(options)
            case "receiver":try receiver(options)
            case "probe-server","probe-client","network-probe":try probe(options)
            default:throw AccessError.selection
            }
        } catch {
            try? FileHandle.standardError.write(contentsOf:Data("REFUSE: \(error)\n".utf8));exit(1)
        }
    }
}
