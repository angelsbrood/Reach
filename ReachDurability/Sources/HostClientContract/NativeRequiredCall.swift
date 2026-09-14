import Foundation
import ReachWire

/// Model-free projection of exact original signed provider bytes. It authenticates
/// identity and schema provenance, not argument-schema acceptance or effects.
public struct NativeRequiredCall {
    public let request:String, operation:String, entryID:String, callID:String, name:String, schemaJSON:String
    public let inputTokens:Int, maximumTokens:Int
    static func project(_ provider:Data,digest:String,request:String,operation:String,route:String) throws -> NativeRequiredCall? {
        guard provider.count<=16<<10,HandoffContract.hash(provider)==digest,
              let root=try JSONSerialization.jsonObject(with:provider) as? [String:Any],
              root["version"] as? Int == 1,root["policy"] as? String == "S80-exact-candidate-ack;json-sorted-v1",
              root["requestID"] as? String == request,root["operationID"] as? String == operation,
              let lane=root["lane"] as? [String:Any],Set(lane.keys)==Set([route]),
              ["ordinary","guided","required"].contains(route) else { throw HandoffError.invalid }
        guard route == "required" else { return nil }
        guard let selected=lane[route] as? [String:Any],Set(selected.keys)==Set(["_0","tokens"]),
              let b=selected["_0"] as? [String:Any],b["version"] as? Int == 1,b["route"] as? String == route,
              b["policy"] as? String == "stable-ids;accepted-eos;whole-batch;ready-wins-v1",
              b["requestIdentity"] as? String == request,
              let entry=b["entryID"] as? String,let call=b["callID"] as? String,
              [entry,call].allSatisfy({!$0.isEmpty && $0.utf8.count<=256}),
              let tools=b["tools"] as? [[String:Any]],tools.count==1,
              let name=tools[0]["name"] as? String,!name.isEmpty,name.utf8.count<=1024,
              let source=tools[0]["schemaJSON"] as? String,source.utf8.count<=65536,
              let specification=b["specification"] as? [String:Any],specification["kind"] as? String == "structural-tag",
              let tokens=selected["tokens"] as? [Int],(1...512).contains(tokens.count),
              let options=b["options"] as? [String:Any],let model=options["model"] as? [String:Any],
              model["prefillStepSize"] as? Int == 256,let maximum=model["maximumTokens"] as? Int,(1...48).contains(maximum)
        else { throw HandoffError.invalid }
        let bytes=Data(source.utf8),schema=try JSONDecoder().decode(WireGenerationSchema.self,from:bytes)
        guard try HandoffContract.encode(schema)==bytes else { throw HandoffError.invalid }
        let nameJSON=String(decoding:try HandoffContract.encode(name),as:UTF8.self)
        let structural:[String:Any]=["type":"structural_tag","format":["type":"or","elements":[
            ["type":"tag","begin":"{\"name\":\(nameJSON),\"arguments\":","content":["type":"json_schema","json_schema":try JSONSerialization.jsonObject(with:bytes)],"end":["}"]]]]]
        let exact=try JSONSerialization.data(withJSONObject:structural,options:[.sortedKeys,.withoutEscapingSlashes])
        guard specification["source"] as? String == String(decoding:exact,as:UTF8.self) else { throw HandoffError.invalid }
        return NativeRequiredCall(request:request,operation:operation,entryID:entry,callID:call,name:name,schemaJSON:source,inputTokens:tokens.count,maximumTokens:maximum)
    }
    func wholeCall(_ events:[WireEvent]) throws -> Data {
        guard events.count==3,
              case .toolCallAppendArguments(let entry,let id,let tool,let arguments,let count)=events[0],
              entry==entryID,id==callID,tool==name,count==1,
              case .usage(let input,let output)=events[1],input==inputTokens,(1..<maximumTokens).contains(output),
              case .finished(.complete)=events[2],arguments.utf8.count<=256<<10,
              let object=try JSONSerialization.jsonObject(with:Data(arguments.utf8)) as? [String:Any]
        else { throw HandoffError.invalid }
        let canonical=try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes])
        guard canonical==Data(arguments.utf8) else { throw HandoffError.invalid };return canonical
    }
}

/// The existing exact replay and registration digests, with closed native event
/// shape and terminal projection. It grants no handler, intent or outcome API.
public struct NativeRecoveryPrefix {
    public let required:NativeRequiredCall?
    private var prefix:HandoffPrefix
    public private(set) var terminal=false
    public var high:UInt64 { prefix.high }
    public var registrations:Int { prefix.registrations }
    public init(context:Data,provider:Data,providerDigest:String,request:String,operation:String,route:String) throws {
        required=try NativeRequiredCall.project(provider,digest:providerDigest,request:request,operation:operation,route:route)
        prefix=HandoffPrefix(context:context)
    }
    public mutating func append(_ batch:HandoffBatch) throws {
        guard !terminal,batch.skip==0 else { throw HandoffError.invalid }
        let events=try HandoffContract.decode([WireEvent].self,batch.bytes,maximum:HandoffContract.batch)
        guard events.count==batch.count,!events.isEmpty else { throw HandoffError.invalid }
        if let required {
            guard prefix.high==0 else { throw HandoffError.invalid }
            if events.count==1 {
                switch events[0] { case .finished(.error),.finished(.cancelled):break;default:throw HandoffError.invalid }
            } else {
                let arguments=try required.wholeCall(events)
                try prefix.register(id:Data(required.callID.utf8),name:Data(required.name.utf8),arguments:arguments)
            }
        } else {
            for (index,event) in events.enumerated() {
                switch event {
                case .responseAppend,.usage:break
                case .finished:guard index==events.count-1 else { throw HandoffError.invalid }
                default:throw HandoffError.invalid
                }
            }
        }
        if case .finished?=events.last { terminal=true }
        try prefix.append(batch)
    }
    public mutating func digests() -> (String,String) { prefix.digests() }
}
