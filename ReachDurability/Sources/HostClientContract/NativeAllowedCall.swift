import Foundation
import ReachWire

/// Static original provenance only. A probe-selected call ID and aggregate
/// usage are authenticated by saved host history, not precommitted here.
public struct NativeAllowedCall {
    public let request:String,operation:String,entryID:String,namespace:String,name:String,schemaJSON:String
    public let inputTokens:Int,maximumTokens:Int
    static func project(_ provider:Data,digest:String,request:String,operation:String,route:String) throws -> NativeAllowedCall? {
        guard route=="allowed" else { return nil }
        guard provider.count<=16<<10,HandoffContract.hash(provider)==digest,
              let root=try JSONSerialization.jsonObject(with:provider) as? [String:Any],
              root["version"] as? Int==1,root["policy"] as? String=="S80-exact-candidate-ack;json-sorted-v1",
              root["requestID"] as? String==request,root["operationID"] as? String==operation,
              let lane=root["lane"] as? [String:Any],Set(lane.keys)==["allowed"],
              let selected=lane["allowed"] as? [String:Any],Set(selected.keys)==["_0"],
              let b=selected["_0"] as? [String:Any],b["version"] as? Int==1,b["route"] as? String=="allowed",
              b["policy"] as? String=="S79-proposals-first;visible-probe-unless-schema;final-ready-wins-v1",
              b["preparationPolicy"] as? String=="S79-json-messages-tokenizer-v1",b["requestIdentity"] as? String==request,
              b["responseSchema"]==nil,let entry=b["entryID"] as? String,!entry.isEmpty,entry.utf8.count<=256,
              let namespace=b["namespace"] as? String,namespace.utf8.count==32,
              namespace.utf8.allSatisfy({(48...57).contains($0)||(97...102).contains($0)}),
              let tools=b["tools"] as? [[String:Any]],tools.count==1,
              let name=tools[0]["name"] as? String,!name.isEmpty,name.utf8.count<=1024,
              let schema=tools[0]["schemaJSON"] as? String,schema.utf8.count<=65536,
              let tokens=b["originalTokens"] as? [Int],(1...512).contains(tokens.count),
              let probe=b["probeOptions"] as? [String:Any],probe["prefillStepSize"] as? Int==256,
              let maximum=probe["maximumTokens"] as? Int,(1...64).contains(maximum),
              let guided=b["guidedOptions"] as? [String:Any],let model=guided["model"] as? [String:Any],
              model["maximumTokens"] as? Int==maximum,model["prefillStepSize"] as? Int==256 else { throw HandoffError.invalid }
        let bytes=Data(schema.utf8),portable=try JSONDecoder().decode(WireGenerationSchema.self,from:bytes)
        guard try HandoffContract.encode(portable)==bytes else { throw HandoffError.invalid }
        return .init(request:request,operation:operation,entryID:entry,namespace:namespace,name:name,schemaJSON:schema,inputTokens:tokens.count,maximumTokens:maximum)
    }
    struct Registration { let id:String,name:String,arguments:Data }
    func validate(_ events:[WireEvent]) throws -> Registration? {
        guard !events.isEmpty else { throw HandoffError.invalid }
        if case .toolCallAppendArguments(let entry,let id,let name,let arguments,let count)=events[0] {
            guard events.count==3,entry==entryID,!id.isEmpty,id.utf8.count<=256,name==self.name,count==1,
                  arguments.utf8.count<=256<<10,
                  case .usage(let input,let output)=events[1],
                  ((inputTokens+1)...(inputTokens+512)).contains(input),(0..<(2*maximumTokens)).contains(output),
                  case .finished(.complete)=events[2],
                  let object=try JSONSerialization.jsonObject(with:Data(arguments.utf8)) as? [String:Any] else { throw HandoffError.invalid }
            let canonical=try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys,.withoutEscapingSlashes])
            guard canonical==Data(arguments.utf8) else { throw HandoffError.invalid }
            return .init(id:id,name:name,arguments:canonical)
        }
        if events.count==2,case .usage(let input,let output)=events[0],case .finished(.complete)=events[1] {
            guard input==inputTokens,(0...maximumTokens).contains(output) else { throw HandoffError.invalid };return nil
        }
        if events.count==1 {
            switch events[0] { case .finished(.error),.finished(.cancelled):return nil;default:break }
        }
        for event in events {
            guard case .responseAppend(let entry,let text,let segment,let count)=event,
                  entry==nil,segment==nil,!text.isEmpty,count==1 else { throw HandoffError.invalid }
        }
        return nil
    }
}
