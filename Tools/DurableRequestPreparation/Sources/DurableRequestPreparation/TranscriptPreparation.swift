import Foundation
import ReachWire
import MLXLMCommon
import RequestPreparationContract

public enum TranscriptPreparation {
    public static func input(_ request:WireGenerationRequest,revision:String=RequestPreparationContract.ModelDescriptor.legacyRevision) throws -> UserInput {
        try RequestBounds.check(request,revision:revision)
        var chat:[Chat.Message]=[],pending:[String:String]=[:],seen=Set<String>()
        func text(_ segments:[WireTranscript.Segment]) throws -> String {
            try segments.map { guard case .text(let t)=$0 else { throw PreparationError.unsupported };return t.content }.joined()
        }
        for entry in request.portableTranscript.entries {
            switch entry {
            case .instructions(let x):guard pending.isEmpty else { throw PreparationError.unsupported };chat.append(.system(try text(x.segments)))
            case .prompt(let x):guard pending.isEmpty else { throw PreparationError.unsupported };chat.append(.user(try text(x.segments)))
            case .response(let x):guard pending.isEmpty else { throw PreparationError.unsupported };chat.append(.assistant(try text(x.segments)))
            case .toolCalls(let x):
                guard pending.isEmpty else { throw PreparationError.unsupported }
                var calls:[ToolCall]=[]
                for c in x.calls {
                    guard seen.insert(c.id).inserted else { throw PreparationError.unsupported }
                    let arguments=try JSONDecoder().decode([String:MLXLMCommon.JSONValue].self,from:Data(c.argumentsJSON.utf8))
                    let portable=try JSONDecoder().decode(WireJSONValue.self,from:Data(c.argumentsJSON.utf8))
                    let roundTrip=try JSONDecoder().decode(WireJSONValue.self,from:PreparationEncoding.encode(arguments))
                    guard portable==roundTrip else { throw PreparationError.unsupported }
                    pending[c.id]=c.name;calls.append(.init(function:.init(name:c.name,arguments:arguments),id:c.id))
                }
                chat.append(.assistant("",toolCalls:calls))
            case .toolOutput(let x):
                guard pending.removeValue(forKey:x.toolCallID)==x.toolName else { throw PreparationError.unsupported }
                chat.append(.tool(try text(x.segments),id:x.toolCallID))
            case .reasoning:throw PreparationError.unsupported
            }
        }
        guard pending.isEmpty else { throw PreparationError.unsupported }
        let tools:[ToolSpec]=try request.tools.map { t in
            // Enter the throwing portable encoder before extracting its bounded tree.
            let bytes=try PreparationEncoding.encode(PreparationEncoding.schemaValue(t.portableParameters))
            let schema=try JSONDecoder().decode(WireJSONValue.self,from:bytes)
            return ["type":"function","function":["name":t.name,"description":t.description,"parameters":sendable(schema)] as [String:any Sendable]]
        }
        return UserInput(chat:chat,tools:tools.isEmpty ? nil : tools,additionalContext:["enable_thinking":false])
    }
    private static func sendable(_ value:WireJSONValue) -> any Sendable {
        switch value {
        case .null:return NSNull()
        case .bool(let v):return v
        case .integer(let v):return v
        case .unsigned(let v):return v
        case .number(let v):return v
        case .string(let v):return v
        case .array(let v):return v.map(sendable)
        case .object(let v):return v.mapValues(sendable)
        }
    }
}
