import Foundation
import ReachWire
import RequestPreparationContract
import RequestPreparationFixtures

/// S90 only selects the new revision and bounded requests. Preparation, the
/// real tiny-Llama runtime, journals and encoded adapters are the S89 libraries.
public enum SchemaPreparationFixtures {
    public static let revision=ModelDescriptor.schemaRevision
    public static let phrase="A durable schema response retains its visible prefix while the fresh process continues the original generation."
    public static func native() throws -> NativePreparationFixture { try .init(revision:revision) }
    public static func pair(root:String?=nil,fresh:Bool=true) throws -> PreparationPair {
        try .init(root:root ?? (PreparationFixtures.base()+"/schema-unit-"+UUID().uuidString.lowercased()),fresh:fresh,revision:revision)
    }
    public static func request(_ variant:String="seven",text:String="Hello 🌙 — retain café and 日本語.") throws -> WireGenerationRequest {
        guard ["seven","eight","scalar","zero","short"].contains(variant) else { throw PreparationError.unsupported }
        var request=try PreparationFixtures.request("ordinary",text:text)
        let n:Int64=variant=="eight" ? 8 : 7
        let value:WireJSONValue=variant=="scalar" ? .object(["type":.string("string"),"enum":.array([.string("ok")])]) :
            .object(["title":.string("S90Reply"),"type":.string("object"),"properties":.object([
                "text":.object(["type":.string("string"),"enum":.array([.string(phrase)])]),
                "n":.object(["type":.string("integer"),"minimum":.integer(n),"maximum":.integer(n)])]),
                "required":.array([.string("text"),.string("n")]),"x-order":.array([.string("text"),.string("n")]),"additionalProperties":.bool(false)])
        request.portableSchema=try .init(jsonValue:value)
        request.options = .init(maximumResponseTokens:variant=="zero" ? 0 : (variant=="short" ? 1 : 256),sampling:.greedy)
        request.context.includeSchemaInPrompt=false
        return request
    }
    public static func events(_ batches:[DurableBatchPayload]) throws -> [WireEvent] {
        try batches.flatMap { try JSONDecoder().decode([WireEvent].self,from:$0.bytes) }
    }
    public static func text(_ batches:[DurableBatchPayload]) throws -> String {
        try events(batches).compactMap { event -> String? in
            if case .responseAppend(_,let text,_,_)=event { return text };return nil
        }.joined()
    }
}
