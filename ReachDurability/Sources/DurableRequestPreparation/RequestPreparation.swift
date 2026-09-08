import Foundation
import ReachWire
import MLXLMCommon
import MLXGuidedGeneration
import RequiredToolCoordinator
import AllowedToolCoordinator
import ResumableMLXProvider
import WireAdapterContract
import RequestPreparationContract

public struct SelectedNativePolicy: Encodable {
    public let caches:[ResumableCacheSpec],text:ResumableTextOptions,guided:ResumableGuidedOptions
    public let codec:String,prefill:Int
    public init(caches:[ResumableCacheSpec],text:ResumableTextOptions,guided:ResumableGuidedOptions,codec:String,prefill:Int) {
        self.caches=caches;self.text=text;self.guided=guided;self.codec=codec;self.prefill=prefill
    }
    public var identity:String { get throws { try PreparationEncoding.digest(self) } }
    public func guidedOptions(maximum:Int) -> ResumableGuidedOptions {
        .init(model:.init(logitWidth:guided.model.logitWidth,maximumTokens:maximum,prefillStepSize:prefill),
              completionReserve:guided.completionReserve,hardReserve:guided.hardReserve,closingBias:guided.closingBias,
              whitespaceBias:guided.whitespaceBias,whitespaceTokenIDs:Set(guided.whitespaceTokenIDs),whitespaceThreshold:guided.whitespaceThreshold)
    }
}

/// Synchronous public text core. Owner supplies current artifact attestations;
/// this does not pretend to inspect arbitrary tokenizer/model implementations.
public final class RequestPreparation {
    public let policy:RequestPolicy,native:SelectedNativePolicy,tokenizer:any Tokenizer
    public private(set) var preparations=0,templateCalls=0
    public private(set) var lastTokens:[Int]=[]
    public init(descriptor:RequestPreparationContract.ModelDescriptor,actualDescriptor:RequestPreparationContract.ModelDescriptor,native:SelectedNativePolicy,tokenizer:any Tokenizer) throws {
        guard descriptor==actualDescriptor,descriptor.nativePolicy==(try native.identity),descriptor.codec==native.codec,
              (try descriptor.tokenizerIdentity)==native.text.tokenizerIdentity,native.guided.model.maximumTokens==0,
              native.guided.model.logitWidth==descriptor.vocabulary.count,(1...4096).contains(native.prefill),
              native.guided.model.prefillStepSize==native.prefill,tokenizer.eosTokenId != nil,
              tokenizer.eosTokenId==native.text.stopTokenIDs.first,tokenizer.unknownTokenId==native.text.unknownTokenID else { throw PreparationError.identity }
        self.policy=try .init(descriptor:descriptor);self.native=native;self.tokenizer=tokenizer
    }
    public func prepare(_ request:WireGenerationRequest,reference:DurableGenerationReference,configuration:AdapterConfiguration) throws -> ProviderBinding {
        try policy.validate(configuration)
        let route=try policy.route(request),resolved=try policy.resolve(request.options,route:route)
        let input=try TranscriptPreparation.input(request,revision:policy.descriptor.revision),messages=DefaultMessageGenerator().generate(from:input)
        preparations+=1;templateCalls+=1
        let tokens=try tokenizer.applyChatTemplate(messages:messages,tools:input.tools,additionalContext:input.additionalContext)
        try checkTokens(tokens);lastTokens=tokens
        let requestID=try policy.requestBinding(request,configuration:configuration,route:route),d=policy.descriptor
        let model=AllowedModelBinding(identity:try identity(tokens),cacheSpecs:native.caches,codecIdentity:native.codec)
        let ids=try stableIDs(requestID,operation:reference.operationID)
        let binding:ProviderBinding
        if route=="ordinary" {
            let options=ResumableTokenOptions(vocabularySize:d.vocabulary.count,maximumTokens:resolved.maximum,prefillStepSize:native.prefill,
                temperature:resolved.temperature,topP:resolved.topP,topK:resolved.topK,seed:resolved.seed)
            binding = .init(operationID:reference.operationID,requestID:requestID,lane:.ordinary(.init(model:model,tokens:tokens,options:options,text:native.text,entryID:ids.0,segmentID:ids.1)))
        } else if route=="required" {
            let tools=try request.tools.map { RequiredToolDefinition(name:$0.name,schemaJSON:String(decoding:try PreparationEncoding.encode(PreparationEncoding.schemaValue($0.portableParameters)),as:UTF8.self)) }
            let required=try RequiredToolBinding(requestIdentity:requestID,entryID:ids.0,callID:ids.1,tools:tools,identity:model.identity,
                cacheSpecs:native.caches,codecIdentity:native.codec,vocabulary:d.vocabulary,vocabularyType:.byteFallback,
                tokenizerIdentity:d.tokenizerIdentity,eosTokenID:tokenizer.eosTokenId!,unknownTokenID:tokenizer.unknownTokenId,
                fastForward:true,options:native.guidedOptions(maximum:resolved.maximum))
            binding = .init(operationID:reference.operationID,requestID:requestID,lane:.required(required,tokens:tokens))
        } else if route=="allowed" {
            let tools=try request.tools.map { RequiredToolDefinition(name:$0.name,schemaJSON:String(decoding:try PreparationEncoding.encode(PreparationEncoding.schemaValue($0.portableParameters)),as:UTF8.self)) }
            binding = .init(operationID:reference.operationID,requestID:requestID,lane:.allowed(try allowed(requestID:requestID,operation:reference.operationID,tokens:tokens,tools:tools,maximum:resolved.maximum,responseSchema:request.portableSchema.map { String(decoding:try PreparationEncoding.encode(PreparationEncoding.schemaValue($0)),as:UTF8.self) })))
        } else {
            guard let schema=request.portableSchema else { throw PreparationError.unsupported }
            let source=String(decoding:try PreparationEncoding.encode(PreparationEncoding.schemaValue(schema)),as:UTF8.self)
            let specification=ResumableGrammarSpecification(jsonSchema:source,vocabulary:d.vocabulary,vocabularyType:.byteFallback,
                tokenizerIdentity:try d.tokenizerIdentity,eosTokenID:tokenizer.eosTokenId!,unknownTokenID:tokenizer.unknownTokenId,fastForward:true)
            binding = .init(operationID:reference.operationID,requestID:requestID,lane:.guided(.init(model:model,tokens:tokens,
                specification:specification,options:native.guidedOptions(maximum:resolved.maximum),entryID:ids.0,segmentID:ids.1)))
        }
        try validateStored(binding,configuration:configuration);return binding
    }
    private func allowed(requestID:String,operation:String,tokens:[Int],tools:[RequiredToolDefinition],maximum:Int,responseSchema:String?=nil) throws -> AllowedToolBinding {
        let d=policy.descriptor
        let current=d.revision==RequestPreparationContract.ModelDescriptor.schemaToolRevision
        let domain=current ? "s92" : "s91"
        // Bind optional fallback declaration consistency without reconstructing
        // the original request preimage. S91 domains/bytes stay exact.
        let material=[requestID,operation]+(current ? [responseSchema==nil ? "none" : "schema",responseSchema ?? ""] : [])
        let entry="entry-" + (try PreparationEncoding.digest([domain+"-entry-v1"]+material))
        let namespace=String(try PreparationEncoding.digest([domain+"-parser-namespace-v1"]+material).prefix(32))
        let model=AllowedModelBinding(identity:try identity(tokens),cacheSpecs:native.caches,codecIdentity:native.codec)
        let tokenizerSpec=ResumableGrammarSpecification(jsonSchema:"{}",vocabulary:d.vocabulary,vocabularyType:.byteFallback,
            tokenizerIdentity:try d.tokenizerIdentity,eosTokenID:tokenizer.eosTokenId!,unknownTokenID:tokenizer.unknownTokenId,fastForward:true)
        return try .init(requestIdentity:requestID,entryID:entry,namespace:namespace,tools:tools,responseSchema:responseSchema,originalTokens:tokens,
            probeModel:model,guidedModel:model,
            probeOptions:.init(vocabularySize:d.vocabulary.count,maximumTokens:maximum,prefillStepSize:native.prefill,temperature:0,topP:1,topK:0,seed:0),
            textOptions:native.text,format:.json,tokenizer:tokenizerSpec,guidedOptions:native.guidedOptions(maximum:maximum))
    }
    private func stableIDs(_ request:String,operation:String) throws -> (String,String) {
        let suffix=try PreparationEncoding.digest([request,operation]);return ("entry-"+suffix,"segment-call-"+suffix)
    }
    private func checkTokens(_ tokens:[Int]) throws {
        guard (1...2048).contains(tokens.count),tokens.allSatisfy({policy.descriptor.vocabulary.indices.contains($0)}) else { throw PreparationError.tokens }
    }
    private func identity(_ tokens:[Int]) throws -> ResumableTokenIdentity {
        let d=policy.descriptor
        return try .init(model:d.model,configuration:d.configuration,weights:d.weights,input:ResumableTokenIdentity.inputDigest(tokens),backend:d.backend,dependency:d.dependency)
    }
    /// Pure persisted-declaration validation; no request mapping, template,
    /// tokenization, model creation/prepare/forward, or replacement identifiers.
    public func validateStored(_ binding:ProviderBinding,configuration:AdapterConfiguration) throws {
        try policy.validate(configuration);try policy.validateRequestID(binding.requestID,route:binding.lane.route.rawValue)
        guard case .supported=ResumableMLXProvider.assess(binding) else { throw PreparationError.identity }
        let ids=try stableIDs(binding.requestID,operation:binding.operationID),d=policy.descriptor
        switch binding.lane {
        case .ordinary(let b):
            try checkTokens(b.tokens)
            guard b.model.identity==(try identity(b.tokens)),b.model.cacheSpecs==native.caches,b.model.codecIdentity==native.codec,
                  (try PreparationEncoding.encode(b.text))==(try PreparationEncoding.encode(native.text)),b.entryID==ids.0,b.segmentID==ids.1,(0...512).contains(b.options.maximumTokens),
                  b.options.prefillStepSize==native.prefill,b.options.vocabularySize==d.vocabulary.count else { throw PreparationError.identity }
            let expected=ResumableTokenOptions(vocabularySize:d.vocabulary.count,maximumTokens:b.options.maximumTokens,prefillStepSize:native.prefill,
                temperature:b.options.temperature,topP:b.options.topP,topK:b.options.topK,seed:b.options.seed)
            guard b.options==expected,b.options.temperature==0 || b.options.topP>0 else { throw PreparationError.identity }
        case .guided(let b):
            guard [RequestPreparationContract.ModelDescriptor.schemaRevision,RequestPreparationContract.ModelDescriptor.allowedRevision,RequestPreparationContract.ModelDescriptor.schemaToolRevision].contains(d.revision),(0...512).contains(b.options.model.maximumTokens) else { throw PreparationError.identity }
            try checkTokens(b.tokens)
            let source=try RequestBounds.canonicalStoredSchema(b.specification.source)
            let specification=ResumableGrammarSpecification(jsonSchema:source,vocabulary:d.vocabulary,vocabularyType:.byteFallback,
                tokenizerIdentity:try d.tokenizerIdentity,eosTokenID:tokenizer.eosTokenId!,unknownTokenID:tokenizer.unknownTokenId,fastForward:true)
            let expected=ProviderGuidedBinding(model:.init(identity:try identity(b.tokens),cacheSpecs:native.caches,codecIdentity:native.codec),tokens:b.tokens,
                specification:specification,options:native.guidedOptions(maximum:b.options.model.maximumTokens),entryID:ids.0,segmentID:ids.1)
            guard try PreparationEncoding.encode(b)==PreparationEncoding.encode(expected) else { throw PreparationError.identity }
        case .required(let b,let tokens):
            try checkTokens(tokens)
            guard (0...512).contains(b.options.model.maximumTokens),(1...8).contains(b.tools.count) else { throw PreparationError.identity }
            let expected=try RequiredToolBinding(requestIdentity:binding.requestID,entryID:ids.0,callID:ids.1,tools:b.tools,identity:identity(tokens),
                cacheSpecs:native.caches,codecIdentity:native.codec,vocabulary:d.vocabulary,vocabularyType:.byteFallback,
                tokenizerIdentity:d.tokenizerIdentity,eosTokenID:tokenizer.eosTokenId!,unknownTokenID:tokenizer.unknownTokenId,
                fastForward:true,options:native.guidedOptions(maximum:b.options.model.maximumTokens))
            guard try PreparationEncoding.encode(b)==PreparationEncoding.encode(expected) else { throw PreparationError.identity }
        case .allowed(let b):
            guard [RequestPreparationContract.ModelDescriptor.allowedRevision,RequestPreparationContract.ModelDescriptor.schemaToolRevision].contains(d.revision),
                  b.responseSchema==nil || d.revision==RequestPreparationContract.ModelDescriptor.schemaToolRevision,(0...512).contains(b.probeOptions.maximumTokens) else { throw PreparationError.identity }
            try checkTokens(b.originalTokens)
            try RequestBounds.validateStoredTools(names:b.tools.map(\.name),schemas:b.tools.map(\.schemaJSON),responseSchema:b.responseSchema)
            let expected=try allowed(requestID:binding.requestID,operation:binding.operationID,tokens:b.originalTokens,tools:b.tools,maximum:b.probeOptions.maximumTokens,responseSchema:b.responseSchema)
            guard try PreparationEncoding.encode(b)==PreparationEncoding.encode(expected) else { throw PreparationError.identity }
        }
    }
}
