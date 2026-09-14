import Foundation
import ResumableMLXProvider
import ReachWire
import RecoveryAuthorityContract

/// Closed qualification lanes. Complete selected-artifact validation still runs
/// in RequestPreparation.validateStored before any native factory is invoked.
public enum NativeRecoveryBinding {
    public static func validate(_ provider: ProviderBinding) throws {
        guard case .supported = ResumableMLXProvider.assess(provider),
              try storeEncode(provider).count <= 16 << 10 else { throw AuthorityError.scope }
        switch provider.lane {
        case .ordinary(let b):
            guard b.options.prefillStepSize == 256, (1...256).contains(b.tokens.count),
                  (1...20).contains(b.options.maximumTokens) else { throw AuthorityError.scope }
        case .guided(let b):
            guard b.options.model.prefillStepSize == 256, (1...256).contains(b.tokens.count),
                  (1...32).contains(b.options.model.maximumTokens) else { throw AuthorityError.scope }
            let s=b.specification, bytes=Data(s.source.utf8)
            let schema=try JSONDecoder().decode(WireGenerationSchema.self,from:bytes)
            guard try storeEncode(schema) == bytes else { throw AuthorityError.scope }
            var nodes=0
            func tree(_ value: WireJSONValue, depth: Int=0) throws {
                nodes += 1; guard nodes <= 8192, depth <= 32 else { throw AuthorityError.scope }
                switch value {
                case .array(let a): for v in a { try tree(v,depth:depth+1) }
                case .object(let o): for v in o.values { try tree(v,depth:depth+1) }
                default: break
                }
            }
            try tree(schema.jsonValue)
            // Reconstruct the public JSON-schema initializer to authenticate the
            // otherwise internal kind/compiler fields. Route alone is insufficient.
            let expected=type(of:s).init(jsonSchema:s.source,vocabulary:s.vocabulary,vocabularyType:s.vocabularyType,
                tokenizerIdentity:s.tokenizerIdentity,eosTokenID:s.eosTokenID,unknownTokenID:s.unknownTokenID,fastForward:s.fastForward)
            guard try storeEncode(expected) == storeEncode(s) else { throw AuthorityError.scope }
        case .required(let b, let tokens):
            guard b.tools.count == 1, b.options.model.prefillStepSize == 256,
                  (1...512).contains(tokens.count), (1...48).contains(b.options.model.maximumTokens),
                  b.requestIdentity == provider.requestID else { throw AuthorityError.scope }
            let schema=try JSONDecoder().decode(WireGenerationSchema.self,from:Data(b.tools[0].schemaJSON.utf8))
            guard try storeEncode(schema) == Data(b.tools[0].schemaJSON.utf8) else { throw AuthorityError.scope }
            let s=b.specification
            let exact=try type(of:b).init(requestIdentity:b.requestIdentity,entryID:b.entryID,callID:b.callID,tools:b.tools,
                identity:b.identity,cacheSpecs:b.cacheSpecs,codecIdentity:b.codecIdentity,vocabulary:s.vocabulary,
                vocabularyType:s.vocabularyType,tokenizerIdentity:s.tokenizerIdentity,eosTokenID:s.eosTokenID,
                unknownTokenID:s.unknownTokenID,fastForward:s.fastForward,options:b.options)
            guard try storeEncode(exact) == storeEncode(b) else { throw AuthorityError.scope }
        case .allowed(let b):
            guard b.tools.count==1,b.requestIdentity==provider.requestID,
                  b.probeOptions.prefillStepSize==256,b.guidedOptions.model.prefillStepSize==256,
                  (1...512).contains(b.originalTokens.count),(1...64).contains(b.probeOptions.maximumTokens),
                  b.guidedOptions.model.maximumTokens==b.probeOptions.maximumTokens else { throw AuthorityError.scope }
            for source in [b.tools[0].schemaJSON]+[b.responseSchema].compactMap({$0}) {
                let bytes=Data(source.utf8),schema=try JSONDecoder().decode(WireGenerationSchema.self,from:bytes)
                guard try storeEncode(schema)==bytes else { throw AuthorityError.scope }
            }
        }
    }
}
