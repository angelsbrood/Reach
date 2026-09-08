import Foundation
import ReachWire
import HostClientContract
import DurableClientReceipts
import WireAdapterContract

public struct ResolvedRequestOptions: Equatable, Sendable {
    public let maximum:Int, temperature:Float, topK:Int, topP:Float, seed:UInt64
}

public struct RequestPolicy: AdapterRequestPolicy {
    public let descriptor:ModelDescriptor
    public init(descriptor:ModelDescriptor) throws { try descriptor.validate(); self.descriptor=descriptor }
    public var requiresPreparedValidation:Bool { true }
    public func validate(_ c:AdapterConfiguration) throws {
        try descriptor.validate()
        guard c.optIn && c.ready else { throw AdapterError.disabled }
        guard c.dialect==2,c.model==descriptor.model,c.profile==DurableWire.profile else { throw AdapterError.incompatible }
    }
    public func route(_ request:WireGenerationRequest) throws -> String {
        try RequestBounds.check(request,revision:descriptor.revision)
        let result:String
        if request.portableSchema != nil { result="guided" }
        else if request.tools.isEmpty {
            guard request.options.toolCalling != .required else { throw PreparationError.unsupported }; result="ordinary"
        } else {
            guard request.tools.count<=8,Set(request.tools.map(\.name)).count==request.tools.count else { throw PreparationError.unsupported }
            if request.options.toolCalling == .required { result="required" }
            else if descriptor.revision==ModelDescriptor.allowedRevision && (request.options.toolCalling==nil || request.options.toolCalling == .allowed) { result="allowed" }
            else { throw PreparationError.unsupported }
        }
        _=try resolve(request.options,route:result);return result
    }
    public func resolve(_ options:WireGenerationOptions,route:String) throws -> ResolvedRequestOptions {
        let maximum=options.maximumResponseTokens ?? 512
        guard (0...512).contains(maximum),options.temperature.map({$0.isFinite && $0>=0 && $0<=Double(Float.greatestFiniteMagnitude)}) ?? true else { throw PreparationError.unsupported }
        if let t=options.temperature,t>0,Float(t)==0 { throw PreparationError.unsupported }
        if route=="guided" && ![ModelDescriptor.schemaRevision,ModelDescriptor.allowedRevision].contains(descriptor.revision) { throw PreparationError.unsupported }
        if route=="allowed" && descriptor.revision != ModelDescriptor.allowedRevision { throw PreparationError.unsupported }
        if route=="required" || route=="guided" || route=="allowed" {
            if let sampling=options.sampling { guard case .greedy=sampling else { throw PreparationError.unsupported } }
            guard options.temperature==nil || options.temperature==0 else { throw PreparationError.unsupported }
            return .init(maximum:maximum,temperature:0,topK:0,topP:1,seed:0)
        }
        guard route=="ordinary" else { throw PreparationError.unsupported }
        var temperature=Float(options.temperature ?? 0.6),topK=0,topP:Float=1,seed:UInt64?
        switch options.sampling {
        case .greedy?: temperature=0
        case .topK(let k,let s)?: guard (1...descriptor.vocabulary.count).contains(k) else { throw PreparationError.unsupported };topK=k;seed=s
        case .topP(let p,let s)?: guard p.isFinite,(0...1).contains(p),p==0 || Float(p)>0 else { throw PreparationError.unsupported };topP=Float(p);seed=s;if p==0 { temperature=0 }
        case nil: break
        }
        guard temperature.isFinite,temperature==0 || ((1/temperature).isFinite && seed != nil) else { throw PreparationError.unsupported }
        // Argmax ignores filter/seed settings; retain filters but use zero when no
        // seed was supplied. The complete original request remains separately bound.
        return .init(maximum:maximum,temperature:temperature,topK:topK,topP:topP,seed:seed ?? 0)
    }
    public func requestBinding(_ request:WireGenerationRequest,configuration:AdapterConfiguration,route:String) throws -> String {
        try validate(configuration);guard try self.route(request)==route else { throw PreparationError.unsupported }
        struct Bound:Encodable { let descriptor:String,model:String,profile:String,route:String;let request:WireGenerationRequest }
        let selection=try descriptor.identity
        let digest=try PreparationEncoding.digest(Bound(descriptor:selection,model:configuration.model,profile:configuration.profile,route:route,request:request))
        return "s89:"+selection+":"+request.id.uuidString.lowercased()+":"+digest
    }
    public func validateRequestID(_ id:String,route:String) throws {
        let fields=id.split(separator:":",omittingEmptySubsequences:false).map(String.init)
        let routes=descriptor.revision==ModelDescriptor.allowedRevision ? ["ordinary","required","guided","allowed"] : (descriptor.revision==ModelDescriptor.schemaRevision ? ["ordinary","required","guided"] : ["ordinary","required"])
        guard routes.contains(route),fields.count==4,fields[0]=="s89",fields[1]==(try descriptor.identity),
              let uuid=UUID(uuidString:fields[2]),uuid.uuidString.lowercased()==fields[2],PreparationEncoding.isDigest(fields[3]) else { throw PreparationError.identity }
    }
    public func validateContext(_ context:ClientContext,configuration:AdapterConfiguration) throws {
        try validate(configuration);try validateRequestID(context.request,route:context.route)
    }
}

/// Preflight collection, tree and string limits before canonical serialization.
public enum RequestBounds {
    private final class Budget {
        var bytes=65_536,nodes=8192
        func string(_ s:String) throws { bytes-=s.utf8.count;guard bytes>=0 else { throw PreparationError.oversized } }
        func identifier(_ s:String) throws { guard !s.isEmpty,s.utf8.count<=256 else { throw PreparationError.unsupported };try string(s) }
        func value(_ v:WireJSONValue,_ depth:Int=0) throws {
            nodes-=1;guard nodes>=0,depth<=32 else { throw PreparationError.oversized }
            switch v {
            case .string(let s):try string(s)
            case .array(let a):guard a.count<=8192 else { throw PreparationError.oversized };for x in a { try value(x,depth+1) }
            case .object(let o):guard o.count<=8192 else { throw PreparationError.oversized };for (k,x) in o { try string(k);try value(x,depth+1) }
            case .number(let n):guard n.isFinite else { throw PreparationError.unsupported }
            default:break
            }
        }
    }
    /// Recovered declarations have no raw request preimage. Check their retained
    /// canonical schema with the same tree ceilings before native compilation.
    public static func canonicalStoredSchema(_ source:String) throws -> String {
        try canonicalSchema(source,budget:Budget())
    }
    /// Canonical selected tool declarations have one shared tree/string budget.
    /// Original descriptions/history remain bound by the authenticated request ID.
    public static func validateStoredTools(names:[String],schemas:[String]) throws {
        guard (1...8).contains(names.count),names.count==schemas.count,Set(names).count==names.count else { throw PreparationError.unsupported }
        let budget=Budget();var encodedBytes=0
        for (name,source) in zip(names,schemas) {
            try budget.identifier(name);encodedBytes+=source.utf8.count+name.utf8.count
            guard encodedBytes<=65_536 else { throw PreparationError.oversized }
            _=try canonicalSchema(source,budget:budget)
        }
    }
    private static func canonicalSchema(_ source:String,budget:Budget) throws -> String {
        guard !source.isEmpty,source.utf8.count<=65_536 else { throw PreparationError.oversized }
        let schema=try JSONDecoder().decode(WireGenerationSchema.self,from:Data(source.utf8))
        let tree=try PreparationEncoding.schemaValue(schema);try budget.value(tree)
        let canonical=String(decoding:try PreparationEncoding.encode(tree),as:UTF8.self)
        guard canonical==source else { throw PreparationError.identity };return canonical
    }
    public static func check(_ r:WireGenerationRequest,revision:String=ModelDescriptor.legacyRevision) throws {
        guard [ModelDescriptor.legacyRevision,ModelDescriptor.schemaRevision,ModelDescriptor.allowedRevision].contains(revision),r.context.reasoning==nil else { throw PreparationError.unsupported }
        if r.portableSchema != nil {
            guard [ModelDescriptor.schemaRevision,ModelDescriptor.allowedRevision].contains(revision),r.tools.isEmpty,r.options.toolCalling != .required,r.context.includeSchemaInPrompt==false else { throw PreparationError.unsupported }
        } else { guard r.context.includeSchemaInPrompt==nil else { throw PreparationError.unsupported } }
        let budget=Budget()
        func string(_ s:String) throws { try budget.string(s) }
        func identifier(_ s:String) throws { try budget.identifier(s) }
        func value(_ v:WireJSONValue) throws { try budget.value(v) }
        func metadata(_ m:[String:WireJSONValue]) throws { try value(.object(m)) }
        func segments(_ ss:[WireTranscript.Segment]) throws {
            guard ss.count<=64 else { throw PreparationError.oversized }
            for s in ss { guard case .text(let t)=s else { throw PreparationError.unsupported };try identifier(t.id);try string(t.content) }
        }
        guard (1...64).contains(r.portableTranscript.entries.count),r.tools.count<=8 else { throw PreparationError.oversized }
        if let schema=r.portableSchema { try value(PreparationEncoding.schemaValue(schema)) }
        for t in r.tools { try identifier(t.name);guard t.description.utf8.count<=8192 else { throw PreparationError.oversized };try string(t.description);try value(PreparationEncoding.schemaValue(t.portableParameters)) }
        for e in r.portableTranscript.entries {
            switch e {
            case .instructions(let x):try identifier(x.id);guard x.toolDefinitions.isEmpty else { throw PreparationError.unsupported };try segments(x.segments)
            case .prompt(let x):try identifier(x.id);guard x.options.isEmpty,x.contextOptions.isEmpty,x.responseFormat==nil else { throw PreparationError.unsupported };try segments(x.segments);try metadata(x.metadata)
            case .response(let x):try identifier(x.id);guard x.assetIDs.isEmpty,x.metadata["assetIDs"]==nil else { throw PreparationError.unsupported };try segments(x.segments);try metadata(x.metadata)
            case .toolCalls(let x):try identifier(x.id);guard (1...8).contains(x.calls.count) else { throw PreparationError.unsupported };for c in x.calls {
                try identifier(c.id);try identifier(c.name);try string(c.argumentsJSON);try metadata(c.metadata)
                let arguments=try JSONDecoder().decode(WireJSONValue.self,from:Data(c.argumentsJSON.utf8))
                guard case .object=arguments else { throw PreparationError.unsupported };try value(arguments)
            }
            case .toolOutput(let x):try identifier(x.id);try identifier(x.toolCallID);try identifier(x.toolName);try segments(x.segments)
            case .reasoning:throw PreparationError.unsupported
            }
        }
        guard try PreparationEncoding.encode(r).count<=65_536 else { throw PreparationError.oversized }
    }
}
