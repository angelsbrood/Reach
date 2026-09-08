import Foundation
import MLXLMCommon
import RequestPreparationContract

public final class ArtifactTokenizer: Tokenizer, @unchecked Sendable {
    public static let configuredTemplate="s89-json-chat-v1:sorted-json(messages,tools,enable_thinking=false) + LF + assistant-prefix"
    public let template:String
        let repairPrefix="S79-json-messages-tokenizer-v1\n"
    public private(set) var repairEncodes=0
    public private(set) var renders=0,encodes=0,requestTokenizations=0,lastRendered=""
    public init(template:String=ArtifactTokenizer.configuredTemplate) { self.template=template }
    public var bosToken:String? { nil }; public var eosToken:String? { "<eos>" };public var unknownToken:String? { "<unk>" }
    public func encode(text:String,addSpecialTokens:Bool) -> [Int] { encodes+=1;if text.hasPrefix(repairPrefix) { repairEncodes+=1 };return text.utf8.map { Int($0)+1 } }
    public func decode(tokenIds:[Int],skipSpecialTokens:Bool) -> String { String(decoding:tokenIds.filter{(1...256).contains($0)}.map{UInt8($0-1)},as:UTF8.self) }
    public func convertTokenToId(_ token:String) -> Int? { SelectedArtifactProfile.vocabulary.firstIndex(of:token) }
    public func convertIdToToken(_ id:Int) -> String? { SelectedArtifactProfile.vocabulary.indices.contains(id) ? SelectedArtifactProfile.vocabulary[id] : nil }
    public func applyChatTemplate(messages:[[String:any Sendable]],tools:[[String:any Sendable]]?,additionalContext:[String:any Sendable]?) throws -> [Int] {
        guard !template.isEmpty else { throw TokenizerError.missingChatTemplate }
        guard template==Self.configuredTemplate,additionalContext?["enable_thinking"] as? Bool == false else { throw PreparationError.template }
        renders+=1
        var bytes=Data()
        func append(_ s:String) throws { guard bytes.count+s.utf8.count<=65_536 else { throw PreparationError.oversized };bytes.append(contentsOf:s.utf8) }
        func render(_ value:Any,_ depth:Int=0) throws {
            guard depth<=40 else { throw PreparationError.oversized }
            if let object=value as? [String:Any] {
                try append("{");for (i,key) in object.keys.sorted().enumerated() { if i>0 { try append(",") };try render(key,depth+1);try append(":");try render(object[key]!,depth+1) };try append("}")
            } else if let array=value as? [Any] {
                try append("[");for (i,x) in array.enumerated() { if i>0 { try append(",") };try render(x,depth+1) };try append("]")
            } else if let string=value as? String {
                try append("\"")
                for scalar in string.unicodeScalars {
                    switch scalar.value {
                    case 34:try append("\\\"")
                    case 92:try append("\\\\")
                    case 0...31:try append(String(format:"\\u%04x",scalar.value))
                    default:try append(String(scalar))
                    }
                }
                try append("\"")
            } else {
                let encoded=try JSONSerialization.data(withJSONObject:value,options:[.fragmentsAllowed,.sortedKeys,.withoutEscapingSlashes])
                guard bytes.count+encoded.count<=65_536 else { throw PreparationError.oversized };bytes.append(encoded)
            }
        }
        try render(["messages":messages,"tools":tools ?? [],"enable_thinking":false] as [String:Any])
        try append("\n{\"role\":\"assistant\",\"content\":")
        lastRendered=String(decoding:bytes,as:UTF8.self)
        requestTokenizations+=1;return encode(text:lastRendered,addSpecialTokens:false)
    }
}
