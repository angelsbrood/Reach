import MLX
import MLXLMCommon

/// Reach's JSON completion policy for constrained generation.
///
/// A digit is content, not a structural exit: rewarding it in the hard
/// completion zone can keep an otherwise accepting integer grammar alive
/// forever. Separators are the useful exit instead. The grammar mask still
/// decides legality, so a required first digit remains available while a
/// comma is preferred as soon as the current number may finish.
enum CompletionGuidance {
    static let closingCharacters: Set<String> = ["\"", "}", "]", ","]

    static func isClosingToken(_ token: String) -> Bool {
        closingCharacters.contains(token)
    }

    static func closingBias(
        tokenizer: any MLXLMCommon.Tokenizer,
        eosTokenID: Int?
    ) -> MLXArray {
        var vocabularySize = 0
        while tokenizer.convertIdToToken(vocabularySize) != nil {
            vocabularySize += 1
            if vocabularySize > 500_000 { break }
        }

        var biases = [Float](repeating: 0, count: vocabularySize)
        for id in 0 ..< vocabularySize {
            if let token = tokenizer.convertIdToToken(id), isClosingToken(token) {
                biases[id] = 100
            }
        }
        if let eosTokenID, eosTokenID >= 0, eosTokenID < vocabularySize {
            biases[eosTokenID] = 200
        }
        return MLXArray(biases)
    }
}
