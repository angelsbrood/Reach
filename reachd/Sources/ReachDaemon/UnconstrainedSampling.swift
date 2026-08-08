import MLXLMCommon
import ReachWire

/// Resolves the sampling controls that can safely ride an unconstrained MLX
/// pass. Grammar-constrained passes deliberately do not call this resolver:
/// their argmax completion boundary is a separately measured contract.
enum UnconstrainedSampling {
    static func parameters(
        options: WireGenerationOptions,
        maxTokens: Int
    ) -> GenerateParameters {
        var parameters = GenerateParameters(maxTokens: maxTokens)

        if let temperature = options.temperature {
            parameters.temperature = Float(Swift.max(0, temperature))
        }

        switch options.sampling {
        case .greedy:
            parameters.temperature = 0

        case .topK(let k, let seed):
            if k >= 1 {
                parameters.topK = k
            }
            parameters.seed = seed

        case .topP(let probability, let seed):
            if probability <= 0 {
                parameters.temperature = 0
            } else {
                // One is MLX's explicit no-filter value; normalize larger
                // wire values to the same full-distribution meaning.
                parameters.topP = Float(Swift.min(probability, 1))
            }
            parameters.seed = seed

        case nil:
            break
        }

        return parameters
    }
}
