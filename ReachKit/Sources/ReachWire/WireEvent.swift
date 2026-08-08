/// The wire's event vocabulary, mirroring the framework channel's factory
/// surface. The framework's own `Event`/`Action` types are construct-only
/// (verified: no public read path), so the daemon's slot produces these
/// natively and only the client-side executor turns them into framework
/// events via the factories.
public enum WireEvent: Codable, Sendable, Equatable {
    case responseAppend(entryID: String?, text: String, segmentID: String?, tokenCount: Int)
    case responseReplace(entryID: String?, text: String, segmentID: String?, tokenCount: Int)
    case reasoningAppend(entryID: String?, text: String, segmentID: String?, tokenCount: Int)
    /// One complete, grammar-constrained tool argument object. The daemon
    /// emits whole calls because the pinned native processor exposes no safe
    /// incremental argument surface.
    case toolCallAppendArguments(entryID: String?, id: String, name: String, content: String, tokenCount: Int)
    case usage(inputTokens: Int, outputTokens: Int)
    case finished(WireFinishReason)
}

public enum WireFinishReason: Codable, Sendable, Equatable {
    case complete
    case cancelled
    case error(String)
}
