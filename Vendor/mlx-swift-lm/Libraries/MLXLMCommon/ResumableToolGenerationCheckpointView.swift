import Foundation

/// Genuine S76 frontier only. Historical prose and ordered proposal arguments
/// are not retained by that child and cannot be authenticated by this view.
/// Full native restore must precede inspection of a saved checkpoint.
public struct ResumableToolGenerationCheckpointView: Codable, Equatable, Sendable {
    public let promptTokens: Int
    public let generationTokens: Int
    public let rawTokens: Int
    public let terminalReason: ResumableTextEnd?
    public let disposition: String
    public let forwardedChunks: UInt64
    public let parserSequence: UInt64
    public let parserFinished: Bool
    public let parserState: String
    public let parserBufferedBytes: Int
    public let incompleteUnicode: Bool
    public let namespace: String
    public let issuedIDs: [String]
    public let allocationPosition: UInt64

    public init(checkpoint: ResumableToolGenerationCheckpoint,
                validatedOperation: ResumableToolGeneration) throws {
        guard try validatedOperation.capture() == checkpoint else { throw ResumableTokenError.incompatible }
        let d = try checkpoint.document()
        let text = try ResumableTextCheckpoint(data: d.text).document().output
        let parser = try ResumableToolCallCheckpoint(data: d.parser).document()
        promptTokens = text.promptCount; generationTokens = text.generationCount; rawTokens = text.rawCount
        terminalReason = text.terminal; disposition = d.disposition.rawValue; forwardedChunks = d.forwardedChunks
        parserSequence = parser.sequence; parserFinished = parser.finished; parserState = parser.parser.state
        parserBufferedBytes = parser.parser.buffer.count
        incompleteUnicode = text.emittedTokenCount < text.segmentTokens.count
        namespace = parser.parser.allocation.namespace
        issuedIDs = try parser.parser.issued.map { try ToolCheckpointEncoding.string($0, maximum: 256) }
        allocationPosition = parser.parser.allocation.position
    }
}
