#if canImport(FoundationModels)
import FoundationModels
import ReachHost
import ReachWire

public extension TranscriptChat {
    static func messages(from transcript: Transcript) -> [Message] {
        messages(from: WireTranscript(transcript))
    }
}
#endif
