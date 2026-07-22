import Foundation
import FoundationModels
import ReachWire

/// The slot: reachd hosts whatever filling conforms. The slot speaks the
/// wire's event vocabulary natively — the framework's channel events are
/// construct-only, so a filling never touches them; only the client-side
/// executor does.
public protocol SlotFilling: Sendable {
    var modelID: String { get }
    var displayName: String { get }
    var capabilities: [String] { get }

    /// Prepare whatever the filling needs (weights, caches) before serving.
    func prewarm() async throws

    /// Serve one generation. The stream finishes after `.finished`.
    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error>
}

/// Transcript → (role, text) mapping shared by fillings (spike S4c).
public enum TranscriptChat {
    public struct Message: Sendable, Equatable {
        public enum Role: Sendable, Equatable { case system, user, assistant }
        public var role: Role
        public var text: String

        public init(role: Role, text: String) {
            self.role = role
            self.text = text
        }
    }

    public static func messages(from transcript: Transcript) -> [Message] {
        var messages: [Message] = []
        for entry in transcript {
            switch entry {
            case .instructions(let instructions):
                messages.append(Message(role: .system, text: text(of: instructions.segments)))
            case .prompt(let prompt):
                messages.append(Message(role: .user, text: text(of: prompt.segments)))
            case .response(let response):
                messages.append(Message(role: .assistant, text: text(of: response.segments)))
            default:
                continue
            }
        }
        return messages
    }

    static func text(of segments: [Transcript.Segment]) -> String {
        segments.compactMap { segment in
            if case .text(let text) = segment { return text.content }
            return nil
        }.joined()
    }
}
