import Foundation
import ReachWire

/// The slot: reachd hosts whatever filling conforms. The slot speaks the
/// wire's event vocabulary natively — the framework's channel events are
/// construct-only, so a filling never touches them; only the client-side
/// executor does.
public protocol SlotFilling: Sendable {
    var modelID: String { get }
    var displayName: String { get }
    var capabilities: [String] { get }

    /// How many public generations this provider can execute at once.
    ///
    /// This is deliberately about the whole generation, not a prefill,
    /// decode loop, or guided/tool pass inside one. A filling that can safely
    /// host more work may opt in; existing fillings inherit the conservative
    /// one-generation capacity.
    var maximumConcurrentGenerations: Int { get }

    /// Prepare whatever the filling needs (weights, caches) before serving.
    func prewarm() async throws

    /// Serve one generation. The stream finishes after `.finished`.
    func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error>

    /// Stop accepting provider work, cancel every owned operation, and return
    /// only after provider-side children have terminated.
    func shutdown() async
}

public extension SlotFilling {
    var maximumConcurrentGenerations: Int { 1 }

    func shutdown() async {}
}

/// Transcript → (role, text) mapping shared by fillings (spike S4c).
public enum TranscriptChat {
    public struct Message: Sendable, Equatable {
        public enum Role: Sendable, Equatable { case system, user, assistant, tool }

        /// One call the model already made, as it must be replayed on the next
        /// turn. Arguments ride as a JSON string because that is what both ends
        /// speak: the framework hands them over as `GeneratedContent`, whose
        /// `jsonString` is lossless, and every chat template renders them from
        /// JSON.
        public struct Call: Sendable, Equatable {
            public var id: String
            public var name: String
            public var argumentsJSON: String

            public init(id: String, name: String, argumentsJSON: String) {
                self.id = id
                self.name = name
                self.argumentsJSON = argumentsJSON
            }
        }

        /// What a message carries beyond its text once a tool round trip is in
        /// the transcript. Absent for every message in a session without tools,
        /// which is why nothing about the no-tools path changes shape.
        public enum ToolPart: Sendable, Equatable {
            /// An assistant turn that ended in calls rather than prose.
            case calls([Call])
            /// A tool's answer, tagged with the call it answers. The id is the
            /// **call's**, not the transcript entry's — verified in spike S6a,
            /// where a `toolOutput` came back carrying the id minted for the
            /// call rather than the id of the `toolCalls` entry holding it.
            case output(callID: String)
        }

        public var role: Role
        public var text: String
        public var tool: ToolPart?

        public init(role: Role, text: String, tool: ToolPart? = nil) {
            self.role = role
            self.text = text
            self.tool = tool
        }
    }

    public static func messages(from transcript: WireTranscript) -> [Message] {
        var messages: [Message] = []
        for entry in transcript {
            switch entry {
            case .instructions(let instructions):
                messages.append(Message(role: .system, text: text(of: instructions.segments)))
            case .prompt(let prompt):
                messages.append(Message(role: .user, text: text(of: prompt.segments)))
            case .response(let response):
                messages.append(Message(role: .assistant, text: text(of: response.segments)))
            // The two entries a tool round trip adds. They were dropped here
            // for as long as the daemon had nothing to do with them, which was
            // survivable only while it never rendered tools: replaying a turn
            // with the call and its answer missing leaves the model looking at
            // its own question with no answer and asking it again.
            case .toolCalls(let calls):
                messages.append(Message(
                    role: .assistant,
                    text: "",
                    tool: .calls(calls.calls.map { call in
                        Message.Call(
                            id: call.id,
                            name: call.name,
                            argumentsJSON: call.argumentsJSON
                        )
                    })
                ))
            case .toolOutput(let output):
                messages.append(Message(
                    role: .tool,
                    text: text(of: output.segments),
                    tool: .output(callID: output.toolCallID)
                ))
            default:
                continue
            }
        }
        return messages
    }

    static func text(of segments: [WireTranscript.Segment]) -> String {
        segments.compactMap { segment in
            if case .text(let text) = segment { return text.content }
            return nil
        }.joined()
    }
}
