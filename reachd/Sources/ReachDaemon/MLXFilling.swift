import Foundation
import HuggingFace
import MLXHuggingFace
import MLXLLM
import MLXLMCommon
import ReachWire
import Tokenizers

/// Open weights on the host GPU behind the slot — single-node MLX only for
/// this package (the exo adapter is funded scope, and deliberately absent).
public final class MLXFilling: SlotFilling {
    public let modelID: String
    public let displayName: String
    public let capabilities: [String] = []

    private let configuration: ModelConfiguration
    private let container = ContainerBox()

    /// Known registry ids map through `LLMRegistry`; anything else is
    /// treated as a Hugging Face repo id.
    public init(modelID: String) {
        self.modelID = modelID
        switch modelID {
        case "gemma-4-e2b", "default":
            // Built by hand because the QAT weights are in no registry —
            // neither factory names them. `extraEOSTokens` is not decoration:
            // the registry's own gemma-4 entries carry it, and without it the
            // stream does not stop at the turn boundary. What that looks like
            // is the demo's essay followed by chatbot text, which is the one
            // thing the closing frame cannot have.
            configuration = ModelConfiguration(
                id: "mlx-community/gemma-4-E2B-it-qat-4bit",
                extraEOSTokens: ["<turn|>"]
            )
            displayName = "Gemma 4 E2B (QAT 4-bit)"
        default:
            configuration = ModelConfiguration(id: modelID)
            displayName = modelID
        }
    }

    public func prewarm() async throws {
        _ = try await container.get(configuration: configuration)
    }

    public func generate(_ request: WireGenerationRequest) -> AsyncThrowingStream<WireEvent, Error> {
        let (stream, continuation) = AsyncThrowingStream<WireEvent, Error>.makeStream()
        let configuration = self.configuration
        let box = container
        let task = Task {
            do {
                let container = try await box.get(configuration: configuration)
                let messages = TranscriptChat.messages(from: request.transcript)
                let maxTokens = request.options.maximumResponseTokens ?? 512
                let temperature = request.options.temperature

                let events = try await container.perform { context in
                    let chat: [Chat.Message] = messages.map { message in
                        switch message.role {
                        case .system: .system(message.text)
                        case .assistant: .assistant(message.text)
                        case .user: .user(message.text)
                        }
                    }
                    // Gemma 4's thinking is configurable, and a thought block
                    // rendered on camera is a killed take. The template kwarg
                    // is the belt; the rehearsal is what proves the template
                    // honours it, because nothing here can.
                    let input = try await context.processor.prepare(
                        input: UserInput(chat: chat, additionalContext: ["enable_thinking": false])
                    )
                    var parameters = GenerateParameters(maxTokens: maxTokens)
                    if let temperature {
                        parameters.temperature = Float(temperature)
                    }
                    return try MLXLMCommon.generate(input: input, parameters: parameters, context: context)
                }

                for await event in events {
                    if Task.isCancelled { break }
                    switch event {
                    case .chunk(let chunk):
                        continuation.yield(.responseAppend(entryID: nil, text: chunk, segmentID: nil, tokenCount: 1))
                    case .info(let info):
                        continuation.yield(.usage(
                            inputTokens: info.promptTokenCount,
                            outputTokens: info.generationTokenCount
                        ))
                    default:
                        break
                    }
                }
                continuation.yield(.finished(Task.isCancelled ? .cancelled : .complete))
                continuation.finish()
            } catch {
                continuation.yield(.finished(.error("\(error)")))
                continuation.finish()
            }
        }
        continuation.onTermination = { _ in task.cancel() }
        return stream
    }
}

/// One loaded model container shared across generations.
private actor ContainerBox {
    private var container: ModelContainer?

    func get(configuration: ModelConfiguration) async throws -> ModelContainer {
        if let container { return container }
        let loaded = try await #huggingFaceLoadModelContainer(configuration: configuration)
        container = loaded
        return loaded
    }
}
