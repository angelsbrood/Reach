import Foundation

/// Token counts for one generation that the cluster completed.
///
/// Counts describe actual model passes, not billing: a constrained tool call
/// may include both its private proposal and accepted replay passes.
public struct ReachGenerationUsage: Sendable, Equatable {
    public let requestID: UUID
    public let inputTokens: Int
    public let outputTokens: Int

    public init(requestID: UUID, inputTokens: Int, outputTokens: Int) {
        self.requestID = requestID
        self.inputTokens = inputTokens
        self.outputTokens = outputTokens
    }
}

/// Reach-owned observation of completed generation usage.
///
/// This deliberately does not bridge into Foundation Models' private usage
/// action. `latest` remains available even when no stream was subscribed;
/// each live subscriber buffers the newest 64 completions.
public actor ReachUsageMonitor {
    public private(set) var latest: ReachGenerationUsage?

    private var subscribers: [UUID: AsyncStream<ReachGenerationUsage>.Continuation] = [:]
    private var publishedRequestIDs: Set<UUID> = []
    private var publishedOrder: [UUID] = []
    private let deduplicationCapacity = 256

    public init() {}

    public func updates() -> AsyncStream<ReachGenerationUsage> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<ReachGenerationUsage>.makeStream(
            bufferingPolicy: .bufferingNewest(64)
        )
        subscribers[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.removeSubscriber(id) }
        }
        return stream
    }

    func record(_ usage: ReachGenerationUsage) {
        guard publishedRequestIDs.insert(usage.requestID).inserted else { return }
        publishedOrder.append(usage.requestID)
        if publishedOrder.count > deduplicationCapacity {
            publishedRequestIDs.remove(publishedOrder.removeFirst())
        }
        latest = usage
        for continuation in subscribers.values {
            continuation.yield(usage)
        }
    }

    private func removeSubscriber(_ id: UUID) {
        subscribers[id] = nil
    }
}
