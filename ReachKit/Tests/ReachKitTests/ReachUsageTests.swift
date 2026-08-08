import Foundation
import Testing
@testable import ReachKit

@Suite struct ReachUsageTests {
    @Test func modelCopiesShareOneMonitorAndNewModelsDoNot() {
        let model = ReachLanguageModel(configuration: .init())
        let copy = model
        let other = ReachLanguageModel(configuration: .init())

        #expect(model.usage === copy.usage)
        #expect(model.usage !== other.usage)
    }

    @Test func recordUpdatesLatestAndEveryLiveSubscriber() async {
        let monitor = ReachUsageMonitor()
        let firstStream = await monitor.updates()
        let secondStream = await monitor.updates()
        var first = firstStream.makeAsyncIterator()
        var second = secondStream.makeAsyncIterator()
        let expected = ReachGenerationUsage(
            requestID: UUID(),
            inputTokens: 7,
            outputTokens: 11
        )

        await monitor.record(expected)

        #expect(await first.next() == expected)
        #expect(await second.next() == expected)
        #expect(await monitor.latest == expected)
    }

    @Test func subscriberBufferKeepsTheNewestSixtyFourCompletions() async {
        let monitor = ReachUsageMonitor()
        let stream = await monitor.updates()
        var iterator = stream.makeAsyncIterator()
        let ids = (0 ..< 65).map { _ in UUID() }

        for (index, id) in ids.enumerated() {
            await monitor.record(ReachGenerationUsage(
                requestID: id,
                inputTokens: index,
                outputTokens: index
            ))
        }

        let firstBuffered = await iterator.next()
        #expect(firstBuffered?.requestID == ids[1])
        #expect(firstBuffered?.inputTokens == 1)
        #expect(await monitor.latest?.requestID == ids[64])
    }

    @Test func aCompletedRequestIsPublishedOnlyOnce() async {
        let monitor = ReachUsageMonitor()
        let stream = await monitor.updates()
        var iterator = stream.makeAsyncIterator()
        let id = UUID()
        let first = ReachGenerationUsage(requestID: id, inputTokens: 2, outputTokens: 3)
        let replay = ReachGenerationUsage(requestID: id, inputTokens: 200, outputTokens: 300)

        await monitor.record(first)
        await monitor.record(replay)

        #expect(await iterator.next() == first)
        #expect(await monitor.latest == first)
    }

    @Test func concurrentCompletionsRemainCorrelatedToTheirRequestIDs() async {
        let monitor = ReachUsageMonitor()
        let stream = await monitor.updates()
        var iterator = stream.makeAsyncIterator()
        let values = [
            ReachGenerationUsage(requestID: UUID(), inputTokens: 5, outputTokens: 8),
            ReachGenerationUsage(requestID: UUID(), inputTokens: 13, outputTokens: 21),
        ]

        await withTaskGroup(of: Void.self) { group in
            for value in values {
                group.addTask { await monitor.record(value) }
            }
        }

        let received = [await iterator.next(), await iterator.next()].compactMap { $0 }
        #expect(Set(received.map(\.requestID)) == Set(values.map(\.requestID)))
        #expect(Set(received.map(\.inputTokens)) == Set(values.map(\.inputTokens)))
        #expect(Set(received.map(\.outputTokens)) == Set(values.map(\.outputTokens)))
    }
}
