import MLXLMCommon
import ReachWire
import Testing
@testable import ReachDaemon

@Suite struct UnconstrainedSamplingTests {
    private func resolve(
        temperature: Double? = nil,
        sampling: WireSampling? = nil,
        maxTokens: Int = 73
    ) -> GenerateParameters {
        UnconstrainedSampling.parameters(
            options: WireGenerationOptions(
                temperature: temperature,
                sampling: sampling
            ),
            maxTokens: maxTokens
        )
    }

    @Test func unsetControlsPreserveProviderDefaults() {
        let parameters = resolve()
        #expect(parameters.maxTokens == 73)
        #expect(parameters.temperature == 0.6)
        #expect(parameters.topK == 0)
        #expect(parameters.topP == 1)
        #expect(parameters.seed == nil)
    }

    @Test func temperatureIsClampedAndExplicitZeroIsGreedy() {
        #expect(resolve(temperature: -0.25).temperature == 0)
        #expect(resolve(temperature: 0).temperature == 0)
        #expect(resolve(temperature: 1).temperature == 1)
    }

    @Test func greedyOverridesTemperature() {
        let parameters = resolve(temperature: 1, sampling: .greedy)
        #expect(parameters.temperature == 0)
    }

    @Test func topKUsesCallerOrDefaultTemperatureAndForwardsSeed() {
        let defaulted = resolve(sampling: .topK(40, seed: 7))
        #expect(defaulted.temperature == 0.6)
        #expect(defaulted.topK == 40)
        #expect(defaulted.seed == 7)

        let explicit = resolve(temperature: 0.2, sampling: .topK(3, seed: UInt64.max))
        #expect(explicit.temperature == 0.2)
        #expect(explicit.topK == 3)
        #expect(explicit.seed == UInt64.max)
    }

    @Test func nonpositiveTopKDisablesOnlyThatFilter() {
        for k in [0, -1] {
            let parameters = resolve(sampling: .topK(k, seed: 11))
            #expect(parameters.topK == 0)
            #expect(parameters.temperature == 0.6)
            #expect(parameters.seed == 11)
        }
    }

    @Test func topPBoundariesHaveExactMeanings() {
        for probability in [0.0, -0.5] {
            let parameters = resolve(
                temperature: 1,
                sampling: .topP(probability, seed: 13)
            )
            #expect(parameters.temperature == 0)
            #expect(parameters.seed == 13)
        }

        let filtered = resolve(sampling: .topP(0.9, seed: 17))
        #expect(filtered.topP == Float(0.9))
        #expect(filtered.seed == 17)

        for probability in [1.0, 2.0] {
            let parameters = resolve(sampling: .topP(probability, seed: 19))
            #expect(parameters.topP == 1)
            #expect(parameters.seed == 19)
        }
    }

    @Test func explicitZeroTemperatureWinsOverFilters() {
        #expect(resolve(temperature: 0, sampling: .topK(40, seed: 1)).temperature == 0)
        #expect(resolve(temperature: 0, sampling: .topP(0.9, seed: 1)).temperature == 0)
    }

    @Test func everyResolutionProducesFreshParameters() {
        var first = resolve(sampling: .topK(8, seed: 23))
        first.topK = 1
        first.seed = 99

        let second = resolve(sampling: .topK(8, seed: 23))
        #expect(second.topK == 8)
        #expect(second.seed == 23)
    }
}
