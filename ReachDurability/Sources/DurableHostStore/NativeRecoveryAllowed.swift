import Foundation
import ReachWire
import ResumableMLXProvider
import RecoveryAuthorityContract

/// Qualification bounds over an already acknowledged, fully validated child.
/// No native algorithm, request preparation or stored representation changes.
public enum NativeRecoveryAllowed {
    public static func validate(_ progress:ProviderAllowedProgress,binding:ProviderBinding) throws {
        try NativeRecoveryBinding.validate(binding)
        guard case .allowed(let b)=binding.lane,
              progress.proposals.count<=1,progress.completedCalls.count<=1,progress.deliveredCalls<=1,
              progress.probe.namespace==b.namespace,progress.probe.promptTokens==b.originalTokens.count,
              progress.route != "schema",!["callReady","interpass"].contains(progress.phase) else { throw AuthorityError.scope }
        if let pass=progress.current {
            guard pass.kind=="tool",pass.index==0,(1...512).contains(pass.tokens.count),
                  progress.proposals.count==1,pass.proposalID==progress.proposals[0].id else { throw AuthorityError.scope }
        }
        if let call=progress.completedCalls.first {
            guard progress.proposals.count==1,call.name==b.tools[0].name,progress.proposals[0].name==call.name,
                  let pass=progress.current,let guided=progress.guided,guided.terminalReason=="complete",guided.interceptedEndings==1,
                  progress.inputTokens==b.originalTokens.count+pass.tokens.count,
                  progress.outputTokens==progress.probe.generationTokens+guided.sampledTokens+guided.forcedTokens else { throw AuthorityError.scope }
        } else {
            guard progress.inputTokens==b.originalTokens.count,progress.outputTokens==progress.probe.generationTokens else { throw AuthorityError.scope }
        }
    }
    /// At finalReady the exact selected proposal, accepted call and aggregate
    /// native usage are authenticated before their durable/public final batch.
    public static func validateFinalBatch(_ candidate:ProviderCandidate,prior:ProviderAllowedProgress,binding:ProviderBinding) throws {
        try validate(prior,binding:binding)
        guard prior.phase=="finalReady" else { return }
        guard case .allowed(let b)=binding.lane,prior.outcome=="complete" else { throw AuthorityError.scope }
        var events:[WireEvent]=[]
        if prior.route=="calls" {
            guard prior.proposals.count==1,prior.completedCalls.count==1,prior.deliveredCalls==0 else { throw AuthorityError.scope }
            let selected=prior.proposals[0],call=prior.completedCalls[0]
            events.append(.toolCallAppendArguments(entryID:b.entryID,id:selected.id,name:call.name,content:call.argumentsJSON,tokenCount:1))
        } else { guard prior.route=="prose",prior.proposals.isEmpty,prior.completedCalls.isEmpty else { throw AuthorityError.scope } }
        events += [.usage(inputTokens:prior.inputTokens,outputTokens:prior.outputTokens),.finished(.complete)]
        guard try storeEncode(events)==candidate.eventBytes else { throw AuthorityError.scope }
    }
}
