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
              progress.proposals.count<=1,progress.completed.count<=1,progress.completedCalls.count<=1,(0...1).contains(progress.deliveredCalls),
              progress.probe.namespace==b.namespace,progress.probe.promptTokens==b.originalTokens.count,
              !["callReady","interpass"].contains(progress.phase) else { throw AuthorityError.scope }
        let combined=b.responseSchema != nil
        guard combined ? progress.proseDelivered==0 && progress.route != "prose" : progress.route != "schema" && progress.schemaReturnedBytes==0 else { throw AuthorityError.scope }
        if let pass=progress.current {
            guard pass.index==0,(1...512).contains(pass.tokens.count) else { throw AuthorityError.scope }
            if pass.kind=="schema" {
                guard combined,progress.route=="schema",progress.proposals.isEmpty,pass.tokens==b.originalTokens,
                      pass.proposalID==nil,pass.messagesDigest==storeHash(Data()),progress.schemaReturnedBytes==progress.whole.count else { throw AuthorityError.scope }
            } else {
                guard pass.kind=="tool",progress.route=="calls",progress.proposals.count==1,
                      pass.proposalID==progress.proposals[0].id,progress.schemaReturnedBytes==0 else { throw AuthorityError.scope }
            }
        } else {
            guard progress.completed.isEmpty,progress.schemaReturnedBytes==0 else { throw AuthorityError.scope }
        }
        if let completed=progress.completed.first {
            guard let pass=progress.current,let guided=progress.guided,guided.terminalReason=="complete",guided.interceptedEndings==1,
                  completed.kind==pass.kind,completed.index==pass.index,completed.inputDigest==pass.inputDigest,
                  completed.prompt==pass.tokens.count,completed.prompt==guided.promptTokens,
                  completed.output==guided.sampledTokens+guided.forcedTokens else { throw AuthorityError.scope }
            if completed.kind=="tool" {
                guard progress.completedCalls.count==1,let call=progress.completedCalls.first,
                      progress.proposals.count==1,call.name==b.tools[0].name,progress.proposals[0].name==call.name else { throw AuthorityError.scope }
            } else { guard completed.kind=="schema",progress.completedCalls.isEmpty else { throw AuthorityError.scope } }
        } else { guard progress.completedCalls.isEmpty else { throw AuthorityError.scope } }
        guard progress.inputTokens==b.originalTokens.count+progress.completed.reduce(0,{$0+$1.prompt}),
              progress.outputTokens==progress.probe.generationTokens+progress.completed.reduce(0,{$0+$1.output}) else { throw AuthorityError.scope }
    }
    /// At finalReady the exact selected branch, accepted call and completed-pass
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
        } else if prior.route=="schema" {
            guard b.responseSchema != nil,prior.proposals.isEmpty,prior.completedCalls.isEmpty,prior.completed.count==1,
                  prior.completed[0].kind=="schema",prior.deliveredCalls==0 else { throw AuthorityError.scope }
        } else {
            guard prior.route=="prose",b.responseSchema==nil,prior.proposals.isEmpty,prior.completed.isEmpty,prior.completedCalls.isEmpty else { throw AuthorityError.scope }
        }
        events += [.usage(inputTokens:prior.inputTokens,outputTokens:prior.outputTokens),.finished(.complete)]
        guard try storeEncode(events)==candidate.eventBytes else { throw AuthorityError.scope }
    }
}
