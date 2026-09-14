import Foundation
import MLX
import ReachWire
import ResumableMLXProvider
import WireAdapterContract
import RecoveryAuthorityContract

extension NativeRecoveryRuntime {
    /// Empirical qualification only: no witness, roots, tickets or originals.
    public static func probeGuidedFixture(model: String, prepared: String, report: String) throws {
        try LocalDurableRuntime.withCPU {
            let p=try SelectedArtifactProfile(at:model,nativeRecovery:true)
            let execution=try AuthorityCodec.decode(AuthorityExecution.self,LocalFiles.read(prepared,maximum:64<<10))
            let binding=try AuthorityCodec.decode(ProviderBinding.self,execution.provider)
            try validateFixture(binding)
            guard binding.lane.route == .guided else { throw AuthorityError.scope }
            let config=AdapterConfiguration(dialect:2,model:p.preparer.policy.descriptor.model,optIn:true,ready:true)
            let live=try ResumableMLXProvider.prepare(binding:binding,runtime:p.runtime(binding,configuration:config),owner:"guided-feasibility",credit:ResumableMLXProvider.reservationBytes)
            defer { live.close() }
            guard var selected=try live.pendingCandidate() else { throw AuthorityError.state }
            try live.acceptCommit(selected.commit,owner:"guided-feasibility")
            var progress=[try live.committedGuidedProgress(selected,tokenizer:p.tokenizer)]
            for _ in 0..<32 where !live.isTerminal {
                guard let next=try live.advance(owner:"guided-feasibility",current:selected.commit,credit:ResumableMLXProvider.reservationBytes) else { throw AuthorityError.state }
                try live.acceptCommit(next.commit,owner:"guided-feasibility"); selected=next
                progress.append(try live.committedGuidedProgress(next,tokenizer:p.tokenizer))
            }
            let cut=progress.contains { $0.terminalReason == nil && $0.consumedTokens>1 && $0.pendingTokens>0 && !$0.cumulativeEmittedBytes.isEmpty && $0.modelOffsets.allSatisfy { $0>0 } }
            guard cut, let end=progress.last, end.terminalReason == "complete", end.interceptedEndings == 1,
                  end.pendingTokens == 0, end.consumedTokens <= 32 else { throw AuthorityError.state }
            struct Report: Encodable {
                let stage="guided-fixture", beforeOriginals=true, cutFound:Bool
                let provider:ProviderBinding, progress:[ProviderGuidedProgress], nativeCalls:Int, nativePeak:Int
            }
            let data=try AuthorityCodec.encode(Report(cutFound:cut,provider:binding,progress:progress,nativeCalls:p.observations.reduce(0){$0+$1.calls},nativePeak:Memory.peakMemory))
            guard data.count <= 64<<10, Memory.peakMemory <= 128<<20 else { throw AuthorityError.state }
            try LocalFiles.writeNew(data,to:report); try FileHandle.standardOutput.write(contentsOf:data+Data([10]))
        }
    }
}
