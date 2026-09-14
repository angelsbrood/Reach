import Foundation
import HostClientContract
import RecoveryAuthorityContract

extension ClientSnapshot {
    func nativePrefix(_ live:LiveClientRecord) throws -> NativeRecoveryPrefix {
        guard live.retention?.version==3,let acceptance=live.retention?.acceptance else { throw ClientError.unavailable }
        let admission=try acceptance.admission(),c=try AuthorityCodec.decode(ClientContext.self,context)
        guard context==admission.context,let execution=admission.scope.provision.execution,
              execution.operation==c.operation else { throw ClientError.unavailable }
        var prefix=try NativeRecoveryPrefix(context:context,provider:execution.provider,providerDigest:admission.providerDigest,
            request:c.request,operation:c.operation,route:c.route)
        for batch in batches { try prefix.append(.init(first:batch.first,count:batch.count,commit:batch.commit,bytes:batch.bytes)) }
        guard prefix.high==high,prefix.terminal==terminal,prefix.registrations==calls.count,
              calls.count==live.calls,calls.allSatisfy({!$0.intent && $0.outcome==nil}) else { throw ClientError.unavailable }
        return prefix
    }
}
