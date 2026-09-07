import Foundation
import HostClientContract

extension DurableClientReceipts {
    /// The surviving supervisor freezes root/authority and marks establishment before launch.
    /// Established recovery never selects create, even if the original journal disappeared.
    public static func openHostJoin(at path: String, fresh: Bool, environment: ClientEnvironment, metadataKey: Data,
                                    clock: any ClientClock, authority: ClientAuthority,
                                    authorization: ClientAuthorization, hook: @escaping ClientFaultHook = { _ in }) throws -> (DurableClientReceipts, ClientHandle) {
        guard authority.context.revision == HandoffContract.revision else { throw HandoffError.invalid }
        try authorization.check(authority, now: clock.now())
        let owner = try DurableClientReceipts(path: path, create: fresh, environment: environment, metadataKey: metadataKey, clock: clock, hook: hook)
        do { return (owner, try owner.open(authority, authorization: authorization)) }
        catch { owner.close(); throw error }
    }
    public func acceptHostBatch(_ batch: HandoffBatch, requestedCursor: UInt64, handle: ClientHandle,
                                authority: ClientAuthority, authorization: ClientAuthorization) throws -> HandoffWitness {
        _ = try batch.last()
        _ = try accept(.init(firstSequence: batch.first, count: batch.count, providerCommit: batch.commit, eventBytes: batch.bytes, skipPrefix: batch.skip),
            requestedCursor: requestedCursor, handle: handle, authority: authority, authorization: authorization)
        return try hostWitness(handle, authority: authority, authorization: authorization)
    }
    /// Derive solely from authenticated selected journal state, including full skipped bytes.
    public func hostWitness(_ handle: ClientHandle, authority a: ClientAuthority, authorization auth: ClientAuthorization) throws -> HandoffWitness {
        guard a.context.revision == HandoffContract.revision else { throw HandoffError.invalid }
        try precheck(a, auth); let m = try refresh(); let i = try find(handle, a, m); let s = try snapshot(m.records[i])
        guard s.context == a.bytes else { throw HandoffError.invalid }
        var prefix = HandoffPrefix(context: s.context)
        for b in s.batches { try prefix.append(.init(first: b.first, count: b.count, commit: b.commit, bytes: b.bytes)) }
        for c in s.calls { try prefix.register(id: c.id, name: c.name, arguments: c.arguments) }
        let (batchDigest, callDigest) = prefix.digests()
        let witness = HandoffWitness(context: crHash(s.context), clientRoot: environment.rootID, revision: s.receiptRevision,
            high: s.high, terminal: s.terminal, prefix: batchDigest, registrations: s.calls.count, calls: callDigest)
        try witness.validate(expectedRoot: environment.rootID)
        try publish(a, auth, m); return witness
    }
}
