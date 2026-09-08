import Foundation
import DurableRootKeys
import DurableStoreBootstrap
import DurableClientReceipts
import DurableSessionLifecycle
import RecoveryContract
import WireAdapterContract

/// Both explicit routes feed the same transport/native state machine with only
/// the current role's local resources. The client never constructs a host owner.
struct TransportResources {
    let selection: TransportSelectionBinding, audit: TransportRoleAudit, keys: BootstrapKeys
    let hostID: String, clientID: String, hostQuota: Int, clientQuota: Int
    let hostClock: any LifecycleClock, clientClock: any ClientClock
    let recovery: RecoveryBinding?, catalogReference: RootKeyReference?
    let legacyCore: BootstrapCore?, agreement: IndependentPairAgreement?
    let lifecycle: RoleLifecycleLease?
    init(root: String, role: TransportRole, independent: Bool) throws {
        if independent {
            let value=try AcquiredIndependentRoot(root:root,role:role), core=value.acquisition.ready.core
            lifecycle=value.lifecycle
            selection=value.selection; audit=value.audit; keys=value.acquisition.keys
            hostID=value.agreement.hostID;clientID=value.agreement.clientID;hostQuota=core.quota;clientQuota=core.quota
            let clock=try RoleMonotonicClock(origin:core.origin,epoch:core.epoch,boot:core.boot)
            hostClock=clock;clientClock=clock;legacyCore=nil;agreement=value.agreement
            recovery=role == .client ? .init(bootstrap:core.identifier,core:try core.binding(),clientRoot:clientID,host:hostID,localBoot:core.boot,localPolicy:core.policy,pair:core.agreement) : nil
            catalogReference=role == .host ? try core.reference(.hostCatalog) : nil
        } else {
            let value=try AcquiredTransportRoot(root,role:role),core=value.core
            guard value.selection.revision==TransportContract.revision else { throw TransportRuntimeError.invalid }
            lifecycle=nil
            selection=value.selection;audit=value.audit;keys=value.keys
            hostID=core.hostID;clientID=core.clientID;hostQuota=core.policy.hostQuota;clientQuota=core.policy.clientQuota
            hostClock=SystemLifecycleClock();clientClock=SystemClientClock();legacyCore=core;agreement=nil
            recovery=role == .client ? try BootstrapRecoveryBinding.make(core) : nil
            catalogReference=role == .host ? try core.reference(.hostCatalog) : nil
        }
    }
    func clientEnvironment() throws -> ClientEnvironment {
        try .init(rootID:clientID,clock:clientClock,quota:clientQuota,authorityMode:agreement == nil ? .legacy : .independent,
            pairDigest:agreement?.digest,retentionCap:agreement?.retentionCap ?? ClientLimits.session)
    }
}
