import Foundation
import Darwin
import DurableRootKeys
import DurableStoreBootstrap
import RequestPreparationContract

public enum IndependentRetirementBoundary { case authorized, containerDeleted }
public struct IndependentRetirementReport: Encodable {
    public let stage: String, role: String, bootstrap: String, receiptDigest: String
}

/// Explicit content-free ownership retirement. No generation owner, snapshot,
/// ticket decryption, model or retained initializer memory is used here.
public enum IndependentRoleLifecycle {
    public static func retire(receipt path: String, expectedDigest: String,
                              boundary: (IndependentRetirementBoundary) throws -> Void = { _ in }) throws -> IndependentRetirementReport {
        try TransportContract.currentUser()
        let (receipt, lease)=try RoleLifecycleLease.selectRetirement(receipt:path,expectedDigest:expectedDigest)
        defer { lease.close() }
        let core=receipt.ready.core, lifecycle=core.lifecycle!
        guard lifecycle.executable == (try LocalFiles.executable()) else { throw TransportRuntimeError.invalid }
        let result: (String) -> IndependentRetirementReport = {
            .init(stage:$0,role:core.role.rawValue,bootstrap:core.identifier,receiptDigest:expectedDigest)
        }
        guard try lifecycle.identity.present() else { return result("absent") }
        let phase=try lease.phase(receipt:receipt)
        guard phase == .ready || phase == .retiring else { throw TransportRuntimeError.invalid }
        let metadata=try KeychainMetadata.read()
        let owned: Set<String>=[core.container]
        // The current default must survive unchanged before any deletion.
        guard metadata.preservesUnrelated(metadata,owned:owned) else { throw TransportRuntimeError.invalid }
        if phase == .ready {
            try lease.confirmReady(receipt.ready)
            let actual=try RoleBootstrapStore.inspect(at:core.root,role:core.role)
            guard try RootKeyCodec.encode(actual,limit:64<<10) == RootKeyCodec.encode(receipt.ready,limit:64<<10) else { throw TransportRuntimeError.invalid }
            try validateSelection(core)
            try lease.lockJournal()
            let capability=try OwnedContainerRetirement.authenticate(receipt.container,expectedDigest:receipt.container.digest())
            try lease.beginRetirement(capability,receipt:receipt)
            try boundary(.authorized)
            try capability.deleteAuthenticated()
            try boundary(.containerDeleted)
        } else {
            // Retiring is selected under the same external lock before key deletion.
            // If the container remains, original confirmations are still mandatory.
            var info=stat()
            if lstat(core.container,&info)==0 {
                let capability=try OwnedContainerRetirement.authenticate(receipt.container,expectedDigest:receipt.container.digest())
                try capability.deleteAuthenticated(); try boundary(.containerDeleted)
            } else { guard errno == ENOENT else { throw TransportRuntimeError.invalid } }
        }
        let after=try KeychainMetadata.read()
        guard after.preservesUnrelated(metadata,owned:owned),after.excludes(owned) else { throw TransportRuntimeError.invalid }
        try removeSelectedRoot(core)
        try lease.finishRetirement(receipt:receipt)
        return result("retired")
    }
    static func validateSelection(_ core: RoleBootstrapCore) throws {
        let role: TransportRole=core.role == .host ? .host : .client
        let agreement=try IndependentPairAgreement.load(core.root+"/agreement.json")
        let selection=try RootKeyCodec.decode(TransportSelectionBinding.self,LocalFiles.read(core.root+"/"+role.rawValue+"/selection.json",maximum:64<<10),limit:64<<10)
        try selection.validate(role:role)
        guard selection.revision==IndependentContract.revision,selection.executable==core.lifecycle!.executable,
              selection.bootstrap==(try agreement.digest),selection.profileDigest==agreement.model.artifactDigest,
              selection.descriptor==agreement.model.descriptor,selection.pins==agreement.pins,selection.port==agreement.port,
              core.localID==(role == .host ? agreement.hostID : agreement.clientID),core.agreement==(try agreement.digest),
              core.selection==(try PreparationEncoding.digest(selection)) else { throw TransportRuntimeError.invalid }
    }
    private static func removeSelectedRoot(_ core: RoleBootstrapCore) throws {
        let identity=core.lifecycle!.identity
        guard try identity.present() else { throw TransportRuntimeError.invalid }
        let allowed=Set(["agreement.json",core.role.rawValue,"keys","bootstrap"])
            .union(core.role == .host ? ["model"] : ["tickets-"+core.identifier])
        let names=try FileManager.default.contentsOfDirectory(atPath:core.root)
        guard Set(names).isSubset(of:allowed) else { throw TransportRuntimeError.invalid }
        var entries:[(String,Bool)]=[],allocated:UInt64=0
        func scan(_ path:String,depth:Int) throws {
            guard depth<=12,entries.count<65536 else { throw TransportRuntimeError.invalid }
            var info=stat();guard lstat(path,&info)==0,info.st_uid==getuid(),info.st_blocks>=0 else { throw TransportRuntimeError.invalid }
            let directory=info.st_mode&S_IFMT == S_IFDIR
            guard directory || info.st_mode&S_IFMT == S_IFREG && info.st_nlink==1 else { throw TransportRuntimeError.invalid }
            guard info.st_mode&0o7777 == (directory ? 0o700 : 0o600) else { throw TransportRuntimeError.invalid }
            allocated+=UInt64(info.st_blocks)*512;guard allocated<=4<<30 else { throw TransportRuntimeError.invalid }
            if directory {
                for name in try FileManager.default.contentsOfDirectory(atPath:path) { try scan(path+"/"+name,depth:depth+1) }
            }
            guard entries.count<65536 else { throw TransportRuntimeError.invalid }
            entries.append((path,directory))
        }
        for name in names { try scan(core.root+"/"+name,depth:0) }
        for (path,directory) in entries {
            guard try identity.present() else { throw TransportRuntimeError.invalid }
            guard (directory ? rmdir(path) : unlink(path))==0 else { throw TransportRuntimeError.invalid }
        }
        guard try identity.present(),rmdir(core.root)==0 else { throw TransportRuntimeError.invalid }
        let parent=try RootKeyCodec.parent(core.root),fd=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard fd>=0 else { throw TransportRuntimeError.invalid };defer { _=Darwin.close(fd) }
        guard fsync(fd)==0 else { throw TransportRuntimeError.invalid }
    }
}
