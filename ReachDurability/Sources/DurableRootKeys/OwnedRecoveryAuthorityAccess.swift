import Foundation
import Security

/// Explicit original-key access inside a descriptor-pinned root and a held role
/// lease. Time eligibility is supplied separately by the caller; it cannot unlock
/// a container or stand in for any original key confirmation.
public enum OwnedRecoveryAuthorityAccess {
    public static func perform(_ selected: OwnedContainerSelection, expectedDigest: String, current: OwnedAfterBootRoot,
        credential: UnlockCredential, verifySelection: () throws -> Void, operation: (any RootKeyProvider) throws -> Void) throws {
        try OwnedFileKeychain.disableInteraction(); try selected.validate()
        try RootKeyCodec.require(selected.digest() == expectedDigest && current.original == selected.identity)
        try selected.executable.validate()
        guard let running=Bundle.main.executableURL?.path else { throw RootKeyError.invalid }
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(running) == selected.executable.path)
        try current.check(); _=try current.inspect(selected.identity.container); try verifySelection()
        let metadata=try KeychainMetadata.read(), container=try OwnedFileKeychain.openExisting(at:selected.identity.container)
        func unlocked() throws -> Bool {
            var value:SecKeychainStatus=0
            try RootKeyCodec.check(SecKeychainGetStatus(container.reference,&value),"authority-key-status")
            return value & kSecUnlockStateStatus != 0
        }
        func relock() throws {
            try OwnedFileKeychain.disableInteraction()
            try RootKeyCodec.check(SecKeychainLock(container.reference),"authority-key-relock")
        }
        let initiallyUnlocked=try unlocked()
        try credential.consume { bytes in
            try OwnedRetirementTransaction.run(initiallyUnlocked:initiallyUnlocked,unlock:{
                try RootKeyCodec.check(bytes.withUnsafeBytes { SecKeychainUnlock(container.reference,UInt32(bytes.count),$0.baseAddress!,true) },"authority-key-unlock")
            },isUnlocked:unlocked,containerPresent:{ try current.check(); _=try current.inspect(selected.identity.container); return true },relock:relock,operation:{
                try current.check(); try RootKeyCodec.require(OwnedFileKeychain.path(container.reference) == selected.identity.container)
                let provider=MacKeychainProvider(container:container)
                for (reference,confirmation) in zip(selected.references,selected.confirmations) {
                    let key=try provider.load(reference,binding:selected.binding)
                    try key.confirm(confirmation,reference:reference,binding:selected.binding)
                }
                try verifySelection(); try current.check()
                try RootKeyCodec.require(KeychainMetadata.read() == metadata)
                try operation(provider)
                try verifySelection(); try current.check()
                if !initiallyUnlocked { try relock(); try RootKeyCodec.require(!unlocked()) }
                try RootKeyCodec.require(KeychainMetadata.read() == metadata)
            })
        }
    }
}
