import Foundation
import Darwin
import Security

public enum OwnedContainerUnlockError: Error, Equatable { case refused, verificationRefusedLocked, relockUnconfirmed }

/// The small state-changing boundary is also exercised with a failing relock
/// operation in focused tests. Production closures select only the owned handle.
enum OwnedUnlockTransaction {
    static func run(initiallyUnlocked: Bool, unlock: () throws -> Void,
                    isUnlocked: () throws -> Bool, confirm: () throws -> Void,
                    relock: () throws -> Void) throws -> Bool {
        if initiallyUnlocked {
            do { try confirm() } catch { throw OwnedContainerUnlockError.refused }
            return false // Original-key availability, not password authentication.
        }
        var reachedVerification = false
        do {
            try unlock()
            guard try isUnlocked() else { throw OwnedContainerUnlockError.refused }
            reachedVerification = true
            try confirm()
            return true
        } catch {
            let refusal: OwnedContainerUnlockError = reachedVerification ? .verificationRefusedLocked : .refused
            if (try? isUnlocked()) == false { throw refusal }
            do {
                try relock()
                guard try !isUnlocked() else { throw OwnedContainerUnlockError.relockUnconfirmed }
            } catch { throw OwnedContainerUnlockError.relockUnconfirmed }
            throw refusal
        }
    }
}

public enum OwnedContainerUnlock {
    /// The caller holds role/journal exclusion and authenticates the policy/core
    /// through verifySelection before and after the OS/key-confirmation boundary.
    public static func perform(_ selected: OwnedContainerSelection, expectedDigest: String,
                               policy: String, credential: UnlockCredential,
                               verifySelection: () throws -> Void) throws -> Bool {
        try OwnedFileKeychain.disableInteraction()
        try selected.validate()
        try RootKeyCodec.require(policy == UnlockCredential.policy && RootKeyCodec.digest(expectedDigest) &&
            selected.digest() == expectedDigest && selected.boot == RootKeyCodec.boot())
        try selected.executable.validate()
        guard let running = Bundle.main.executableURL?.path else { throw RootKeyError.invalid }
        try RootKeyCodec.require(RootKeyCodec.canonicalExisting(running) == selected.executable.path && selected.identity.present())
        try verifySelection()
        let container = try OwnedFileKeychain.openExisting(at: selected.identity.container)
        func isUnlocked() throws -> Bool {
            var value: SecKeychainStatus = 0
            try RootKeyCodec.check(SecKeychainGetStatus(container.reference, &value), "selected-unlock-status")
            return value & kSecUnlockStateStatus != 0
        }
        let initiallyUnlocked = try isUnlocked(), metadata = try KeychainMetadata.read()
        return try credential.consume { bytes in
            try OwnedUnlockTransaction.run(initiallyUnlocked: initiallyUnlocked, unlock: {
                try OwnedFileKeychain.disableInteraction()
                try RootKeyCodec.check(bytes.withUnsafeBytes {
                    SecKeychainUnlock(container.reference, UInt32(bytes.count), $0.baseAddress!, true)
                }, "explicit-selected-unlock")
            }, isUnlocked: isUnlocked, confirm: {
                try RootKeyCodec.require(selected.identity.present() && OwnedFileKeychain.path(container.reference) == selected.identity.container)
                let provider = MacKeychainProvider(container: container)
                for (reference, confirmation) in zip(selected.references, selected.confirmations) {
                    let key = try provider.load(reference, binding: selected.binding)
                    try key.confirm(confirmation, reference: reference, binding: selected.binding)
                }
                try verifySelection()
                try RootKeyCodec.require(KeychainMetadata.read() == metadata)
            }, relock: {
                try OwnedFileKeychain.disableInteraction()
                try RootKeyCodec.check(SecKeychainLock(container.reference), "relock-selected-unlock-failure")
            })
        }
    }
}
