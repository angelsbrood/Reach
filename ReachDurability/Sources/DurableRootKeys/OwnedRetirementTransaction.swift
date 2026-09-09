import Foundation

public enum OwnedAfterBootRetirementError: Error, Equatable { case refusedLocked, relockUnconfirmed }

/// Includes authorization, deletion and root removal in the relock boundary.
/// Tests inject failed/no-effect relock operations through this same transaction.
enum OwnedRetirementTransaction {
    static func run<T>(initiallyUnlocked: Bool, unlock: () throws -> Void,
        isUnlocked: () throws -> Bool, containerPresent: () throws -> Bool,
        relock: () throws -> Void, operation: () throws -> T) throws -> T {
        do {
            if !initiallyUnlocked {
                try unlock()
                guard try isUnlocked() else { throw OwnedAfterBootRetirementError.refusedLocked }
            }
            return try operation()
        } catch {
            // Available keys do not authenticate the password. Never lock a
            // container that this invocation found already unlocked.
            if initiallyUnlocked || (try? containerPresent()) == false { throw error }
            if (try? isUnlocked()) == false { throw OwnedAfterBootRetirementError.refusedLocked }
            do {
                try relock()
                guard try !isUnlocked() else { throw OwnedAfterBootRetirementError.relockUnconfirmed }
            } catch { throw OwnedAfterBootRetirementError.relockUnconfirmed }
            throw OwnedAfterBootRetirementError.refusedLocked
        }
    }
}
