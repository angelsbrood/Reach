import Foundation
import DurableRootKeys
import DurableStoreBootstrap
import BootstrapFixtures
import Darwin

do {
    let config = try BootstrapPipe.read()
    guard config.action == "control", let workers = config.workers else { throw BootstrapError.invalid }
    _ = try BootstrapFixture.base(); let access = try BootstrapFixture.access(workers)
    try OwnedFileKeychain.disableInteraction()
    let initial = try KeychainMetadata.read()
    var containers: [String:OwnedFileKeychain] = [:], ownedPaths = Set<String>(), added = 0
    var first = BootstrapMessage("ready"); first.metadataPreserved = true; try BootstrapPipe.write(first)
    while true {
        let request = try BootstrapPipe.read()
        do {
            var response = BootstrapMessage("ok"); let slot = request.slot ?? "primary"
            if request.action == "close" {
                guard containers.isEmpty else { throw BootstrapError.invalid }; try BootstrapPipe.write(.init("closed")); break
            }
            switch request.action {
            case "create":
                guard containers[slot] == nil, containers.count < 2, let password = request.password else { throw BootstrapError.invalid }
                let path = try BootstrapFixture.container(slot), container = try OwnedFileKeychain.create(at:path,password:password)
                containers[slot] = container; ownedPaths.insert(path)
                try RootKeyCodec.require(KeychainMetadata.read().preserves(initial,owned:ownedPaths))
                response.metadataPreserved = true
            case "lock", "unlock":
                guard let container = containers[slot] else { throw BootstrapError.invalid }
                if request.action == "lock" { try container.lockOwned() }
                else { guard let password = request.password else { throw BootstrapError.invalid }; try container.unlockOwned(password:password) }
            case "load", "delete", "replace", "add":
                guard let container = containers[slot], let reference = request.reference, let binding = request.binding else { throw BootstrapError.invalid }
                let provider = MacKeychainProvider(container:container,initialAccess:access)
                if request.action == "delete" || request.action == "replace" { try provider.deleteExact(reference,binding:binding) }
                if request.action == "replace" || request.action == "add" {
                    guard added < 32 else { throw BootstrapError.invalid }
                    _ = try provider.create(reference,binding:binding); added += 1
                }
                if request.action == "load" {
                    let key = try provider.load(reference,binding:binding)
                    if let expected = request.confirmation { try key.confirm(expected,reference:reference,binding:binding) }
                }
            case "cleanup":
                // These non-null references came only from this process's successful fresh creates.
                for container in containers.values { try container.deleteOwned() }; containers.removeAll()
                let final = try KeychainMetadata.read()
                try RootKeyCodec.require(final == initial && final.excludes(ownedPaths))
                response.metadataPreserved = true; response.registrationAbsent = true
            default: throw BootstrapError.invalid
            }
            try BootstrapPipe.write(response)
        } catch { try BootstrapPipe.write(.failure(error)) }
    }
} catch { var response = BootstrapMessage.failure(error); response.action = "unavailable"; try? BootstrapPipe.write(response); exit(1) }
