import ArgumentParser
import Foundation
import ReachDaemon

struct Mesh: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mesh",
        abstract: "Compile and visibly apply the login-owned mesh intent.",
        subcommands: [Stage.self, Apply.self, Relay.self]
    )

    struct Relay: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "relay",
            abstract: "Change login-owned relay intent without invoking privilege.",
            subcommands: [Set.self, Remove.self]
        )

        struct Set: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Configure one relay overlay; run `reachd mesh apply` separately."
            )

            @Option(name: .long, help: "Canonical private /24 for the relay overlay.")
            var network: String

            @Option(name: .long, help: "Canonical base64 WireGuard public key for the hub.")
            var hubPublicKey: String

            @Option(name: .long, help: "Stable numeric IPv4:port or [IPv6]:port hub endpoint.")
            var endpoint: String

            @Option(name: .long, help: "State directory to update. Defaults to the current Reach state.")
            var state: String?

            func run() async throws {
                let directory = state.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? DaemonInfo.stateDirectory
                let result = try MeshIntentStore.setRelay(
                    in: directory,
                    network: network,
                    hubPublicKey: hubPublicKey,
                    endpoint: endpoint
                )
                print("[reachd] mesh relay intent \(result.changed ? "updated" : "unchanged") at generation \(result.intent.generation)")
                print("[reachd] public digest \(result.intent.publicDigest)")
                print("[reachd] direct digest \(result.intent.directDigest)")
                if let digest = result.intent.relayDigest {
                    print("[reachd] relay digest \(digest)")
                }
                print("[reachd] run `reachd mesh apply` to ask the privileged owner to apply this intent")
            }
        }

        struct Remove: AsyncParsableCommand {
            static let configuration = CommandConfiguration(
                abstract: "Remove relay intent and return to canonical direct-only v1."
            )

            @Option(name: .long, help: "State directory to update. Defaults to the current Reach state.")
            var state: String?

            func run() async throws {
                let directory = state.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? DaemonInfo.stateDirectory
                let result = try MeshIntentStore.removeRelay(in: directory)
                print("[reachd] mesh relay intent \(result.changed ? "removed" : "already absent") at generation \(result.intent.generation)")
                print("[reachd] public digest \(result.intent.publicDigest)")
                print("[reachd] direct digest \(result.intent.directDigest)")
                print("[reachd] run `reachd mesh apply` to ask the privileged owner to apply this intent")
            }
        }
    }

    struct Stage: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Create one secure, bounded helper specification without applying it."
        )

        @Option(name: .long, help: "State directory to compile. Defaults to the current Reach state.")
        var state: String?

        func run() async throws {
            let directory = state.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? DaemonInfo.stateDirectory
            let result = try await Mesh.stage(in: directory)
            print("[reachd] mesh generation \(result.generation) staged at \(result.url.path)")
            print("[reachd] public digest \(result.digest)")
            print("[reachd] the file is mode 0600 and contains the host private key; apply it or remove it")
        }
    }

    struct Apply: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Stage intent and ask the installed root-owned helper to apply it."
        )

        @Option(name: .long, help: "State directory to compile. Defaults to the current Reach state.")
        var state: String?

        func run() async throws {
            let directory = state.map { URL(fileURLWithPath: $0, isDirectory: true) } ?? DaemonInfo.stateDirectory
            let result = try await Mesh.stage(in: directory)
            let operation = MeshOwner.applyOperation(input: result.url)
            print("[reachd] applying mesh generation \(result.generation), public digest \(result.digest)")
            print("[reachd] administrator argv: \(MeshOwner.renderOperation(executable: operation.executable, arguments: operation.arguments))")
            do {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: operation.executable)
                process.arguments = operation.arguments
                process.standardInput = FileHandle.standardInput
                process.standardOutput = FileHandle.standardOutput
                process.standardError = FileHandle.standardError
                try process.run()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    try? FileManager.default.removeItem(at: result.url)
                    throw ExitCode(process.terminationStatus)
                }
            } catch {
                try? FileManager.default.removeItem(at: result.url)
                throw error
            }
            print("[reachd] mesh generation \(result.generation) accepted by the privileged owner")
        }
    }

    private static func stage(in directory: URL) async throws -> (url: URL, generation: UInt64, digest: String) {
        let devices = await DeviceRegistry(directory: directory).all
        let specification = try MeshIntentStore.specification(in: directory, devices: devices)
        let url = try MeshIntentStore.stage(specification, in: directory)
        return (url, specification.intent.generation, specification.publicDigest)
    }
}
