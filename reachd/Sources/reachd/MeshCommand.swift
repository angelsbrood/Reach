import ArgumentParser
import Foundation
import ReachDaemon

struct Mesh: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mesh",
        abstract: "Compile and visibly apply the login-owned mesh intent.",
        subcommands: [Stage.self, Apply.self]
    )

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
