import Foundation
import Glibc
import ReachLinuxService

@main
struct ReachLinuxMain {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 1 else {
                throw LinuxServiceConfigurationError.invalid("this service accepts no command arguments")
            }
            try await LinuxServiceRuntime.runProduction()
        } catch {
            FileHandle.standardError.write(Data("[reachd-linux] \(error)\n".utf8))
            exit(LinuxServiceExitStatus.code(for: error))
        }
    }
}
