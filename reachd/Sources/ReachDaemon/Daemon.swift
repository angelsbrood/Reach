import Foundation
import ReachWire

public enum DaemonInfo {
    public static let version = "0.0.1"
    public static let wireVersion = Wire.version

    /// Runtime state root; never inside the repository.
    public static var stateDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Reach", isDirectory: true)
    }
}
