import ReachIdentity
import ReachTransport
import ReachWire

/// The conforming model provider package. `ReachLanguageModel` and
/// `ReachExecutor` land with the spine.
public enum ReachKitInfo {
    public static let wireVersion = Wire.version
}
