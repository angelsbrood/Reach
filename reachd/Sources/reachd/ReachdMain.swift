import Darwin
import ReachDaemon

/// The executable boundary runs before ArgumentParser and before anything
/// touches MLX. Replacing this process gives Foundation and every linked
/// dependency one canonical `Bundle.main` without a wrapper process or a
/// second resource layout.
@main
enum ReachdMain {
    static func main() async {
        normalizeLaunchIdentity()
        await Reachd.main()
    }

    private static func normalizeLaunchIdentity() {
        guard case .reexecute(let canonicalPath) = LaunchIdentity.currentDecision() else {
            return
        }

        let failure = LaunchIdentity.replaceCurrentProcess(with: canonicalPath)

        // The current process is already usable for non-GPU commands. A
        // replacement race must not make status, doctor, or service install
        // less useful than they were before launch normalization existed.
        let detail = String(cString: strerror(failure))
        fputs(
            "[reachd] could not normalize executable path to \(canonicalPath): \(detail); continuing in place\n",
            stderr
        )
    }
}
