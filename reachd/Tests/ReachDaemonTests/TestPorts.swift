import Darwin
import Foundation

/// Which hundred this test process's ports live in.
///
/// ⚠️ **The port literals below are global to the machine, and a second
/// `swift test` on the same Mac picks exactly the same ones.** Measured 7 Aug
/// over sixteen full runs with a sampler naming the holder of every 474xx port
/// once a second: **every** `Address already in use` was a *foreign* test
/// process — never this one, not once.
///
/// It is worth being precise about what that rules out, because the opposite
/// reading was written down twice. The suites do **not** race their own port
/// releases: no test in this target rebinds a port another test in the same
/// suite used, and `SpineTests` — where it always surfaces — hands each of its
/// six tests a port of its own. `.serialized` was never the relevant fact.
/// Nothing here needs a retry, a settle, or a wait for release; a neighbour
/// holds the port for the length of *its* test, seconds at a time, and a brief
/// rebind would mostly land inside that.
///
/// So the literals stay. They are still unique within the target, the
/// roadmap's grep still proves it, and `config.port` is still the port that
/// actually got bound — the properties the static-allocator design was chosen
/// for. What moves is the hundred they sit in, once per process:
/// `TestPorts.port(47418)` is "the suite's 47418, in whichever block this
/// process claimed".
///
/// The claim is a **bind, not a check** — a plain UDP socket on the block's
/// first port, held for the life of the process. Two processes cannot both
/// hold it and there is no window between deciding and taking, which a
/// probe-then-use would have. It also protects us from a neighbour running
/// *older* code: their unshifted 47400 block is one we never touch.
enum TestPorts {
    /// The suite's literal, relocated into this process's block.
    static func port(_ literal: UInt16) -> UInt16 {
        // The message deliberately carries no port literal of its own: the
        // roadmap's uniqueness grep reads every number in this target's code,
        // and a number in an error string reads to it as a second binder.
        precondition(
            (47400 ... 47499).contains(literal),
            "\(literal) is outside the block these suites allocate from — the "
                + "daemon's own ports and fixture data are not relocatable"
        )
        return base + (literal - 47400)
    }

    /// Blocks start at 48000 and stop short of 49152, where macOS hands out
    /// ephemeral ports and a bind would be racing the whole system rather than
    /// one neighbour.
    private static let candidates: [UInt16] = (0 ..< 11).map { 48000 + UInt16($0) * 100 }

    private static let base: UInt16 = {
        for candidate in candidates where hold(candidate) { return candidate }
        // Eleven concurrent test processes is not a thing that happens, and if
        // it ever does, saying so beats silently sharing a block with someone.
        let warning = "[reach-tests] every port block 48000–49000 is claimed; falling back "
            + "to the historical 47400 block, which another `swift test` may be using\n"
        FileHandle.standardError.write(Data(warning.utf8))
        return 47400
    }()

    /// Binds the block's first port and **leaks the descriptor deliberately**:
    /// the claim has to outlive this call and end only when the process does,
    /// so there is nothing to close and nowhere to keep it.
    private static func hold(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return false }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY
        let bound = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bound == 0 { return true }
        close(fd)
        return false
    }
}
