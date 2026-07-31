import Foundation
import ReachWire

/// How a read of the next frame ended — because there are three ways and the
/// shape everybody reached for handles two.
///
/// `guard let raw = try await frames.next() else { … }` covers a stream that
/// closed cleanly, which returns nil and lands in the `else`. It does not cover
/// a stream that was reset, or one **this side cancelled**: those THROW out of
/// `next()`, and **a throw cannot reach a `guard`'s `else`.** It goes to
/// whatever outer catch exists, and the sentence written for exactly that
/// ending stops being reachable — by construction, in precisely the case it
/// was written for.
///
/// Found first in the daemon (7d), where a ceremony that fully succeeded came
/// out of the log as `POSIXErrorCode 57`. Found again by grepping for the shape
/// afterwards, at the one site whose text a person reads on a phone screen
/// mid-ceremony. That is why this lives here rather than in either of them:
/// the keeper is an app target with no tests, and the daemon is a module it
/// cannot import, so the only home where one reader can serve both — and be
/// held to a test — is beside the stream itself.
///
/// **The prose stays with the caller.** Only the caller knows which frame it
/// was waiting for and what is at stake if it never comes; a shared sentence
/// would have to be vague in both places to be true in either.
public enum FrameEnding: Sendable {
    case frame(RawFrame)
    case closed
    case broke(any Error)

    /// Reads one frame and returns how the read ended.
    ///
    /// It cannot throw, and that is the whole point — the signature is the
    /// guarantee, so a caller's `guard case .frame` handles every ending there
    /// is. Takes the iterator `inout` because `AsyncThrowingStream`'s iterator
    /// is not Sendable and a second one over shared storage is not a second
    /// reader.
    public static func next(
        from iterator: inout AsyncThrowingStream<RawFrame, Error>.AsyncIterator
    ) async -> FrameEnding {
        do {
            guard let raw = try await iterator.next() else { return .closed }
            return .frame(raw)
        } catch {
            return .broke(error)
        }
    }
}
