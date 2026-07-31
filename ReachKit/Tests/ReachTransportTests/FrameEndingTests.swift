import Foundation
import ReachWire
import Testing
@testable import ReachTransport

/// The three endings, and that reading one cannot throw.
///
/// The last part is the load-bearing one and it is enforced by the signature
/// rather than by anything below: `FrameEnding.next` is not `throws`, so a
/// caller's `guard case .frame` is exhaustive by construction. That is the
/// entire defect this type exists to close — `guard let raw = try await
/// frames.next() else` reaches its `else` on a clean close and never on a
/// reset, so the sentence written for a torn ceremony was unreachable in
/// exactly the case it described, on both halves of the daemon and on the
/// keeper's screen.
///
/// No network here on purpose: a hand-fed stream can produce all three endings
/// deterministically, and the live one — a cancelled read — is measured in the
/// daemon's `LoopbackTransportTests` where a mutual-TLS fixture already stands.
@Suite struct FrameEndingTests {
    private func makeStream() -> (
        AsyncThrowingStream<RawFrame, Error>.Continuation,
        AsyncThrowingStream<RawFrame, Error>
    ) {
        let (stream, continuation) = AsyncThrowingStream<RawFrame, Error>.makeStream()
        return (continuation, stream)
    }

    @Test func aFrameThatArrivesComesBackAsItself() async {
        let (continuation, stream) = makeStream()
        var iterator = stream.makeAsyncIterator()
        continuation.yield(RawFrame(type: Ping.frameType, body: Data()))
        guard case .frame(let raw) = await FrameEnding.next(from: &iterator) else {
            Issue.record("a yielded frame did not come back as .frame")
            return
        }
        #expect(raw.type == Ping.frameType)
    }

    @Test func aCleanCloseIsClosed() async {
        let (continuation, stream) = makeStream()
        var iterator = stream.makeAsyncIterator()
        continuation.finish()
        guard case .closed = await FrameEnding.next(from: &iterator) else {
            Issue.record("a stream that finished cleanly did not read as .closed")
            return
        }
    }

    /// The ending that used to escape. A reset finishes the stream *throwing*,
    /// and a throw cannot reach a `guard`'s `else` — so this is the case that
    /// went to an outer catch and printed a socket where a situation belonged.
    /// It must arrive as a value like the other two, and it must still carry
    /// the transport's own words: they are the part that names what happened,
    /// and `ErrorLegibilityTests` holds the daemon's sentence to them.
    @Test func aResetIsBrokeAndKeepsTheTransportsWords() async {
        let (continuation, stream) = makeStream()
        var iterator = stream.makeAsyncIterator()
        continuation.finish(
            throwing: TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")
        )
        guard case .broke(let error) = await FrameEnding.next(from: &iterator) else {
            Issue.record("a stream that finished throwing did not read as .broke")
            return
        }
        #expect("\(error)".contains("Socket is not connected"))
    }

    /// Frames already buffered are delivered before the failure that ended the
    /// stream — so a reader that treats a torn stream as "nothing more to read"
    /// would drop a frame the peer did send. The daemon's confirming read
    /// depends on this ordering: the confirmation and the reset arrive in that
    /// order when a phone confirms and hangs up on the frame's heels.
    @Test func aFrameBufferedBeforeTheBreakArrivesFirst() async {
        let (continuation, stream) = makeStream()
        var iterator = stream.makeAsyncIterator()
        continuation.yield(RawFrame(type: Ping.frameType, body: Data()))
        continuation.finish(throwing: TransportError.streamClosed)

        guard case .frame = await FrameEnding.next(from: &iterator) else {
            Issue.record("the buffered frame was lost to the break behind it")
            return
        }
        guard case .broke = await FrameEnding.next(from: &iterator) else {
            Issue.record("the break did not follow the frame it was queued behind")
            return
        }
    }
}
