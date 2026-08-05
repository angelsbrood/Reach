import Foundation
import ReachTransport
import ReachWire
import Testing
@testable import ReachKit

/// The three endings a read has, held to the standard the daemon's
/// `ErrorLegibilityTests` holds its own copy to.
///
/// This module's sentences are the ones nobody can watch: the Keeper's land on
/// a phone mid-ceremony and the daemon's land in a terminal, but ReachKit's go
/// to whatever app linked it — `ExampleModel` puts them on screen as
/// "no grant: \(error)" — and there is no rig that makes that reliably visible.
/// So the part that can be held automatically is held here: that the caller's
/// sentence survives, and that a break still carries the transport's own words,
/// which is the part naming what actually happened.
@Suite struct FrameEndingDetailTests {
    private static let sentence = "the cluster's hello ack never came"

    @Test func aCleanCloseSaysExactlyWhatTheCallerWrote() {
        #expect(FrameEnding.closed.detailing(Self.sentence) == Self.sentence)
    }

    @Test func aWrongFrameSaysExactlyWhatTheCallerWrote() {
        let ending = FrameEnding.frame(RawFrame(type: Ping.frameType, body: Data()))
        #expect(ending.detailing(Self.sentence) == Self.sentence)
    }

    /// The regression this exists to catch: someone tidying the helper down to
    /// a one-liner that returns the sentence for all three endings. It reads
    /// fine and it silently drops the fault.
    @Test func aBreakKeepsBothTheSentenceAndTheTransportsWords() {
        let ending = FrameEnding.broke(
            TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")
        )
        let rendered = ending.detailing(Self.sentence)
        #expect(rendered.hasPrefix(Self.sentence), "the caller's sentence did not survive: \(rendered)")
        #expect(rendered.contains("Socket is not connected"), "the transport's words were dropped: \(rendered)")
        #expect(rendered != Self.sentence)
    }

    /// The sentence belongs to the caller, so the helper must not have one of
    /// its own baked in — a hardcoded noun would pass every check above while
    /// telling one call site about another one's read.
    @Test func theHelperCarriesNoSentenceOfItsOwn() {
        let other = "the cluster never answered the session request for gemma-3n-e4b"
        #expect(FrameEnding.closed.detailing(other) == other)
        #expect(FrameEnding.broke(TransportError.streamClosed).detailing(other).hasPrefix(other))
    }

    /// `.sequence` carries two endings it was not written for, so its prefix
    /// has to be true of all three. "arrived out of order" was false of a
    /// stream that closed or broke: it did not arrive at all.
    @Test func theEnrollmentSequenceErrorDoesNotContradictItsOwnDetail() {
        let rendered = "\(ReachEnrollmentError.sequence(FrameEnding.closed.detailing(Self.sentence)))"
        #expect(!rendered.contains("out of order"), "the prefix contradicts the detail: \(rendered)")
        #expect(rendered.contains(Self.sentence))
        #expect(rendered.first?.isUppercase != true, "reads like a type name: \(rendered)")
    }
}
