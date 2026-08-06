import Foundation
import Testing

@testable import ReachKit

/// The refusal a person actually reads when nothing answered.
///
/// What it replaced said "no reachable cluster address (1 dialed)", and on a
/// cold start that count was always exactly 1 — the one structured thing in
/// the sentence carried no signal at all. These hold the two things the new
/// case has to get right: it counts roads truthfully, and it tells the two
/// situations apart, because they have different next actions.
@Suite struct ReachErrorSentenceTests {
    /// A restart mid-answer used to read `the cluster refused this
    /// (reattach-rejected): unknownSession` under half an answer — the wrong
    /// event, in the daemon's private vocabulary, with no next action. These
    /// hold the three things the replacement has to do.
    @Test func aLostAnswerSaysItStoppedRatherThanThatItWasRefused() {
        let sentence = "\(ReachError.generationLost("the cluster has no session by that name"))"
        #expect(sentence.contains("stopped partway"))
        #expect(!sentence.contains("refused"), "the cluster did not decline anything; it stopped holding it")
    }

    @Test func aLostAnswerSaysWhatToDoNext() {
        let sentence = "\(ReachError.generationLost("the daemon holding it restarted"))"
        #expect(sentence.lowercased().contains("asking again"))
    }

    @Test func aLostAnswerKeepsTheClustersOwnReason() {
        // The wire's reason beats one invented here, and it is the only part
        // that can tell an idle eviction from a restart.
        let reason = "it did not outlive a restart"
        #expect("\(ReachError.generationLost(reason))".contains(reason))
    }

    @Test func aLostAnswerDoesNotReadLikeAnUnreachableCluster() {
        // Different situations, different next actions: one is "ask again",
        // the other is "bring a road up". A reader who confuses them does the
        // wrong thing, so the sentences must not converge.
        let lost = "\(ReachError.generationLost("the daemon holding it restarted"))"
        #expect(!lost.contains("no road reached the cluster"))
        #expect(!lost.contains("mesh tunnel"))
        #expect(lost != "\(ReachError.unreachable(roads: 3, stored: .known))")
    }

    @Test func oneRoadIsNotCalledOneRoads() {
        let sentence = "\(ReachError.unreachable(roads: 1, stored: .none))"
        #expect(sentence.contains("the one road it knows"))
        #expect(!sentence.contains("1 roads"))
    }

    @Test func severalRoadsAreCounted() {
        let sentence = "\(ReachError.unreachable(roads: 4, stored: .known))"
        #expect(sentence.contains("any of the 4 roads it knows"))
    }

    /// An app that knows the roads and cannot use them has a tunnel problem.
    @Test func anAppThatKeptRoadsIsPointedAtTheTunnel() {
        let sentence = "\(ReachError.unreachable(roads: 3, stored: .known))"
        #expect(sentence.contains("mesh tunnel"))
        #expect(!sentence.contains("has not been answered before"))
    }

    /// An app that has never been answered cannot have a tunnel problem — it
    /// has never learned a road to have a problem with. Sending it to check
    /// the tunnel would be advice that cannot help.
    @Test func anAppThatNeverKeptRoadsIsSentHomeOnce() {
        let sentence = "\(ReachError.unreachable(roads: 1, stored: .none))"
        #expect(sentence.contains("the cluster's own network"))
        #expect(!sentence.contains("mesh tunnel"))
    }

    /// An app whose store will not read back has been answered before, and
    /// sending it home to be answered again is the one instruction that cannot
    /// work — the next set of roads goes to the same store.
    ///
    /// This was a `Bool`, so there were two sentences for three situations and
    /// `unreadable` fell into `none`. The app then said "this app has not been
    /// answered before" to an app that had, and told the person to open it on
    /// the cluster's own network, which writes roads to a keychain that will
    /// not open. `ClusterRoads.load` had the distinction and threw it; the hub
    /// caught it with a `try?`.
    @Test func anAppWhoseStoreWillNotOpenIsNotSentHomeAgain() {
        let sentence = "\(ReachError.unreachable(roads: 1, stored: .unreadable))"
        #expect(sentence.contains("will not read back"))
        #expect(!sentence.contains("has not been answered before"))
        #expect(!sentence.contains("mesh tunnel"))
        // The instruction that would loop.
        #expect(!sentence.contains("Open it once on the cluster's own network"))
    }

    @Test func theThreeSituationsDoNotReadTheSame() {
        let sentences = Set(
            [StoredRoads.known, .none, .unreadable].map {
                "\(ReachError.unreachable(roads: 2, stored: $0))"
            }
        )
        #expect(sentences.count == 3)
    }

    /// The house rule the legibility harness enforces across every error type,
    /// asserted here too so a wording change fails in the file it was made in.
    /// Driven off the case list rather than a literal pair, so a fourth state
    /// cannot be added without arriving here.
    @Test func everyBranchReadsAsASentence() {
        for stored in [StoredRoads.known, .none, .unreadable] {
            let sentence = "\(ReachError.unreachable(roads: 2, stored: stored))"
            #expect(sentence.contains(" "))
            #expect(sentence.first?.isUppercase != true)
            #expect(ReachError.unreachable(roads: 2, stored: stored).localizedDescription == sentence)
        }
    }
}
