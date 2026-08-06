import Foundation
import ReachIdentity
import ReachKit
import ReachTransport
import ReachWire
import Security
import Testing
@testable import ReachDaemon

/// Errors that reach a person have to name the thing and the reason.
///
/// `reachd doctor` was rebuilt to that standard and the rest of the surface
/// was never held to it. Of seven error types in the tree only `ConfigError`
/// carried a description, and around thirty sites interpolate an error
/// straight into text a human reads: `Example` puts `"no grant: \(error)"` on
/// the phone's screen, the Keeper's tunnel manager stores `.failed("\(error)")`,
/// and the daemon sends `ErrorFrame(message: "\(error)")` **across the wire**
/// from `Daemon` and `EnrollmentService`. Swift's default reflection renders
/// those as a case name — `noGrant`, `unknownSession`, `streamClosed` — which
/// is the thing without the reason, on a screen belonging to someone who
/// cannot read the source.
@Suite struct ErrorLegibilityTests {
    /// Every value here has a path to a human. Cases carrying a daemon's own
    /// words are included deliberately: that text travelled the wire to be
    /// read, and it must survive the wrapping intact.
    private static let reachAPerson: [any Error] = [
        IdentityError.identityNotFound(errSecItemNotFound),
        IdentityError.keychainAddFailed(errSecMissingEntitlement),
        IdentityError.malformedCertificate,
        IdentityError.importFailed("key import: bad point"),
        TransportError.streamClosed,
        TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected"),
        TransportError.sendFailed("broken pipe"),
        // Lands on the operator's terminal as the reason `reachd serve` would
        // not start, which is the one moment they can still do something.
        TransportError.listenerCouldNotBind(
            port: 47337,
            detail: "POSIXErrorCode(rawValue: 48): Address already in use"
        ),
        WireError.unknownFrameType(99),
        WireError.frameTooLarge(1 << 25),
        WireError.malformedFrame("GenerateBegin: missing transcript"),
        CAError.stateMissing("/tmp/reach/ca"),
        CAError.stateExists("/tmp/reach/ca"),
        // The three the session registry sends across the wire. They were
        // missing while this suite's own header quoted `unknownSession` as
        // the thing it exists to outlaw, and the `.remote` fixture below
        // stood in a hand-written "unknown generation" the daemon never
        // sends — two words, so it passed, while the real string was one
        // token. A corpus that omits the type it was written for cannot fail
        // where it matters, so the daemon's own values go in first and the
        // stand-in now carries what the daemon actually says.
        SessionRegistry.RegistryError.unknownSession,
        SessionRegistry.RegistryError.badToken,
        SessionRegistry.RegistryError.unknownGeneration,
        ReachError.remote(
            code: "reattach-rejected",
            message: "\(SessionRegistry.RegistryError.unknownGeneration)"
        ),
        // What a person meets when the cluster restarts mid-answer, built
        // the way the executor builds it: the daemon's rendered reason
        // wrapped in what it means.
        ReachError.generationLost("\(SessionRegistry.RegistryError.unknownSession)"),
        ReachError.identityNotRegistered("reach-app-systems.reach.example"),
        ReachError.sessionRejected("token did not match"),
        ReachError.transport("no route to host"),
        // Both branches: they render differently and both reach a screen.
        ReachError.unreachable(roads: 4, stored: .known),
        ReachError.unreachable(roads: 1, stored: .none),
        ReachError.unreachable(roads: 1, stored: .unreadable),
        // A tool the model could not be told about: the filling turns this
        // throw into `.finished(.error(…))`, which crosses the wire and lands
        // on the asking app's screen.
        ToolRenderingError.schemaUnrenderable(
            tool: "current_time",
            reason: "its parameters did not encode as a JSON object"
        ),
        // The operator's terminal, at the one moment they can still act.
        ServiceError.buildPath("/Users/x/Library/Caches/reach-spm/reachd/out/Products/Debug/reachd"),
        ServiceError.notExecutable("/usr/local/bin/reachd"),
        ServiceError.missingResources("/usr/local/bin/reachd"),
        ServiceError.launchctlRefused("Load failed: 5: Input/output error"),
        ReachEnrollmentError.badCAHash,
        ReachEnrollmentError.refused(code: "grant-denied", message: "the ruling was no"),
        ReachEnrollmentError.sequence("expected EnrollGrant"),
        // The one that reaches a person most often, by a wide margin — three
        // red runs in nine. It reaches a *reader of this suite*, which is a
        // kind of person this corpus had not been asked to serve before.
        IdentityError.pkcs12EmptyItemList(bytes: 894),
    ]

    @Test func everyErrorThatReachesAPersonReadsAsASentence() {
        for error in Self.reachAPerson {
            let rendered = "\(error)"
            // A case name is one token, and `caseName(payload)` still leads
            // with one. A sentence does not.
            #expect(
                rendered.contains(" "),
                "\(type(of: error)) renders as a case name, not a sentence: \(rendered)"
            )
            #expect(
                rendered.first?.isUppercase != true,
                "\(type(of: error)) reads like a type name: \(rendered)"
            )
        }
    }

    /// `localizedDescription` is what SwiftUI reaches for, and the Keeper's
    /// ceremony view uses exactly that. Without `LocalizedError` it returns
    /// Foundation's placeholder instead of anything the author wrote.
    @Test func theLocalizedFormIsNotFoundationsPlaceholder() {
        for error in Self.reachAPerson {
            let localized = error.localizedDescription
            #expect(
                !localized.contains("couldn’t be completed"),
                "\(type(of: error)) falls back to Foundation's placeholder: \(localized)"
            )
            #expect(localized == "\(error)")
        }
    }

    /// The failure this suite's own readers meet most, and the one it was
    /// worst at serving them on.
    ///
    /// `SecPKCS12Import` returns `errSecSuccess` with an empty item list on
    /// about one materialization in 250 — three red runs in nine full `reachd`
    /// runs, the dominant failure mode in this tree. It throws out of a
    /// fixture, so swift-testing records `errorCaught` against whichever suite
    /// lost the coin flip, and that suite is innocent. Twice in one afternoon
    /// it named `cancellationPropagates` and then `aSpentTokenSaysWhatToDoAboutIt`,
    /// neither of which had been touched.
    ///
    /// Under `importFailed` it read as an ordinary assembly failure and cost
    /// someone a diagnosis every time. Now the error clears the suite it
    /// landed on, and this holds the clearing. The string checked is the one
    /// swift-testing interpolates into `Caught error:`.
    ///
    /// `withKnownIssue` is the tool that suggests itself here and it is the
    /// wrong one: it absorbs the failure and the run goes green. A quiet run
    /// is not a fixed run. This stays red and explains itself.
    @Test func theKnownPKCS12FailureClearsWhateverTestItLandedOn() {
        let sentence = "\(IdentityError.pkcs12EmptyItemList(bytes: 894))"
        // What it is, so nobody re-derives it.
        #expect(sentence.contains("SecPKCS12Import"))
        // Who is not at fault — the two readings that cost the most time.
        #expect(sentence.contains("not your change"))
        #expect(sentence.contains("innocent"))
        // That it is rare rather than deterministic, so a re-run is worth it.
        #expect(sentence.contains("run it again"))
        // And that the silence of a retry is not on offer.
        #expect(sentence.contains("not retried"))
        // It must not be mistaken for a malformed archive, which is what the
        // old wording implied and what sends a reader after the bytes.
        #expect(!sentence.contains("would not import"))
    }

    /// The reason a confirming frame never arrived reaches a person too — it
    /// is the whole of the daemon's account of a ceremony that tore after the
    /// grant, and for the device half it is what says the QR is spent.
    ///
    /// A stream that was RESET rather than closed throws out of `next()`, and
    /// a throw cannot reach a `guard`'s `else`: it landed in `serve`'s catch
    /// and printed `enrollment stream failed: … POSIXErrorCode 57` instead,
    /// so the sentences written for exactly this case were unreachable by
    /// construction. These hold the replacements to the same standard as
    /// everything above — and the `.broke` case must still carry the
    /// transport's own words, because that is the part naming what happened.
    @Test func aConfirmationThatNeverCameSaysWhichWayItDidNotCome() {
        let endings: [EnrollmentService.Confirmation] = [
            .closed,
            .broke(TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")),
            .frame(RawFrame(type: Ping.frameType, body: Data())),
        ]
        for ending in endings {
            let reason = ending.reason(waitingFor: "EnrollComplete")
            #expect(reason.contains(" "), "reads as a token, not a sentence: \(reason)")
            #expect(reason.first?.isUppercase != true, "reads like a type name: \(reason)")
            #expect(reason.contains("EnrollComplete"), "does not name the frame that is missing: \(reason)")
            // The caller names the frame, so the sentence has to actually use
            // the one it was given — a hardcoded noun would pass every check
            // above while telling the device half's operator about the wrong
            // read.
            #expect(
                ending.reason(waitingFor: "EnrollCertRequest").contains("EnrollCertRequest"),
                "the sentence ignores the frame the caller was waiting for"
            )
        }
        #expect(EnrollmentService.Confirmation.broke(
            TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")
        ).reason(waitingFor: "EnrollComplete").contains("Socket is not connected"))
    }

    /// Which endings the app half survives on its own — because the log level
    /// follows from that, and getting it backwards is what put `error` on
    /// every successful ceremony for a whole recording session.
    ///
    /// A one-phone grant cannot end any other way: the operator must leave the
    /// asking app to rule the sheet, iOS suspends it, and the ruling lands on a
    /// stream nobody is on. The desk keeps the verdict; the next knock collects
    /// it. An app that sent the wrong frame is the one that will not heal, so
    /// that is the one that stays an error.
    @Test func theAppHalfKnowsWhichEndingsItRecoversFrom() {
        #expect(EnrollmentService.Confirmation.closed.appHalfConverges)
        #expect(EnrollmentService.Confirmation.broke(
            TransportError.connectionFailed("POSIXErrorCode(rawValue: 61): Connection refused")
        ).appHalfConverges)
        #expect(
            EnrollmentService.Confirmation.frame(RawFrame(type: Ping.frameType, body: Data()))
                .appHalfConverges == false,
            "an app that sent the wrong frame will send it again — that one is not news, it is a fault"
        )
    }

    /// The same question one listener over, and the same answer: an app going
    /// away is news, not a fault.
    ///
    /// `serve` let a control stream's ending throw past `while let raw = try
    /// await iterator.next()` into its catch, which wrote `stream ended:
    /// POSIXErrorCode 57` at error level. An app quitting with a live control
    /// stream is the commonest thing that happens to this daemon and nearly
    /// all of the traffic just after a restart, so the log filled with errors
    /// for nothing going wrong — 7f's reading, on the listener 7f did not
    /// reach. Now the ending is a returned value and the level follows from
    /// it, which is what makes it assertable here at all: the daemon has no
    /// log sink a test can read, and does not need one.
    @Test func aControlStreamKnowsWhichEndingsAreJustSomeoneLeaving() {
        #expect(FrameEnding.closed.peerWentAway)
        #expect(FrameEnding.broke(
            TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")
        ).peerWentAway)
        // The one that is not a departure: bytes that will not parse as
        // frames. No version negotiation exists to have refused this peer
        // earlier, so this is where it surfaces — and it must not be filed
        // under an app closing its laptop.
        #expect(
            FrameEnding.broke(WireError.unknownFrameType(99)).peerWentAway == false,
            "a peer speaking something unparseable is not a peer leaving"
        )
        #expect(
            FrameEnding.frame(RawFrame(type: Ping.frameType, body: Data())).peerWentAway == false,
            "returning while still holding a frame is a fault in the loop"
        )
    }

    /// What the operator reads in `~/Library/Logs/reachd.log`. Both output
    /// streams land in that one file and neither level prints a tag, so the
    /// sentence is the whole of the distinction a person gets.
    @Test func aDepartingStreamSaysThatNothingWasLost() {
        let reset = FrameEnding.broke(
            TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")
        ).accountOfAControlStream
        // The transport's own words, which name what happened.
        #expect(reset.contains("Socket is not connected"))
        // And the part that stops it reading as a loss.
        #expect(reset.contains("residency window"))
        #expect(reset.first?.isUppercase != true, "reads like a type name: \(reset)")

        let unreadable = FrameEnding.broke(WireError.frameTooLarge(1 << 25)).accountOfAControlStream
        #expect(unreadable.contains("could not read"))
        // The two must not converge — one is an app leaving, the other is a
        // peer this daemon cannot talk to, and they take different actions.
        #expect(!unreadable.contains("quit, slept"))

        #expect(FrameEnding.closed.accountOfAControlStream.contains("closed its control stream"))
    }

    /// A refusal that travelled the wire keeps the daemon's own words. This
    /// is the half that matters at a venue: the Mac knows why it refused and
    /// the phone is the screen someone is looking at.
    @Test func aRefusalCarriesTheReasonItWasGiven() {
        let refusal = ReachEnrollmentError.refused(code: "enroll-token", message: "this QR is spent — run `reachd pair` for a fresh one")
        #expect("\(refusal)".contains("this QR is spent"))
        #expect("\(refusal)".contains("enroll-token"))

        let remote = ReachError.remote(code: "enroll-endpoint", message: "config.json will not parse")
        #expect("\(remote)".contains("config.json will not parse"))
    }
}
