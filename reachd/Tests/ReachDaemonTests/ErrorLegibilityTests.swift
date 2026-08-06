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
        ReachError.unreachable(roads: 4, stored: true),
        ReachError.unreachable(roads: 1, stored: false),
        // A tool the model could not be told about: the filling turns this
        // throw into `.finished(.error(…))`, which crosses the wire and lands
        // on the asking app's screen.
        ToolRenderingError.schemaUnrenderable(
            tool: "current_time",
            reason: "its parameters did not encode as a JSON object"
        ),
        ReachEnrollmentError.badCAHash,
        ReachEnrollmentError.refused(code: "grant-denied", message: "the ruling was no"),
        ReachEnrollmentError.sequence("expected EnrollGrant"),
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
