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
        ReachError.remote(code: "reattach-rejected", message: "unknown generation"),
        ReachError.identityNotRegistered("reach-app-systems.reach.example"),
        ReachError.sessionRejected("token did not match"),
        ReachError.transport("no route to host"),
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
            #expect(ending.reason.contains(" "), "reads as a token, not a sentence: \(ending.reason)")
            #expect(ending.reason.first?.isUppercase != true, "reads like a type name: \(ending.reason)")
            #expect(ending.reason.contains("EnrollComplete"), "does not name the frame that is missing: \(ending.reason)")
        }
        #expect(EnrollmentService.Confirmation.broke(
            TransportError.connectionFailed("POSIXErrorCode(rawValue: 57): Socket is not connected")
        ).reason.contains("Socket is not connected"))
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
