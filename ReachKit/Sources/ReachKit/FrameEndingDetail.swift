import Foundation
import ReachTransport

/// The transport's own words, folded into a sentence this module wrote.
///
/// `FrameEnding` deliberately carries no prose — only the caller knows which
/// frame it was waiting for and what is at stake if it never comes — so what is
/// shared here is the mechanic and not the sentence. Each half of the ceremony
/// has its own copy of these three lines for that reason: the daemon's is
/// `reason(waitingFor:)`, the Keeper's is `unconfirmed(_:)` and `spent(_:waitingFor:)`,
/// and neither can reach this one.
///
/// A break's error reads oddly nested inside a sentence that has just described
/// a ceremony — the transport only knows it lost a connection — but it is the
/// part that names *what happened*, and dropping it leaves a person with a
/// situation and no fault.
extension FrameEnding {
    func detailing(_ sentence: String) -> String {
        guard case .broke(let error) = self else { return sentence }
        return "\(sentence) (the connection ended: \(error))"
    }
}
