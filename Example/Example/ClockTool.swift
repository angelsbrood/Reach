import Foundation
import FoundationModels

/// A tool the Example app answers for itself.
///
/// Deliberately boring, and deliberately something the cluster cannot know:
/// the model is on the Mac, the clock is on this phone. A plausible-looking
/// time in a completion proves nothing — a time that matches *this device*
/// proves the round trip happened, that the arguments crossed intact, and
/// that the answer came back from here rather than being invented there.
///
/// Nothing privileged, per Example's charter: it stands in for every
/// third-party app, so it may only do what any of them could.
struct ClockTool: Tool {
    let name = "current_time"
    let description = "The current time in a given timezone. Call this whenever the user asks what time it is."

    @Generable
    struct Arguments {
        @Guide(description: "IANA timezone identifier, for example Europe/Vienna")
        var timezone: String
    }

    /// Reports what it was asked, so the app can say on screen that the tool
    /// ran here — the one thing the completion text alone cannot establish.
    let ran: @Sendable (String) -> Void

    func call(arguments: Arguments) async throws -> String {
        guard let zone = TimeZone(identifier: arguments.timezone) else {
            // The model chose a timezone that is not one. Saying so is worth
            // more than a wrong time: the sentence goes back into the
            // transcript, and the model gets to correct itself on the next
            // turn rather than reporting a confident fiction.
            ran(arguments.timezone)
            return "\(arguments.timezone) is not a timezone this device knows."
        }
        ran(zone.identifier)
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        formatter.timeZone = zone
        return "\(formatter.string(from: Date())) in \(zone.identifier)"
    }
}
