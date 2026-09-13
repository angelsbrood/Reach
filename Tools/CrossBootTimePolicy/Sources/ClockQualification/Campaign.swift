import Foundation
import ClockPolicy

func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    guard try condition() else { throw NSError(domain: message, code: 1) }
}
func expect(_ refusal: Refusal, _ body: () throws -> Void) throws {
    do { try body() } catch let error as Refusal {
        try require(error == refusal, "expected \(refusal), got \(error)"); return
    }
    throw NSError(domain: "missing expected refusal: \(refusal)", code: 1)
}

struct FreshnessResult: Codable {
    let scenario: String
    let originals: Originals
    let signedResponse: Data
    let signedSample: Sample
    let sampleAfterSigning: Sample
    let originalSend: Sample
    let signatureOnlyWouldAllow: Bool
    let producedWhileConservativelyEligible: Bool
    let beforeBlocking: Evaluation?
    let afterDelay: Evaluation
    let requestedProcessWaitSeconds: Double
}

/// System-clock campaign, separate from all injected fixtures and the actual guest reboot.
func freshness() throws {
    var results: [FreshnessResult] = []
    for delayed in [true, false] {
        let witness = try Witness(clock: SystemClock())
        let subject = UUID().uuidString.lowercased()
        let h = try witness.register(subject: subject, role: .host,
                                     cap: (delayed ? 4 : 30) * 1_000_000_000)
        let c = try witness.register(subject: subject, role: .client,
                                     cap: (delayed ? 30 : 4) * 1_000_000_000)
        let originals = try Originals(pin: witness.identity, host: h, client: c)
        let receiverClock = SystemClock()
        let verifier = try Verifier(originals: originals, clock: receiverClock)
        let action = try verifier.begin(purpose: delayed ? .candidate : .blocking)
        let response = try witness.respond(to: action.request)
        let signed = try Verifier.signatureOnlyControl(response, originals: originals)
        let signedAt = try receiverClock.sample()
        let records = try originals.records()
        let signingUpper = signed.nanoseconds + 2 * (signedAt.nanoseconds - action.sent.nanoseconds) + 1_000_000_000
        let producedEligible = signingUpper < records.host.deadline && signingUpper < records.client.deadline
        try require(producedEligible, "response must be produced while conservatively eligible")
        var before: Evaluation?
        if !delayed {
            try verifier.receive(response, for: action)
            before = try verifier.evaluate(action)
            try require(before?.outcome == .eligible, "pre-blocking candidate must be eligible")
        }
        Thread.sleep(forTimeInterval: 4.25)
        if delayed { try verifier.receive(response, for: action) }
        let after = try verifier.evaluate(action)
        try require(after.outcome == (delayed ? .hostExpired : .clientExpired), "late candidate must refuse")
        try require(after.r0 == action.sent && (before == nil || before?.r0 == after.r0), "send anchor changed")
        let signatureOnlyAllows = signed.nanoseconds < records.host.deadline && signed.nanoseconds < records.client.deadline
        try require(signatureOnlyAllows, "signature-only control must expose stale authorization")
        results.append(FreshnessResult(scenario: delayed ? "signed-delivery-after-expiry" : "post-blocking-refusal",
            originals: originals, signedResponse: response, signedSample: signed, sampleAfterSigning: signedAt,
            originalSend: action.sent, signatureOnlyWouldAllow: signatureOnlyAllows,
            producedWhileConservativelyEligible: producedEligible, beforeBlocking: before, afterDelay: after,
            requestedProcessWaitSeconds: 4.25))
    }
    try Channel().write(results)
}

struct Manifest: Codable {
    let profile: Profile
    let seededBy: Sample
    let fixtures: [Originals]
}
struct Probe: Codable {
    let label: String
    let manifestDigest: String
    let receiver: Sample
    let witnessIdentity: Identity
    let originals: [Originals]
    let evaluations: [Evaluation]
    var priorBoot: String?
    var refusal: String?
}

func receiver(phase: String, root: String) throws {
    guard ["seed", "postboot", "replacement"].contains(phase) else { throw Refusal.binding }
    let channel = Channel(), systemClock = SystemClock()
    let hello = try channel.read(Hello.self)
    try require(hello.profile == .qualification, "qualification profile required")
    let manifestURL = URL(fileURLWithPath: root).appendingPathComponent("originals.json")
    func exchange(_ request: Request) throws -> Reply {
        try channel.write(request)
        return try channel.read(Reply.self)
    }
    func event<T: Encodable>(_ name: String, _ value: T) throws {
        let data = try Wire.encode(value)
        try data.write(to: URL(fileURLWithPath: root).appendingPathComponent(name + ".json"), options: .atomic)
        let reply = try exchange(Request(kind: "event", event: name, evidence: data))
        try require(reply.kind == "ack", "controller evidence acknowledgement required")
    }
    func acquire(_ originals: Originals, purpose: Purpose = .candidate) throws -> (Verifier, Action) {
        let verifier = try Verifier(originals: originals, clock: systemClock)
        try verifier.observeWitnessIdentity(hello.identity)
        let action = try verifier.begin(purpose: purpose)
        let reply = try exchange(Request(kind: "certificate", challenge: action.request))
        guard reply.kind == "certificate", let signed = reply.certificate else {
            verifier.observeWitnessLoss(); throw Refusal.missing
        }
        try verifier.receive(signed, for: action)
        return (verifier, action)
    }
    if phase == "seed" {
        try require(!FileManager.default.fileExists(atPath: manifestURL.path), "original manifest already exists")
        let subjects = (0..<3).map { _ in UUID().uuidString.lowercased() }
        let request = Request(kind: "fixtures", subjects: subjects)
        let response = try exchange(request)
        guard response.kind == "fixtures", let pairs = response.originals, pairs.count == 3 else { throw Refusal.missing }
        for pair in pairs { _ = try pair.records(); try require(pair.pin == hello.identity, "initial trusted pipe pin mismatch") }
        // Repeated registration must return the exact originals even though clocks have advanced.
        let repeated = try exchange(request)
        try require(repeated.originals == pairs, "original registrations renewed")
        let manifest = Manifest(profile: .qualification, seededBy: try systemClock.sample(), fixtures: pairs)
        let bytes = try Wire.encode(manifest)
        try bytes.write(to: manifestURL, options: .atomic)
        var evaluations: [Evaluation] = []
        for pair in pairs {
            let (verifier, action) = try acquire(pair)
            let result = try verifier.evaluate(action)
            try require(result.outcome == .eligible, "preboot positive bound")
            evaluations.append(result)
        }
        try event("seed", Probe(label: "seed", manifestDigest: Wire.digest(bytes), receiver: systemClock.sample(),
            witnessIdentity: hello.identity, originals: pairs, evaluations: evaluations))
        return
    }
    let attributes = try FileManager.default.attributesOfItem(atPath: manifestURL.path)
    guard let size = attributes[.size] as? NSNumber, size.intValue <= Wire.maximumBytes else { throw Refusal.capacity }
    let bytes = try Data(contentsOf: manifestURL)
    let manifest = try Wire.decode(Manifest.self, bytes)
    try require(manifest.profile == .qualification && manifest.fixtures.count == 3, "original manifest profile/selection")
    for pair in manifest.fixtures { _ = try pair.records() }
    let fresh = try systemClock.sample()
    try require(fresh.boot != manifest.seededBy.boot && fresh.incarnation != manifest.seededBy.incarnation,
                "actual new receiver boot and process required")
    if phase == "replacement" {
        let pair = manifest.fixtures[2]
        let verifier = try Verifier(originals: pair, clock: systemClock)
        let pending = try verifier.begin(purpose: .candidate)
        try expect(.binding) { try verifier.observeWitnessIdentity(hello.identity) }
        let reply = try exchange(Request(kind: "certificate", challenge: pending.request))
        try require(reply.kind == "refusal" && reply.error == "binding", "replacement must reject original challenge")
        try expect(.invalidated) { _ = try verifier.evaluate(pending) }
        try require(try Data(contentsOf: manifestURL) == bytes, "replacement modified originals")
        try event("replacement", Probe(label: "replacement-refused", manifestDigest: Wire.digest(bytes),
            receiver: fresh, witnessIdentity: hello.identity, originals: manifest.fixtures, evaluations: [],
            priorBoot: manifest.seededBy.boot, refusal: "replacement-pin-and-epoch-refused"))
        return
    }
    var positive: [Evaluation] = []
    for pair in manifest.fixtures {
        let (verifier, action) = try acquire(pair)
        let evaluation = try verifier.evaluate(action)
        try require(evaluation.outcome == .eligible, "postboot positive bound")
        positive.append(evaluation)
    }
    try event("postboot-positive", Probe(label: "postboot-positive", manifestDigest: Wire.digest(bytes),
        receiver: fresh, witnessIdentity: hello.identity, originals: manifest.fixtures,
        evaluations: positive, priorBoot: manifest.seededBy.boot))
    for index in 0..<2 {
        let pair = manifest.fixtures[index], records = try pair.records()
        let deadline = index == 0 ? records.host.deadline : records.client.deadline
        // Polls are observed data. A finite campaign does not establish a future clock-rate bound.
        while true {
            let reply = try exchange(Request(kind: "sample"))
            guard reply.kind == "sample", let sample = reply.sample,
                  sample.boot == pair.pin.boot, sample.incarnation == pair.pin.incarnation else { throw Refusal.clock }
            if sample.nanoseconds >= deadline { break }
            Thread.sleep(forTimeInterval: min(5, Double(deadline - sample.nanoseconds) / 1_000_000_000))
        }
        let (verifier, action) = try acquire(pair)
        let evaluation = try verifier.evaluate(action)
        try require(evaluation.outcome == (index == 0 ? .hostExpired : .clientExpired), "independent original expiry")
        try event(index == 0 ? "host-expired" : "client-expired", evaluation)
    }
    let pair = manifest.fixtures[2]
    let (unobserved, action) = try acquire(pair)
    let (observed, observedAction) = try acquire(pair)
    try require(try unobserved.evaluate(action).outcome == .eligible, "pre-loss positive bound")
    let stopped = try exchange(Request(kind: "controller-stop-witness"))
    try require(stopped.kind == "ack", "controller must join original witness")
    let afterUnobservedLoss = try unobserved.evaluate(action)
    try require(afterUnobservedLoss.outcome == .eligible, "bounded unobserved loss use")
    observed.observeWitnessLoss()
    try expect(.invalidated) { _ = try observed.evaluate(observedAction) }
    try event("unobserved-loss-bounded-use", afterUnobservedLoss)
    Thread.sleep(forTimeInterval: 10.2)
    try expect(.age) { _ = try unobserved.evaluate(action) }
    try require(try Data(contentsOf: manifestURL) == bytes, "postboot modified originals")
    try event("postboot-complete", Probe(label: "postboot-complete", manifestDigest: Wire.digest(bytes),
        receiver: systemClock.sample(), witnessIdentity: hello.identity, originals: manifest.fixtures,
        evaluations: [afterUnobservedLoss], priorBoot: manifest.seededBy.boot,
        refusal: "observed-loss-invalidated; unobserved-loss-original-age-exhausted"))
}
