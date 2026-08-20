import Testing
@testable import ReachWire

/// The constants both ends agree on, pinned as literals.
///
/// The ALPNs pin the envelope, while `version` and `supportedVersions` pin the
/// JSON dialect. They are deliberately separate assertions: a dialect bump
/// must not partition TLS, and an envelope bump must be deliberate.
@Test func wireConstants() {
    #expect(Wire.baselineVersion == 0)
    #expect(Wire.version == 1)
    #expect(Wire.supportedVersions == [1, 0])
    #expect(Wire.envelopeVersion == 0)
    #expect(Wire.alpn == "reach/0")
    #expect(Wire.enrollALPN == "reach-enroll/0")
    #expect(Wire.bonjourService == "_reach._udp")
    #expect(Wire.txtVersionsKey == "v")
    #expect(Wire.txtVersionsValue == "1,0")
    #expect(Wire.txtVersionsValue(for: [1, 0]) == "1,0")
}

@Test func negotiationUsesServerPreference() {
    #expect(Wire.negotiate(offered: [1, 0], supported: [0]) == 0)
    #expect(Wire.negotiate(offered: [0, 2], supported: [2, 1, 0]) == 2)
    #expect(Wire.negotiate(offered: [1], supported: [0]) == nil)
    #expect(Wire.negotiate(offered: [], supported: [0]) == nil)
    #expect(Wire.offeredOrLegacy(nil) == [0])
    #expect(Wire.offeredOrLegacy([]).isEmpty)
    #expect(Wire.selectedOrLegacy(nil) == 0)
}

@Test func mismatchCopyNamesTheOlderSideOrTheGap() {
    #expect(Wire.mismatchMessage(app: [2, 1], cluster: [0]).hasPrefix(
        "your cluster speaks an older generation"
    ))
    #expect(Wire.mismatchMessage(app: [0], cluster: [2, 1]).hasPrefix(
        "this app speaks an older generation"
    ))
    let disjoint = Wire.mismatchMessage(app: [2, 0], cluster: [1])
    #expect(disjoint.hasPrefix("this app and your cluster do not share"))
    #expect(disjoint.contains("app offers 2,0; cluster supports 1"))
}

private struct FutureTestFrame: WireFrame {
    static let frameType = FrameType.ping
    static let introducedInVersion: UInt8 = 1
}

@Test func aFutureFrameRequiresTheNegotiatedGeneration() throws {
    #expect(throws: WireError.self) {
        _ = try FrameCodec.encode(FutureTestFrame())
    }
    #expect(try FrameCodec.encode(FutureTestFrame(), for: 1).isEmpty == false)
}
