import Testing
@testable import ReachWire

/// The constants both ends agree on, pinned as literals.
///
/// The ALPN lines are deliberately written out rather than recomputed from
/// `Wire.version`: a test that derives them the same way the source does
/// could not fail. Spelled out, they are the forcing function — bumping
/// `version` fails all three of these at once, which is the moment to decide
/// what a v1 daemon serves and whether old peers get anything legible. Before
/// the ALPN was derived, that bump broke nothing and the wire silently kept
/// saying `reach/0` for a protocol that was no longer v0.
@Test func wireConstants() {
    #expect(Wire.version == 0)
    #expect(Wire.alpn == "reach/0")
    #expect(Wire.enrollALPN == "reach-enroll/0")
    #expect(Wire.bonjourService == "_reach._udp")
}
