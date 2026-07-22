import Testing
@testable import ReachWire

@Test func wireConstants() {
    #expect(Wire.version == 0)
    #expect(Wire.alpn == "reach/0")
    #expect(Wire.bonjourService == "_reach._udp")
}
