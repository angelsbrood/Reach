import Testing
@testable import ReachTransport

@Test func transportUsesSessionALPN() {
    #expect(Transport.alpn == "reach/0")
}
