import Testing
@testable import ReachDaemon

@Test func daemonSpeaksWireVersionZero() {
    #expect(DaemonInfo.wireVersion == 0)
}
