import Testing
@testable import ReachDaemon

@Test func daemonPrefersWireDialectOne() {
    #expect(DaemonInfo.wireVersion == 1)
}
