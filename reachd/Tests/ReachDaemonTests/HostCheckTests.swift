import Foundation
import Testing

@testable import ReachDaemon

/// The first tests `doctor` has ever had. They are deliberately pure
/// filesystem: no identity materialization, no real sockets, no listeners —
/// so this suite is deterministic, needs no `.serialized`, and cannot be
/// implicated in the PKCS#12 import failure that the identity path still has.
@Suite struct HostCheckTests {
    /// Fixtures set their own mode. `createDirectory` alone lands at
    /// `0777 & ~umask`, so a developer at `umask 022` gets 0755 and a
    /// developer at `umask 077` gets 0700 — and a permission assertion that
    /// inherits either one passes or fails according to whose machine it is.
    private func fixture(mode: Int = 0o700) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-doctor-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    private func report(
        _ directory: URL,
        conf: String? = nil,
        addresses: [[UInt8]] = [[192, 168, 8, 104], [10, 86, 0, 1]],
        portsHeld: Bool = false
    ) async -> HostCheck.Report {
        await HostCheck.examine(
            stateDirectory: directory,
            wireGuardConf: conf ?? directory.appendingPathComponent("absent.conf").path,
            addresses: addresses,
            portIsHeld: { _ in portsHeld }
        )
    }

    private func finding(_ report: HostCheck.Report, _ title: String) throws -> HostCheck.Finding {
        try #require(report.findings.first { $0.title == title })
    }

    // MARK: - The exit code answers one question

    @Test func aColdRigIsWaitingNotBroken() async throws {
        // Nothing has been started: no CA, no wg key, no conf, no devices,
        // no daemon, no mesh interface. Every one of those is the next step
        // in the runbook, and none of them is a fault.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        var config = DaemonConfig()
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: directory)

        let report = await report(directory, addresses: [[192, 168, 8, 104]])

        #expect(report.isSound, "a rig that has not been started is not a broken one")
        #expect(report.count(.fail) == 0)
        #expect(report.count(.wait) > 0)
        for title in ["mesh interface", "cluster CA", "wg host key", "wg config", "enrolled devices", "session port"] {
            #expect(try finding(report, title).level == .wait, "\(title) should be waiting, not faulted")
        }
    }

    @Test func theMeshInterfaceIsAFaultOnceADaemonIsUp() async throws {
        // The same condition, two verdicts. Down before serving is the next
        // step; down while serving is a rig that streams on the LAN and has
        // nothing to fall to when the demonstrator walks out the door.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        var config = DaemonConfig()
        config.meshEndpoint = "203.0.113.7:51820"
        try config.save(to: directory)

        let waiting = await report(directory, addresses: [[192, 168, 8, 104]], portsHeld: false)
        #expect(try finding(waiting, "mesh interface").level == .wait)
        #expect(waiting.isSound)

        let serving = await report(directory, addresses: [[192, 168, 8, 104]], portsHeld: true)
        #expect(try finding(serving, "mesh interface").level == .fail)
        #expect(!serving.isSound, "a daemon serving with no mesh must not exit zero")
    }

    // MARK: - Absent is not the same answer as broken

    @Test func aCorruptCADoesNotReadAsAbsent() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let ca = directory.appendingPathComponent("ca", isDirectory: true)
        try FileManager.default.createDirectory(at: ca, withIntermediateDirectories: true)

        let absent = await report(directory)
        #expect(try finding(absent, "cluster CA").level == .wait)

        // Present, and will not load. Every enrolled device was issued
        // against this; reporting it as "not started yet" would be worse
        // than the undifferentiated warning it replaced.
        try Data("not a certificate".utf8).write(to: ca.appendingPathComponent("ca.der"))
        try Data("not a key".utf8).write(to: ca.appendingPathComponent("ca-key.raw"))

        let corrupt = await report(directory)
        #expect(try finding(corrupt, "cluster CA").level == .fail)
        #expect(!corrupt.isSound)
    }

    @Test func aWireGuardConfThatServeWillNotRecreateIsAFault() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf").path

        // No host key yet: a missing conf is a genuine first run, and the
        // very next serve writes both together.
        let firstRun = await report(directory, conf: conf)
        #expect(try finding(firstRun, "wg config").level == .wait)
        #expect(firstRun.isSound)

        // Host key present, conf gone. WireGuardHost only writes the skeleton
        // alongside a fresh keypair, so serve will never recreate this — and
        // addPeer will read the absent file as "" and emit a bare [Peer] with
        // no [Interface], which wg-quick refuses.
        let wg = directory.appendingPathComponent("wg", isDirectory: true)
        try FileManager.default.createDirectory(at: wg, withIntermediateDirectories: true)
        try Data("Zm9v".utf8).write(to: wg.appendingPathComponent("server.pub"))

        let stranded = await report(directory, conf: conf)
        #expect(try finding(stranded, "wg config").level == .fail)
        #expect(!stranded.isSound, "a conf serve cannot recreate must not exit zero")
    }

    @Test func anUnreadableConfIsAFaultAndSaysSo() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let conf = directory.appendingPathComponent("reach0.conf")

        // Invalid UTF-8 rather than chmod 000: a permission trick reads as
        // readable when the suite happens to run as root, and this must fail
        // for whoever runs it.
        try Data([0xFF, 0xFE, 0xFF]).write(to: conf)

        let report = await report(directory, conf: conf.path)
        let wgConf = try finding(report, "wg config")
        #expect(wgConf.level == .fail)
        #expect(wgConf.detail.contains("will not read"))
        #expect(!report.isSound)
    }

    // MARK: - The tally

    @Test func theTallyCountsEveryLevel() async throws {
        // Passes used to be derived by subtracting warnings and failures from
        // the total, which is arithmetic that silently loses a level the
        // moment a fourth one exists.
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let report = await report(directory)

        let counted = report.count(.pass) + report.count(.warn) + report.count(.wait) + report.count(.fail)
        #expect(counted == report.findings.count)
    }
}
