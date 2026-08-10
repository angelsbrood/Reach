import Foundation
import Testing

@testable import ReachDaemon

@Suite struct LaunchIdentityTests {
    private func fixture() throws -> (
        root: URL,
        executable: URL,
        alias: URL,
        nestedAlias: URL
    ) {
        let temporaryRoot = try #require(
            LaunchIdentity.canonicalPath(FileManager.default.temporaryDirectory.path)
        )
        let root = URL(fileURLWithPath: temporaryRoot, isDirectory: true)
            .appendingPathComponent("reach launch identity \(UUID())", isDirectory: true)
        let canonicalDirectory = root.appendingPathComponent("libexec/reach", isDirectory: true)
        let binDirectory = root.appendingPathComponent("bin", isDirectory: true)
        let nestedDirectory = root.appendingPathComponent("nested/alias", isDirectory: true)
        try FileManager.default.createDirectory(
            at: canonicalDirectory,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: binDirectory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: nestedDirectory, withIntermediateDirectories: true)

        let executable = canonicalDirectory.appendingPathComponent("reachd")
        try Data().write(to: executable)

        let alias = binDirectory.appendingPathComponent("reachd")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: executable)

        let nestedAlias = nestedDirectory.appendingPathComponent("reachd")
        try FileManager.default.createSymbolicLink(
            atPath: nestedAlias.path,
            withDestinationPath: "../../bin/reachd"
        )
        return (root, executable, alias, nestedAlias)
    }

    @Test func aCanonicalPathContinuesWithoutReplacement() throws {
        let staged = try fixture()
        defer { try? FileManager.default.removeItem(at: staged.root) }

        #expect(LaunchIdentity.decision(for: staged.executable.path) == .continueInPlace)
    }

    @Test func absoluteAndNestedAliasesChooseExactlyOneCanonicalReplacement() throws {
        let staged = try fixture()
        defer { try? FileManager.default.removeItem(at: staged.root) }

        #expect(
            LaunchIdentity.decision(for: staged.alias.path)
                == .reexecute(staged.executable.path)
        )
        #expect(
            LaunchIdentity.decision(for: staged.nestedAlias.path)
                == .reexecute(staged.executable.path)
        )
        #expect(LaunchIdentity.decision(for: staged.executable.path) == .continueInPlace)
    }

    @Test func pathsContainingSpacesResolveWithoutChangingTheTarget() throws {
        let staged = try fixture()
        defer { try? FileManager.default.removeItem(at: staged.root) }

        let decision = LaunchIdentity.decision(for: staged.alias.path)
        #expect(decision == .reexecute(staged.executable.path))
        guard case .reexecute(let target) = decision else { return }
        #expect(target.contains("reach launch identity"))
    }

    @Test func aBarePathCommandUsesTheAbsoluteAliasReportedByTheKernel() throws {
        let staged = try fixture()
        defer { try? FileManager.default.removeItem(at: staged.root) }

        // S22 established that argv[0] is `reachd` for a PATH launch while
        // `_NSGetExecutablePath` supplies this absolute alias. The resolver's
        // input is the kernel report, never argv[0].
        #expect(
            LaunchIdentity.decision(for: staged.alias.path)
                == .reexecute(staged.executable.path)
        )
    }

    @Test func aMissingOrUnresolvablePathKeepsExistingCommandsUsable() {
        #expect(LaunchIdentity.decision(for: "/nowhere/reachd") == .continueInPlace)
        #expect(
            LaunchIdentity.decision(for: "/alias/reachd", resolving: { _ in nil })
                == .continueInPlace
        )
    }

    @Test func thePureDecisionDoesNotInventAReplacement() {
        #expect(
            LaunchIdentity.decision(for: "/same/reachd", resolving: { $0 })
                == .continueInPlace
        )
        #expect(
            LaunchIdentity.decision(for: "/alias/reachd", resolving: { _ in "/real/reachd" })
                == .reexecute("/real/reachd")
        )
    }

    @Test func replacementRewritesOnlyArgvZeroAndReturnsFailureForTheCaller() {
        let original = ["alias/reachd", "value with spaces", ""]
        let allocated = original.map { strdup($0)! }
        defer { allocated.forEach { free($0) } }
        var source = allocated.map(Optional.some) + [nil]

        var receivedExecutable: String?
        var receivedArguments: [String] = []
        var receivedTerminatorWasNil = false
        let failure = source.withUnsafeMutableBufferPointer { buffer in
            LaunchIdentity.replaceCurrentProcess(
                with: "/canonical path/reachd",
                argumentCount: Int32(original.count),
                arguments: buffer.baseAddress!,
                using: { executable, arguments in
                    receivedExecutable = String(cString: executable)
                    receivedArguments = (0..<original.count).map { index in
                        String(cString: arguments![index]!)
                    }
                    receivedTerminatorWasNil = arguments![original.count] == nil
                    errno = EACCES
                    return -1
                }
            )
        }

        #expect(failure == EACCES)
        #expect(receivedExecutable == "/canonical path/reachd")
        #expect(receivedArguments == ["/canonical path/reachd", "value with spaces", ""])
        #expect(receivedTerminatorWasNil)

        // Reaching this assertion is the contract used by ReachdMain: an
        // unexpected replacement failure returns to the ordinary command.
        #expect(source[0] == allocated[0])
    }
}
