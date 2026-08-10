import Darwin
import Foundation

/// Decides whether this process already has the one executable identity its
/// adjacent SwiftPM resources belong to.
///
/// macOS resolves the loaded Mach-O image through a symlink, but
/// `Bundle.main` remains anchored beside the spelling used to launch it. MLX's
/// SwiftPM resource lookup follows `Bundle.main`, so an installed command
/// reached through `~/.local/bin` can load the right executable and still look
/// in the wrong directory for `default.metallib`.
package enum LaunchIdentityDecision: Equatable, Sendable {
    case continueInPlace
    case reexecute(String)
}

package enum LaunchIdentity {
    package typealias ProcessReplacement = (
        UnsafePointer<CChar>,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    ) -> Int32

    /// The decision for the process that is running now.
    package static func currentDecision() -> LaunchIdentityDecision {
        guard let reportedPath = reportedExecutablePath() else {
            return .continueInPlace
        }
        return decision(for: reportedPath)
    }

    /// Pure apart from the supplied resolver, so every path shape can be held
    /// in a test without replacing the test process.
    package static func decision(
        for reportedPath: String,
        resolving resolve: (String) -> String?
    ) -> LaunchIdentityDecision {
        guard let canonicalPath = resolve(reportedPath),
              canonicalPath != reportedPath
        else {
            return .continueInPlace
        }
        return .reexecute(canonicalPath)
    }

    package static func decision(for reportedPath: String) -> LaunchIdentityDecision {
        decision(for: reportedPath, resolving: canonicalPath)
    }

    /// `_NSGetExecutablePath` reports the executable spelling used by the
    /// kernel, including an absolute symlink selected through `PATH`.
    package static func reportedExecutablePath() -> String? {
        var size: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &size)
        guard size > 0 else { return nil }

        var buffer = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&buffer, &size) == 0 else { return nil }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// `realpath`, rather than string standardization, is the operation that
    /// collapses every symlink in a nested installed alias.
    package static func canonicalPath(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    /// Replaces the current image while deliberately making argv[0] agree
    /// with the canonical executable. The kernel-owned argv[1...] pointers
    /// are passed through unchanged, including pointers to empty strings.
    ///
    /// A successful `execv` never returns. A failure returns the captured
    /// errno so the tiny executable bootstrap can report it and continue.
    package static func replaceCurrentProcess(with canonicalPath: String) -> Int32 {
        replaceCurrentProcess(
            with: canonicalPath,
            argumentCount: CommandLine.argc,
            arguments: CommandLine.unsafeArgv,
            using: { executable, arguments in
                execv(executable, arguments)
            }
        )
    }

    package static func replaceCurrentProcess(
        with canonicalPath: String,
        argumentCount: Int32,
        arguments sourceArguments: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
        using replace: ProcessReplacement
    ) -> Int32 {
        canonicalPath.withCString { executable in
            var arguments: [UnsafeMutablePointer<CChar>?] = [
                UnsafeMutablePointer(mutating: executable)
            ]
            arguments.reserveCapacity(Int(argumentCount) + 1)
            if argumentCount > 1 {
                for index in 1..<Int(argumentCount) {
                    arguments.append(sourceArguments[index])
                }
            }
            arguments.append(nil)

            arguments.withUnsafeMutableBufferPointer { buffer in
                _ = replace(executable, buffer.baseAddress)
            }
            return errno
        }
    }
}
