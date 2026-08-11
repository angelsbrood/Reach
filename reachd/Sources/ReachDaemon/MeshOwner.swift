import Darwin
import Foundation

/// Read-only evidence about the root-owned process that owns only the mesh.
/// No method here asks for privilege or changes the interface.
package enum MeshOwner {
    package static let label = "systems.reach.meshd"
    package static let helperVersion = "1"
    package static let helperPath = "/Library/PrivilegedHelperTools/systems.reach.meshd"
    package static let plistPath = "/Library/LaunchDaemons/systems.reach.meshd.plist"
    package static let statePath = "/Library/Application Support/Reach Mesh"
    package static let statusPath = statePath + "/status.json"
    package static let logPath = "/var/log/systems.reach.meshd.log"

    package static func applyOperation(input: URL) -> (executable: String, arguments: [String]) {
        (
            "/usr/bin/sudo",
            ["--", helperPath, "apply", "--input", input.path]
        )
    }

    package static func renderOperation(executable: String, arguments: [String]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return ([executable] + arguments).map { value in
            // String encoding cannot fail; JSON quoting makes whitespace,
            // quotes and control characters unambiguous without implying a
            // shell will parse the displayed operation.
            String(decoding: try! encoder.encode(value), as: UTF8.self)
        }.joined(separator: " ")
    }

    package enum Artifact: Sendable, Equatable {
        case absent
        case valid
        case invalid(String)
    }

    package struct Status: Sendable, Equatable {
        package let helperVersion: String
        package let pid: Int32
        package let generation: UInt64
        package let publicDigest: String
        package let interfaceName: String
        package let ready: Bool
        package let peerCount: Int
        package let updatedAt: Date
        package let error: String?

        package static func decode(_ data: Data) throws -> Status {
            let root = try StrictJSON.parse(data)
            guard case .object(let object) = root else {
                throw MeshIntentError.refused("mesh owner status is not an object")
            }
            let required = Set([
                "helperVersion", "pid", "generation", "publicDigest", "interfaceName",
                "ready", "peerCount", "updatedAt",
            ])
            let keys = Set(object.keys)
            guard keys == required || keys == required.union(["error"]) else {
                throw MeshIntentError.refused("mesh owner status has missing or unknown fields")
            }
            let pidValue = try object.integer("pid")
            guard let pid = Int32(exactly: pidValue), pid > 0 else {
                throw MeshIntentError.refused("mesh owner status PID is invalid")
            }
            let peerCount = try object.integer("peerCount")
            guard (0...MeshIntent.maximumPeers).contains(peerCount) else {
                throw MeshIntentError.refused("mesh owner status peer count is invalid")
            }
            let updatedText = try object.string("updatedAt")
            guard let updated = ISO8601DateFormatter().date(from: updatedText) else {
                throw MeshIntentError.refused("mesh owner status timestamp is invalid")
            }
            let error: String?
            if keys.contains("error") {
                error = try object.string("error")
                let allowed = Set([
                    "unconfigured", "configuration rejected", "update refused",
                    "interface unavailable", "rollback restored", "stopped",
                    "mesh owner unavailable",
                ])
                guard allowed.contains(error!) else {
                    throw MeshIntentError.refused("mesh owner status error is not bounded")
                }
            } else {
                error = nil
            }
            let helperVersion = try object.string("helperVersion")
            let publicDigest = try object.string("publicDigest")
            let interfaceName = try object.string("interfaceName")
            let ready = try object.boolean("ready")
            let generation = try object.unsigned("generation")
            guard !helperVersion.isEmpty, helperVersion.utf8.count <= 16 else {
                throw MeshIntentError.refused("mesh owner status helper version is invalid")
            }
            let lowercaseHex = CharacterSet(charactersIn: "0123456789abcdef")
            guard publicDigest.isEmpty || (publicDigest.utf8.count == 64 && publicDigest.unicodeScalars.allSatisfy(lowercaseHex.contains)) else {
                throw MeshIntentError.refused("mesh owner status digest is invalid")
            }
            let interfaceSuffix = interfaceName.dropFirst(4)
            guard interfaceName.isEmpty || (
                interfaceName.hasPrefix("utun")
                    && !interfaceSuffix.isEmpty
                    && interfaceSuffix.utf8.allSatisfy { (0x30...0x39).contains($0) }
            ) else {
                throw MeshIntentError.refused("mesh owner status interface is invalid")
            }
            guard ready
                ? generation > 0 && !publicDigest.isEmpty && !interfaceName.isEmpty && peerCount > 0
                : interfaceName.isEmpty && error != nil
            else {
                throw MeshIntentError.refused("mesh owner status readiness fields disagree")
            }
            if ready {
                let allowedReadyErrors = Set(["configuration rejected", "update refused", "rollback restored"])
                guard error.map(allowedReadyErrors.contains) ?? true else {
                    throw MeshIntentError.refused("mesh owner status ready/error fields disagree")
                }
            } else {
                guard error != "rollback restored" else {
                    throw MeshIntentError.refused("mesh owner status ready/error fields disagree")
                }
                let hasRecoveryContext = generation > 0 || !publicDigest.isEmpty || peerCount > 0
                guard !hasRecoveryContext || (generation > 0 && !publicDigest.isEmpty && peerCount > 0) else {
                    throw MeshIntentError.refused("mesh owner status recovery fields disagree")
                }
            }
            return Status(
                helperVersion: helperVersion,
                pid: pid,
                generation: generation,
                publicDigest: publicDigest,
                interfaceName: interfaceName,
                ready: ready,
                peerCount: peerCount,
                updatedAt: updated,
                error: error
            )
        }
    }

    package struct Evidence: Sendable, Equatable {
        package var helper: Artifact
        package var plist: Artifact
        package var statusFile: Artifact
        package var status: Status?
        package var statusError: String?
        package var launchdPID: Int32?

        package init(
            helper: Artifact,
            plist: Artifact,
            statusFile: Artifact,
            status: Status?,
            statusError: String? = nil,
            launchdPID: Int32?
        ) {
            self.helper = helper
            self.plist = plist
            self.statusFile = statusFile
            self.status = status
            self.statusError = statusError
            self.launchdPID = launchdPID
        }
    }

    package static func finding(
        stateDirectory: URL,
        addresses: [[UInt8]],
        evidence: Evidence? = nil
    ) -> HostCheck.Finding {
        let intent: Result<MeshIntent?, Error>
        let intentURL = MeshIntentStore.intentURL(in: stateDirectory)
        if FileManager.default.fileExists(atPath: intentURL.path) {
            intent = Result { try MeshIntentStore.load(in: stateDirectory) }
        } else {
            intent = .success(nil)
        }
        return verdict(intent: intent, addresses: addresses, evidence: evidence ?? inspect())
    }

    package static func verdict(
        intent: Result<MeshIntent?, Error>,
        addresses: [[UInt8]],
        evidence: Evidence
    ) -> HostCheck.Finding {
        let exactInterface = addresses.contains([10, 86, 0, 1])
        let anyArtifacts = evidence.helper != .absent || evidence.plist != .absent || evidence.statusFile != .absent
        let desiredForAction: MeshIntent?
        if case .success(let desired) = intent {
            desiredForAction = desired
        } else {
            desiredForAction = nil
        }

        for (name, artifact) in [("helper", evidence.helper), ("LaunchDaemon plist", evidence.plist), ("status", evidence.statusFile)] {
            if case .invalid(let reason) = artifact {
                return .init(
                    level: .fail,
                    title: "mesh owner",
                    detail: "invalid \(name) ownership or shape — \(reason)",
                    action: "Restore the root-owned mesh component from its package and do not run a user-writable replacement."
                )
            }
        }
        if evidence.helper == .absent, evidence.plist == .absent, evidence.statusFile == .absent {
            return .init(
                level: .wait,
                title: "mesh owner",
                detail: exactInterface
                    ? "10.86.0.1 is usable but unmanaged — the privileged mesh owner is not installed"
                    : "not installed or configured",
                action: "Install the scriptless systems.reach.meshd package, then run `reachd mesh apply` after a device is enrolled."
            )
        }
        guard evidence.helper == .valid, evidence.plist == .valid else {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "privileged mesh installation is partial",
                action: "Reinstall or uninstall the complete two-item package; do not leave one privileged artifact behind."
            )
        }
        guard let status = evidence.status else {
            if let error = evidence.statusError, anyArtifacts {
                return .init(level: .fail, title: "mesh owner", detail: "status is malformed — \(error)")
            }
            return .init(
                level: .wait,
                title: "mesh owner",
                detail: "installed; waiting for its first configuration",
                action: desiredForAction?.peers.isEmpty == false ? "Run `reachd mesh apply`." : "Enroll a device, then run `reachd mesh apply`."
            )
        }
        let updateOutcome = status.error.map { "; last update outcome: \($0)" } ?? ""
        guard status.helperVersion == helperVersion else {
            return .init(level: .fail, title: "mesh owner", detail: "status names unsupported helper version \(status.helperVersion)")
        }
        guard evidence.launchdPID == status.pid, evidence.launchdPID != nil else {
            return .init(level: .fail, title: "mesh owner", detail: "helper/status PID mismatch")
        }
        if status.error == "unconfigured", !status.ready {
            return .init(
                level: .wait,
                title: "mesh owner",
                detail: "running but unconfigured",
                action: desiredForAction?.peers.isEmpty == false ? "Run `reachd mesh apply`." : "Enroll a device, then run `reachd mesh apply`."
            )
        }
        guard case .success(let desired) = intent else {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "mesh-intent.json is present but invalid",
                action: "Fix the login-owned intent before asking a privileged process to consume it."
            )
        }
        guard status.ready else {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "generation \(status.generation) is not ready\(status.error.map { " — \($0)" } ?? "")"
            )
        }
        guard let desired else {
            return .init(level: .fail, title: "mesh owner", detail: "helper has configuration but login-owned mesh intent is absent")
        }
        if status.generation > desired.generation {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "helper generation \(status.generation) is ahead of intent generation \(desired.generation) — rollback detected" + updateOutcome
            )
        }
        if status.generation == desired.generation, status.publicDigest != desired.publicDigest {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "generation \(status.generation) names a different public configuration digest" + updateOutcome
            )
        }
        if status.generation < desired.generation || status.publicDigest != desired.publicDigest {
            return .init(
                level: .wait,
                title: "mesh owner",
                detail: "running generation \(status.generation); intent generation \(desired.generation) is pending"
                    + (status.error.map { " — \($0)" } ?? ""),
                action: "Run `reachd mesh apply`; this is the visible administrator action for the changed peer set."
            )
        }
        guard !status.interfaceName.isEmpty, exactInterface else {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "status claims ready but 10.86.0.1 is absent" + updateOutcome
            )
        }
        guard status.peerCount == desired.peers.count else {
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "status peer count does not match intent" + updateOutcome
            )
        }
        let detail = "root-owned \(label) ready on \(status.interfaceName), generation \(status.generation), \(status.peerCount) peer\(status.peerCount == 1 ? "" : "s")"
        return .init(
            level: status.error == nil ? .pass : .warn,
            title: "mesh owner",
            detail: detail + updateOutcome,
            action: status.error == nil ? nil : "The active road is ready. Inspect the rejected or recovered update before retrying it."
        )
    }

    package static func inspect() -> Evidence {
        let helper = artifact(at: helperPath, uid: 0, mode: 0o555)
        let plistShape = artifact(at: plistPath, uid: 0, mode: 0o644)
        let plist = plistShape == .valid ? validateInstalledPlist() : plistShape
        let statusArtifact = artifact(at: statusPath, uid: 0, mode: 0o644)
        var status: Status?
        var statusError: String?
        if statusArtifact == .valid {
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: statusPath), options: [.mappedIfSafe])
                status = try Status.decode(data)
            } catch {
                statusError = "\(error)"
            }
        }
        return Evidence(
            helper: helper,
            plist: plist,
            statusFile: statusArtifact,
            status: status,
            statusError: statusError,
            launchdPID: launchdPID()
        )
    }

    private static func artifact(at path: String, uid: uid_t, mode: mode_t) -> Artifact {
        var value = stat()
        guard lstat(path, &value) == 0 else {
            return errno == ENOENT ? .absent : .invalid("will not stat")
        }
        guard value.st_mode & S_IFMT == S_IFREG,
              value.st_uid == uid, value.st_nlink == 1,
              value.st_mode & 0o777 == mode
        else { return .invalid("expected regular uid \(uid) mode \(String(mode, radix: 8))") }
        return .valid
    }

    private static func validateInstalledPlist() -> Artifact {
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: plistPath), options: [.mappedIfSafe])
            return validatePlist(data)
        } catch {
            return .invalid("will not read")
        }
    }

    package static func validatePlist(_ data: Data) -> Artifact {
        do {
            guard let dictionary = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                return .invalid("not a property-list dictionary")
            }
            let expected = Set([
                "Label", "ProgramArguments", "RunAtLoad", "KeepAlive", "ThrottleInterval",
                "Umask", "ProcessType", "StandardOutPath", "StandardErrorPath",
            ])
            guard Set(dictionary.keys) == expected,
                  dictionary["Label"] as? String == label,
                  dictionary["ProgramArguments"] as? [String] == [helperPath, "serve"],
                  dictionary["RunAtLoad"] as? Bool == true,
                  dictionary["KeepAlive"] as? Bool == true,
                  dictionary["ThrottleInterval"] as? Int == 10,
                  dictionary["Umask"] as? Int == 0o77,
                  dictionary["ProcessType"] as? String == "Background",
                  dictionary["StandardOutPath"] as? String == logPath,
                  dictionary["StandardErrorPath"] as? String == logPath
            else {
                return .invalid("launch policy differs from the packaged contract")
            }
            return .valid
        } catch {
            return .invalid("will not parse")
        }
    }

    private static func launchdPID() -> Int32? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "system/\(label)"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(separator: "\n") where line.contains("pid = ") {
            let value = line.split(separator: "=", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces)
            if let value, let pid = Int32(value), pid > 0 { return pid }
        }
        return nil
    }
}
