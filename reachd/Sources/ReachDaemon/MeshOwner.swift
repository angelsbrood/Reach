import Darwin
import Foundation

/// Read-only evidence about the root-owned process that owns only the mesh.
/// No method here asks for privilege or changes the interface.
package enum MeshOwner {
    package static let label = "systems.reach.meshd"
    package static let helperVersion = "2"
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
        package struct Direct: Sendable, Equatable {
            package let ready: Bool
            package let digest: String
            package let peerCount: Int
        }

        package struct Relay: Sendable, Equatable {
            package let configured: Bool
            package let ready: Bool
            package let digest: String
            package let address: String
            package let routeCount: Int
            package let hubPeerCount: Int
        }

        package let helperVersion: String
        package let pid: Int32
        package let generation: UInt64
        package let publicDigest: String
        package let interfaceName: String
        package let ready: Bool
        package let peerCount: Int
        package let updatedAt: Date
        package let error: String?
        package var direct: Direct? = nil
        package var relay: Relay? = nil

        package static func decode(_ data: Data) throws -> Status {
            let root = try StrictJSON.parse(data)
            guard case .object(let object) = root else {
                throw MeshIntentError.refused("mesh owner status is not an object")
            }
            let common = Set([
                "helperVersion", "pid", "generation", "publicDigest", "interfaceName",
                "ready", "peerCount", "updatedAt",
            ])
            let keys = Set(object.keys)
            let helperVersion = try object.string("helperVersion")
            let required: Set<String>
            switch helperVersion {
            case "1": required = common
            case Self.currentVersion: required = common.union(["direct", "relay"])
            default: throw MeshIntentError.refused("mesh owner status helper version is unsupported")
            }
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
                    "mesh owner unavailable", "updating",
                ])
                guard allowed.contains(error!) else {
                    throw MeshIntentError.refused("mesh owner status error is not bounded")
                }
            } else {
                error = nil
            }
            let publicDigest = try object.string("publicDigest")
            let interfaceName = try object.string("interfaceName")
            let ready = try object.boolean("ready")
            let generation = try object.unsigned("generation")
            guard !helperVersion.isEmpty, helperVersion.utf8.count <= 16 else {
                throw MeshIntentError.refused("mesh owner status helper version is invalid")
            }
            let direct: Direct?
            let relay: Relay?
            if helperVersion == Self.currentVersion {
                let directObject = try object.value("direct").object(exactly: ["ready", "digest", "peerCount"])
                let directReady = try directObject.boolean("ready")
                let directPeerCount = try directObject.integer("peerCount")
                let directDigest = try directObject.string("digest")
                guard (0...MeshIntent.maximumPeers).contains(directPeerCount),
                      Self.validDigest(directDigest, allowEmpty: !directReady),
                      !directReady || (directPeerCount > 0 && !directDigest.isEmpty)
                else {
                    throw MeshIntentError.refused("mesh owner direct status is invalid")
                }
                direct = Direct(
                    ready: directReady,
                    digest: directDigest,
                    peerCount: directPeerCount
                )
                let relayObject = try object.value("relay").object(exactly: [
                    "configured", "ready", "digest", "address", "routeCount", "hubPeerCount",
                ])
                let configured = try relayObject.boolean("configured")
                let relayReady = try relayObject.boolean("ready")
                let relayDigest = try relayObject.string("digest")
                let relayAddress = try relayObject.string("address")
                let routeCount = try relayObject.integer("routeCount")
                let hubPeerCount = try relayObject.integer("hubPeerCount")
                guard (0...MeshIntent.maximumPeers).contains(routeCount), (0...1).contains(hubPeerCount),
                      Self.validDigest(relayDigest, allowEmpty: !configured),
                      configured
                        ? !relayDigest.isEmpty && Self.validRelayAddress(relayAddress)
                            && routeCount > 0 && hubPeerCount == 1
                        : relayDigest.isEmpty && relayAddress.isEmpty
                            && routeCount == 0 && hubPeerCount == 0
                else {
                    throw MeshIntentError.refused("mesh owner relay status is invalid")
                }
                relay = Relay(
                    configured: configured,
                    ready: relayReady,
                    digest: relayDigest,
                    address: relayAddress,
                    routeCount: routeCount,
                    hubPeerCount: hubPeerCount
                )
                guard directPeerCount == peerCount,
                      ready == (directReady && relayReady)
                else {
                    throw MeshIntentError.refused("mesh owner component readiness disagrees")
                }
            } else {
                direct = nil
                relay = nil
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
            if ready {
                guard generation > 0, !publicDigest.isEmpty, !interfaceName.isEmpty, peerCount > 0 else {
                    throw MeshIntentError.refused("mesh owner status readiness fields disagree")
                }
                let allowedReadyErrors = Set(["configuration rejected", "update refused", "rollback restored"])
                guard error.map(allowedReadyErrors.contains) ?? true else {
                    throw MeshIntentError.refused("mesh owner status ready/error fields disagree")
                }
            } else {
                guard error != nil else {
                    throw MeshIntentError.refused("mesh owner status readiness fields disagree")
                }
                guard error != "rollback restored" else {
                    throw MeshIntentError.refused("mesh owner status ready/error fields disagree")
                }
                let hasRecoveryContext = generation > 0 || !publicDigest.isEmpty || peerCount > 0
                guard !hasRecoveryContext || (generation > 0 && !publicDigest.isEmpty && peerCount > 0) else {
                    throw MeshIntentError.refused("mesh owner status recovery fields disagree")
                }
                let partialRelayOutcomes = Set(["updating", "configuration rejected", "update refused"])
                if error.map(partialRelayOutcomes.contains) == true,
                   direct?.ready == true, relay?.ready == false
                {
                    guard helperVersion == Self.currentVersion,
                          hasRecoveryContext, !interfaceName.isEmpty
                    else {
                        throw MeshIntentError.refused("mesh owner updating status is invalid")
                    }
                } else {
                    guard interfaceName.isEmpty,
                          direct?.ready != true, relay?.ready != true
                    else {
                        throw MeshIntentError.refused("mesh owner unavailable status is invalid")
                    }
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
                error: error,
                direct: direct,
                relay: relay
            )
        }

        private static let currentVersion = "2"

        private static func validDigest(_ value: String, allowEmpty: Bool) -> Bool {
            if value.isEmpty { return allowEmpty }
            let lowercaseHex = CharacterSet(charactersIn: "0123456789abcdef")
            return value.utf8.count == 64 && value.unicodeScalars.allSatisfy(lowercaseHex.contains)
        }

        private static func validRelayAddress(_ value: String) -> Bool {
            guard value.hasSuffix("/32") else { return false }
            let host = value.dropLast(3)
            let pieces = host.split(separator: ".", omittingEmptySubsequences: false)
            guard pieces.count == 4 else { return false }
            let octets = pieces.compactMap { piece -> UInt8? in
                guard let octet = UInt8(piece), String(octet) == piece else { return nil }
                return octet
            }
            guard octets.count == 4, octets[3] == 1 else { return false }
            let isPrivate = octets[0] == 10
                || (octets[0] == 172 && (16...31).contains(octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
            return isPrivate && Array(octets.prefix(3)) != [10, 86, 0]
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

    package struct PathEvidence: Sendable, Equatable {
        package var addresses: [LocalAddresses.IPv4Entry]
        package var routes: [MeshIPv4RouteEntry]

        package init(addresses: [LocalAddresses.IPv4Entry], routes: [MeshIPv4RouteEntry]) {
            self.addresses = addresses
            self.routes = routes
        }

        package static func current() throws -> PathEvidence {
            PathEvidence(
                addresses: LocalAddresses.ipv4Entries(),
                routes: try MeshRelayRouteInventory.currentEntries()
            )
        }
    }

    package enum PathInspection: Sendable, Equatable {
        case available(PathEvidence)
        case unavailable
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
        let pathInspection: PathInspection
        do {
            pathInspection = .available(try PathEvidence.current())
        } catch {
            pathInspection = .unavailable
        }
        return verdict(
            intent: intent,
            addresses: addresses,
            evidence: evidence ?? inspect(),
            pathEvidence: pathInspection
        )
    }

    package static func verdict(
        intent: Result<MeshIntent?, Error>,
        addresses: [[UInt8]],
        evidence: Evidence,
        pathEvidence: PathInspection? = nil
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
        guard status.helperVersion == "1" || status.helperVersion == helperVersion else {
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
        guard let desired else {
            return .init(level: .fail, title: "mesh owner", detail: "helper has configuration but login-owned mesh intent is absent")
        }
        if !status.ready {
            if status.helperVersion == helperVersion,
               status.direct?.ready == true,
               status.relay?.ready == false
            {
                let outcome = status.error == "updating"
                    ? "relay authority update is in progress"
                    : "relay authority is not ready — \(status.error ?? "mesh owner unavailable")"
                return .init(
                    level: .wait,
                    title: "mesh owner",
                    detail: "direct mesh remains ready on \(status.interfaceName); \(outcome)",
                    action: "Wait for the bounded helper transaction to finish, then run doctor again."
                )
            }
            return .init(
                level: .fail,
                title: "mesh owner",
                detail: "generation \(status.generation) is not ready\(status.error.map { " — \($0)" } ?? "")"
            )
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
        if status.helperVersion == helperVersion {
            guard let direct = status.direct,
                  direct.ready,
                  direct.digest == desired.directDigest,
                  direct.peerCount == desired.peers.count
            else {
                return .init(
                    level: .fail,
                    title: "mesh owner",
                    detail: "direct component status does not match login-owned intent" + updateOutcome
                )
            }
            guard let relay = status.relay else {
                return .init(level: .fail, title: "mesh owner", detail: "relay component status is absent" + updateOutcome)
            }
            if let desiredRelay = desired.relay {
                guard relay.configured, relay.ready,
                      relay.digest == desired.relayDigest,
                      relay.address == desiredRelay.address,
                      relay.routeCount == desiredRelay.routes.count,
                      relay.hubPeerCount == 1
                else {
                    return .init(
                        level: .fail,
                        title: "mesh owner",
                        detail: "relay component status does not match login-owned intent" + updateOutcome
                    )
                }
            } else {
                guard !relay.configured, relay.ready, relay.digest.isEmpty,
                      relay.address.isEmpty, relay.routeCount == 0, relay.hubPeerCount == 0
                else {
                    return .init(
                        level: .fail,
                        title: "mesh owner",
                        detail: "relay removal is incomplete or falsely ready" + updateOutcome
                    )
                }
            }
        } else if desired.relay != nil {
            return .init(
                level: .wait,
                title: "mesh owner",
                detail: "the installed v1 helper keeps direct mesh ready but cannot apply pending relay intent",
                action: "Upgrade systems.reach.meshd, then run `reachd mesh apply`."
            )
        }
        if let mismatch = pathMismatch(
            desired: desired,
            status: status,
            fallbackAddresses: addresses,
            evidence: pathEvidence
        ) {
            return .init(level: .fail, title: "mesh owner", detail: mismatch + updateOutcome)
        }
        let relayDetail = desired.relay == nil
            ? "; relay verified absent"
            : "; relay ready at \(desired.relay!.address), \(desired.relay!.routes.count) route\(desired.relay!.routes.count == 1 ? "" : "s")"
        let detail = "root-owned \(label) ready on \(status.interfaceName), generation \(status.generation), \(status.peerCount) direct peer\(status.peerCount == 1 ? "" : "s")" + relayDetail
        return .init(
            level: status.error == nil ? .pass : .warn,
            title: "mesh owner",
            detail: detail + updateOutcome,
            action: status.error == nil ? nil : "The active road is ready. Inspect the rejected or recovered update before retrying it."
        )
    }

    package static func appliedRelayAddress() -> String? {
        guard artifact(at: statusPath, uid: 0, mode: 0o644) == .valid,
              let data = try? Data(contentsOf: URL(fileURLWithPath: statusPath), options: [.mappedIfSafe]),
              let status = try? Status.decode(data),
              status.helperVersion == helperVersion,
              status.relay?.configured == true
        else { return nil }
        return status.relay?.address
    }

    private static func pathMismatch(
        desired: MeshIntent,
        status: Status,
        fallbackAddresses: [[UInt8]],
        evidence: PathInspection?
    ) -> String? {
        let pathEvidence: PathEvidence
        switch evidence {
        case .available(let available):
            pathEvidence = available
        case .unavailable, .none:
            if status.helperVersion == helperVersion {
                return "mesh path could not be inspected"
            }
            guard fallbackAddresses.contains([10, 86, 0, 1]) else {
                return "status claims ready but 10.86.0.1 is absent"
            }
            return desired.relay == nil ? nil : "relay path could not be inspected"
        }
        let interfaceAddresses = pathEvidence.addresses
            .filter { $0.interface == status.interfaceName }
            .map(\.address)
        guard interfaceAddresses.contains([10, 86, 0, 1]) else {
            return "status interface does not own 10.86.0.1"
        }
        var expectedAddresses: Set<[UInt8]> = [[10, 86, 0, 1]]
        if let relay = desired.relay, let octets = ipv4Address(relay.address) {
            expectedAddresses.insert(octets)
        }
        guard expectedAddresses.isSubset(of: Set(interfaceAddresses)) else {
            return "relay alias is absent from the mesh interface"
        }
        let unexpectedAddresses = Set(interfaceAddresses).subtracting(expectedAddresses)
        guard unexpectedAddresses.isEmpty else {
            return "mesh interface holds an unowned IPv4 alias"
        }

        let directNetwork = MeshIPv4Prefix.parse("10.86.0.0/24")!
        let directHost = MeshIPv4Prefix.parse("10.86.0.1/32")!
        let actualRoutes = Set(
            pathEvidence.routes
                .filter { $0.interface == status.interfaceName }
                .map(\.prefix)
        )
        var expectedRelayRoutes = Set<MeshIPv4Prefix>()
        if let relay = desired.relay {
            if let hostRoute = MeshIPv4Prefix.parse(relay.address) {
                expectedRelayRoutes.insert(hostRoute)
            }
            for route in relay.routes {
                guard let parsed = MeshIPv4Prefix.parse(route), actualRoutes.contains(parsed) else {
                    return "relay route is absent or owned by another interface"
                }
                expectedRelayRoutes.insert(parsed)
            }
        }
        guard actualRoutes.contains(directNetwork) else {
            return "direct mesh route is absent from the status interface"
        }
        let unexpectedRoutes = actualRoutes.filter {
            $0 != directNetwork && $0 != directHost && !expectedRelayRoutes.contains($0)
        }
        guard unexpectedRoutes.isEmpty else {
            return desired.relay == nil
                ? "relay removal left an unowned route on the mesh interface"
                : "mesh interface holds an unowned relay route"
        }
        return nil
    }

    private static func ipv4Address(_ cidr: String) -> [UInt8]? {
        guard cidr.hasSuffix("/32") else { return nil }
        let parts = cidr.dropLast(3).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: [UInt8] = []
        for part in parts {
            guard let octet = UInt8(part), String(octet) == part else { return nil }
            result.append(octet)
        }
        return result
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
