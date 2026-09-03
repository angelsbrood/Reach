import Foundation
import Glibc
import ReachLinuxTransport
import Testing
@testable import ReachLinuxService

private let reachdRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()

private func productFile(_ relative: String) throws -> String {
    try String(contentsOf: reachdRoot.appendingPathComponent(relative), encoding: .utf8)
}

private func fixedConfiguration() throws -> LinuxServiceConfiguration {
    let source = #"{"schemaVersion":1,"clusterDisplayName":"Synthetic Cluster","listen":{"address":"0.0.0.0","port":4433},"advertisedRoads":[{"address":"192.0.2.10","port":4433}],"tls":{"clusterCACertificatePath":"/etc/reach/tls/ca.pem","serverCertificateChainPath":"/etc/reach/tls/server-chain.pem","serverPrivateKeyPath":"/etc/reach/tls/server-key.pem"},"modelID":"synthetic-model","exoEndpoint":"http://127.0.0.1:52415"}"#
    return try LinuxServiceConfiguration.decode(Data(source.utf8))
}

private func sourceIdentifiers(_ source: String) -> Set<String> {
    var result: Set<String> = []
    var token = ""
    func flush() {
        guard let first = token.unicodeScalars.first,
              CharacterSet.letters.union(CharacterSet(charactersIn: "_")).contains(first) else {
            token = ""
            return
        }
        result.insert(token)
        token = ""
    }
    for scalar in source.unicodeScalars {
        if CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_")).contains(scalar) {
            token.unicodeScalars.append(scalar)
        } else {
            flush()
        }
    }
    flush()
    return result
}

private func previewOnlyIdentifiers(_ header: String) -> Set<String> {
    struct Conditional {
        var parentWasPreview: Bool
        var conditionIsPreview: Bool
    }
    var conditionals: [Conditional] = []
    var inPreview = false
    var preview: Set<String> = []
    var stable: Set<String> = []
    for line in header.split(separator: "\n", omittingEmptySubsequences: false) {
        let text = String(line)
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("#if") {
            let conditional = Conditional(
                parentWasPreview: inPreview,
                conditionIsPreview: trimmed.contains("QUIC_API_ENABLE_PREVIEW_FEATURES")
            )
            conditionals.append(conditional)
            inPreview = conditional.parentWasPreview || conditional.conditionIsPreview
            continue
        }
        if trimmed.hasPrefix("#else"), let conditional = conditionals.last {
            inPreview = conditional.parentWasPreview
            continue
        }
        if trimmed.hasPrefix("#endif"), let conditional = conditionals.popLast() {
            inPreview = conditional.parentWasPreview
            continue
        }
        if inPreview {
            preview.formUnion(sourceIdentifiers(text))
        } else {
            stable.formUnion(sourceIdentifiers(text))
        }
    }
    return Set(preview.subtracting(stable).filter { identifier in
        identifier.hasPrefix("QUIC_") || identifier.first?.isUppercase == true
    })
}

@Suite(.serialized) struct LinuxServiceRuntimeTests {
    @Test func statusIsPrivacySafeBoundedAndAtomicallyReplaced() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-linux-status-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("status.json").path
        let metrics = LinuxTransportMetrics(
            rawConnections: 9,
            acceptedConnections: 4,
            activeConnections: 2,
            refusedConnections: 5,
            acceptedStreams: 6,
            activeStreams: 1,
            refusedStreams: 3,
            peakConnections: 4,
            peakStreams: 6
        )
        let status = LinuxServiceStatus(
            configuration: try fixedConfiguration(),
            ready: true,
            metrics: metrics,
            lastError: String(repeating: "é", count: 400)
        )
        #expect(status.lastError?.utf8.count == 512)
        try LinuxStatusWriter.write(status, path: path)
        var metadata = stat()
        #expect(lstat(path, &metadata) == 0)
        #expect(metadata.st_mode & 0o7777 == 0o600)
        #expect(metadata.st_nlink == 1)

        let decoded = try JSONDecoder().decode(
            LinuxServiceStatus.self,
            from: Data(contentsOf: URL(fileURLWithPath: path))
        )
        #expect(decoded == status)
        let encoded = try productStatusKeys(path)
        #expect(encoded == Set([
            "schemaVersion", "pid", "ready", "modelID", "boundAddress", "boundPort",
            "activeConnections", "activeStreams", "acceptedConnections", "acceptedStreams",
            "refusedConnections", "refusedStreams", "lastError",
        ]))

        var stopped = status
        stopped.ready = false
        stopped.lastError = nil
        try LinuxStatusWriter.write(stopped, path: path)
        #expect(try JSONDecoder().decode(
            LinuxServiceStatus.self,
            from: Data(contentsOf: URL(fileURLWithPath: path))
        ).ready == false)
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: root.path)
        #expect(leftovers == ["status.json"])
    }

    @Test func systemdUnitPinsEveryServiceAndResourceBoundary() throws {
        let unit = try productFile("Linux/package/usr/lib/systemd/system/reachd.service")
        for required in [
            "Type=notify", "NotifyAccess=main", "User=reachd", "Group=reachd",
            "ExecStart=/usr/lib/reach/reachd-linux", "UMask=0077",
            "Restart=on-failure", "RestartPreventExitStatus=64", "RestartSec=2s",
            "StartLimitIntervalSec=60s", "StartLimitBurst=3",
            "TimeoutStartSec=10s", "TimeoutStopSec=15s",
            "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
            "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
            "PrivateDevices=true", "DevicePolicy=closed",
            "ReadOnlyPaths=/etc/reach", "ReadWritePaths=/var/lib/reach /run/reach",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "SystemCallFilter=@system-service", "SystemCallErrorNumber=EPERM",
            "LimitNOFILE=1024", "LimitNPROC=128", "TasksMax=128",
            "MemoryHigh=768M", "MemoryMax=1G",
        ] {
            #expect(unit.contains(required), "missing \(required)")
        }
        for forbidden in [
            "/bin/sh", "/bin/bash", "User=root", "ExecStartPre=", "ExecStartPost=",
            "EnvironmentFile=", "sudo", "curl", "wget", "Bonjour", "avahi",
        ] {
            #expect(!unit.contains(forbidden), "unit contains \(forbidden)")
        }
    }

    @Test func expectedStartupRefusalsAreNoRestartButRuntimeFailureRestarts() {
        let expected: [any Error] = [
            LinuxServiceConfigurationError.invalid("fixture"),
            LinuxServiceConfigurationError.unsafeFile("fixture"),
            LinuxServiceRuntimeError.startupRefused(.exoPreflight, "fixture"),
            LinuxServiceRuntimeError.startupRefused(.credentialOrListener, "fixture"),
            LinuxTransportError.startup("fixture"),
        ]
        for error in expected {
            #expect(LinuxServiceExitStatus.code(for: error) == LinuxServiceExitStatus.noRestart)
        }
        #expect(LinuxServiceExitStatus.code(for: LinuxServiceRuntimeError.runtime("fixture")) ==
            LinuxServiceExitStatus.unexpectedRuntimeFailure)
        #expect(LinuxServiceExitStatus.noRestart == 64)
        #expect(LinuxServiceExitStatus.unexpectedRuntimeFailure == 1)
    }

    @Test func firstStopRequestKeepsItsOriginalAbsoluteDeadline() async {
        let latch = LinuxStopLatch()
        let first = LinuxStopRequest(
            reason: .signal(SIGTERM),
            deadline: LinuxShutdownDeadline(monotonicNanoseconds: 20_000_000_000)
        )
        await latch.request(first)
        await latch.request(LinuxStopRequest(
            reason: .failure("later"),
            deadline: LinuxShutdownDeadline(monotonicNanoseconds: 35_000_000_000)
        ))
        #expect(await latch.wait() == first)
    }

    @Test func installIsInertAndRemovalPreservesOperatorConfiguration() throws {
        let postinst = try productFile("Linux/package/DEBIAN/postinst")
        let prerm = try productFile("Linux/package/DEBIAN/prerm")
        let postrm = try productFile("Linux/package/DEBIAN/postrm")
        let sysusers = try productFile("Linux/package/usr/lib/sysusers.d/reachd.conf")
        let tmpfiles = try productFile("Linux/package/usr/lib/tmpfiles.d/reachd.conf")
        for forbidden in ["enable", " start", "curl", "wget", "openssl", "/etc/reach"] {
            #expect(!postinst.contains(forbidden), "postinst contains \(forbidden)")
        }
        #expect(postinst.contains("systemd-sysusers"))
        #expect(prerm.contains("disable --now reachd.service"))
        #expect(postrm.contains("/var/lib/reach /run/reach"))
        #expect(!postrm.contains("/etc/reach"))
        #expect(sysusers == "u reachd - \"Reach service\" - /usr/sbin/nologin\n")
        #expect(tmpfiles.contains("d /var/lib/reach 0700 reachd reachd -"))
        #expect(tmpfiles.contains("d /run/reach 0700 reachd reachd -"))
    }

    @Test func LinuxTargetClosureExcludesAppleAndModelStacks() throws {
        let package = try productFile("Package.swift")
        let linuxStart = try #require(package.range(of: "#if os(Linux)"))
        let linuxEnd = try #require(package.range(of: "#else", range: linuxStart.upperBound ..< package.endIndex))
        let linux = String(package[linuxStart.lowerBound ..< linuxEnd.lowerBound])
        for forbidden in [
            ".product(name: \"ReachKit\"", "ReachTransport\"", "ReachIdentity\"", "MLX", "HuggingFace",
            "Transformers", "X509", "Metal", "CoreImage", "ImageIO", "Network",
        ] {
            #expect(!linux.contains(forbidden), "Linux target closure contains \(forbidden)")
        }
        #expect(linux.contains("ReachHost"))
        #expect(linux.contains("ReachWire"))
        #expect(linux.contains("CReachLinuxMsQuic"))
        #expect(linux.contains("reachd-linux"))
    }

    @Test func CShimUsesOnlyTheSelectedPreviewSurface() throws {
        let source = try productFile("Sources/CReachLinuxMsQuic/CReachLinuxMsQuic.c")
        #expect(source.contains("#define QUIC_API_ENABLE_PREVIEW_FEATURES 1"))
        #expect(source.contains("QUIC_VERSION_SETTINGS"))
        #expect(source.contains("QUIC_PARAM_GLOBAL_VERSION_SETTINGS"))
        #expect(!source.contains("StreamMultiReceiveEnabled"))
        let header = try productFile("Sources/CReachLinuxMsQuic/vendor/msquic.h")
        let allowedPreviewIdentifiers: Set<String> = [
            "QUIC_API_ENABLE_PREVIEW_FEATURES",
            "QUIC_VERSION_SETTINGS",
            "QUIC_PARAM_GLOBAL_VERSION_SETTINGS",
            // These are the fields of the one permitted preview structure,
            // not additional preview APIs.
            "AcceptableVersions",
            "OfferedVersions",
            "FullyDeployedVersions",
            "AcceptableVersionsLength",
            "OfferedVersionsLength",
            "FullyDeployedVersionsLength",
        ]
        let unauthorizedPreviewIdentifiers = sourceIdentifiers(source)
            .intersection(previewOnlyIdentifiers(header))
            .subtracting(allowedPreviewIdentifiers)
        #expect(
            unauthorizedPreviewIdentifiers.isEmpty,
            "C shim uses unauthorized preview identifiers: \(unauthorizedPreviewIdentifiers.sorted())"
        )
        for forbidden in [
            "StreamProvideReceiveBuffers", "ConnectionPoolCreate", "ExecutionCreate",
            "QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED",
            "QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED",
            "QUIC_CONNECTION_EVENT_NETWORK_STATISTICS",
        ] {
            #expect(!source.contains(forbidden), "C shim uses \(forbidden)")
        }
        #expect(source.contains("QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION"))
        #expect(source.contains("QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION"))
        #expect(!source.contains("NO_CERTIFICATE_VALIDATION"))
        #expect(source.contains("QUIC_SERVER_NO_RESUME"))
        #expect(source.contains("DatagramReceiveEnabled = FALSE"))
        #expect(source.contains("MigrationEnabled = FALSE"))
        #expect(source.contains("QUIC_BUFFER receive_buffers[REACH_RECEIVE_DESCRIPTOR_LIMIT]"))
        #expect(source.contains("memcpy(\n            stream->receive_buffers"))
        #expect(source.contains("return QUIC_STATUS_PENDING"))
        #expect(source.contains("StreamReceiveComplete"))
        #expect(source.contains("TakePendingReceiveLocked"))
        #expect(source.contains("active_api_calls"))
        #expect(source.contains("shutdown_complete"))
        #expect(source.contains("#define REACH_RECEIVE_DESCRIPTOR_LIMIT 2U"))
    }

    private func productStatusKeys(_ path: String) throws -> Set<String> {
        let object = try JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: path))
        )
        return Set(try #require(object as? [String: Any]).keys)
    }
}
