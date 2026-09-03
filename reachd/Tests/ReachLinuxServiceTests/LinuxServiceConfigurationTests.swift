import Foundation
import Glibc
import ReachWire
import Testing
@testable import ReachLinuxService

private func endpointJSON(_ address: String, _ port: Int) -> String {
    #"{"address":"\#(address)","port":\#(port)}"#
}

private func configurationJSON(
    schema: String = "1",
    cluster: String = "Synthetic Cluster",
    listenAddress: String = "0.0.0.0",
    listenPort: Int = 4433,
    roads: [(String, Int)] = [("192.0.2.10", 4433)],
    caPath: String = "/etc/reach/tls/ca.pem",
    certificatePath: String = "/etc/reach/tls/server-chain.pem",
    keyPath: String = "/etc/reach/tls/server-key.pem",
    modelID: String = "synthetic-model",
    exoEndpoint: String = "http://127.0.0.1:52415"
) -> String {
    let roadJSON = roads.map(endpointJSON).joined(separator: ",")
    return #"{"schemaVersion":\#(schema),"clusterDisplayName":"\#(cluster)","listen":{"address":"\#(listenAddress)","port":\#(listenPort)},"advertisedRoads":[\#(roadJSON)],"tls":{"clusterCACertificatePath":"\#(caPath)","serverCertificateChainPath":"\#(certificatePath)","serverPrivateKeyPath":"\#(keyPath)"},"modelID":"\#(modelID)","exoEndpoint":"\#(exoEndpoint)"}"#
}

private func decode(_ source: String) throws -> LinuxServiceConfiguration {
    try LinuxServiceConfiguration.decode(Data(source.utf8))
}

private func expectRejected(_ source: String, sourceLocation: SourceLocation = #_sourceLocation) {
    do {
        _ = try decode(source)
        Issue.record("configuration unexpectedly decoded", sourceLocation: sourceLocation)
    } catch {
        // The exact public contract is refusal before bind; detailed strings
        // deliberately remain non-normative and privacy bounded.
    }
}

@Suite(.serialized) struct LinuxServiceConfigurationTests {
    @Test func exactSchemaAndRoadOrderArePreserved() throws {
        let configuration = try decode(configurationJSON(
            listenAddress: "::",
            roads: [
                ("2001:db8::1", 4433),
                ("192.0.2.10", 8443),
                ("192.0.2.10", 9443),
            ]
        ))
        #expect(configuration.schemaVersion == 1)
        #expect(configuration.listen == .init(address: "::", port: 4433))
        #expect(configuration.advertisedRoads.map(\.road) == [
            RoadEndpoint(host: "2001:db8::1", port: 4433),
            RoadEndpoint(host: "192.0.2.10", port: 8443),
            RoadEndpoint(host: "192.0.2.10", port: 9443),
        ])
        let ack = configuration.helloAck(version: 1, capabilities: [])
        #expect(ack.roads == configuration.advertisedRoads.map(\.road))
        #expect(ack.addrs == nil)
        #expect(ack.port == nil)
    }

    @Test func duplicateUnknownMissingNullWrongTypeAndTrailingValuesRefuse() {
        expectRejected(configurationJSON().replacingOccurrences(
            of: #""schemaVersion":1,"#,
            with: #""schemaVersion":1,"schemaVersion":1,"#
        ))
        expectRejected(configurationJSON().replacingOccurrences(
            of: #""port":4433}"#,
            with: #""port":4433,"port":4433}"#
        ))
        expectRejected(configurationJSON().replacingOccurrences(
            of: #""modelID":"synthetic-model""#,
            with: #""modelID":"synthetic-model","unknown":true"#
        ))
        expectRejected(configurationJSON().replacingOccurrences(
            of: #""exoEndpoint":"http://127.0.0.1:52415""#,
            with: #""missingEndpoint":"http://127.0.0.1:52415""#
        ))
        expectRejected(configurationJSON().replacingOccurrences(
            of: #""exoEndpoint":"http://127.0.0.1:52415""#,
            with: #""exoEndpoint":null"#
        ))
        expectRejected(configurationJSON().replacingOccurrences(
            of: #""advertisedRoads":["#,
            with: #""advertisedRoads":"#
        ))
        expectRejected(configurationJSON() + "{}")
    }

    @Test func schemaVersionMustBeTheLiteralJSONIntegerOne() {
        for spelling in ["0", "2", "1.0", "1e0", #""1""#, "true", "null"] {
            expectRejected(configurationJSON(schema: spelling))
        }
    }

    @Test func documentBoundaryIsExact() throws {
        let source = configurationJSON()
        let acceptedPadding = String(
            repeating: " ",
            count: LinuxServiceConfiguration.maximumDocumentBytes - source.utf8.count
        )
        #expect(try decode(source + acceptedPadding).modelID == "synthetic-model")
        expectRejected(source + acceptedPadding + " ")
    }

    @Test func stringBoundsNFCAndControlsAreStrict() throws {
        #expect(try decode(configurationJSON(
            cluster: String(repeating: "c", count: 128),
            modelID: String(repeating: "m", count: 256)
        )).clusterDisplayName.utf8.count == 128)
        expectRejected(configurationJSON(cluster: String(repeating: "c", count: 129)))
        expectRejected(configurationJSON(modelID: String(repeating: "m", count: 257)))
        expectRejected(configurationJSON(cluster: "e\u{301}"))
        expectRejected(configurationJSON(cluster: "line\\nfeed"))
        expectRejected(configurationJSON(exoEndpoint: String(repeating: "a", count: 257)))
    }

    @Test func exactLoopbackProviderAndPortBoundsRefuseWidening() {
        for endpoint in [
            "https://127.0.0.1:52415",
            "http://localhost:52415",
            "http://0.0.0.0:52415",
            "http://127.0.0.1:52415/path",
            "http://127.0.0.1:52415?query",
        ] {
            expectRejected(configurationJSON(exoEndpoint: endpoint))
        }
        expectRejected(configurationJSON(listenPort: 1023))
        expectRejected(configurationJSON(listenPort: 65536))
        expectRejected(configurationJSON().replacingOccurrences(of: #""port":4433"#, with: #""port":4433.0"#))
    }

    @Test func numericAddressCanonicalizationAndWildcardRulesAreStrict() throws {
        #expect(try decode(configurationJSON(listenAddress: "0.0.0.0")).listen.address == "0.0.0.0")
        #expect(try decode(configurationJSON(listenAddress: "::")).listen.address == "::")
        for address in ["localhost", "192.000.002.010", "2001:0db8::1", "fe80::1%eth0"] {
            expectRejected(configurationJSON(listenAddress: address))
        }
        expectRejected(configurationJSON(roads: [("0.0.0.0", 4433)]))
        expectRejected(configurationJSON(roads: [("::", 4433)]))
        expectRejected(configurationJSON(roads: [("192.0.2.10", 4433), ("192.0.2.10", 4433)]))
        expectRejected(configurationJSON(roads: [("2001:0db8::1", 4433), ("2001:db8::1", 4433)]))
    }

    @Test func roadCountBoundsAreExact() throws {
        expectRejected(configurationJSON(roads: []))
        #expect(try decode(configurationJSON(roads: [("192.0.2.1", 4433)])).advertisedRoads.count == 1)
        let sixteen = (1 ... 16).map { ("192.0.2.\($0)", 4433) }
        #expect(try decode(configurationJSON(roads: sixteen)).advertisedRoads.count == 16)
        let seventeen = (1 ... 17).map { ("192.0.2.\($0)", 4433) }
        expectRejected(configurationJSON(roads: seventeen))
    }

    @Test func tlsPathsStayCanonicalDistinctAndInsideOperatorRoot() throws {
        let maximum = "/etc/reach/" + String(repeating: "a", count: 4_096 - "/etc/reach/".utf8.count)
        #expect(try decode(configurationJSON(caPath: maximum)).tls.clusterCACertificatePath.utf8.count == 4_096)
        expectRejected(configurationJSON(caPath: maximum + "a"))
        for path in ["tls/ca.pem", "/tmp/ca.pem", "/etc/reach/tls/../ca.pem", "/etc/reach//tls/ca.pem"] {
            expectRejected(configurationJSON(caPath: path))
        }
        expectRejected(configurationJSON(
            caPath: "/etc/reach/tls/same.pem",
            certificatePath: "/etc/reach/tls/same.pem"
        ))
    }

    @Test func secureFileBoundaryRejectsModeOwnerSymlinkHardlinkAndTraversal() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("reach-linux-files-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let original = root.appendingPathComponent("config.json")
        try Data("{}".utf8).write(to: original)
        #expect(chmod(original.path, 0o600) == 0)
        let authority = LinuxSecureFile.Authority(owner: getuid(), group: getgid(), mode: 0o600)
        #expect(try LinuxSecureFile.read(
            path: original.path,
            authority: authority,
            maximumBytes: 16,
            allowedRoot: root.path
        ) == Data("{}".utf8))

        #expect(chmod(original.path, 0o644) == 0)
        #expect(throws: (any Error).self) {
            try LinuxSecureFile.validate(path: original.path, authority: authority, allowedRoot: root.path)
        }
        #expect(chmod(original.path, 0o600) == 0)
        #expect(throws: (any Error).self) {
            try LinuxSecureFile.validate(
                path: original.path,
                authority: .init(owner: getuid() &+ 1, group: getgid(), mode: 0o600),
                allowedRoot: root.path
            )
        }

        let hardlink = root.appendingPathComponent("hardlink.json")
        #expect(link(original.path, hardlink.path) == 0)
        #expect(throws: (any Error).self) {
            try LinuxSecureFile.validate(path: original.path, authority: authority, allowedRoot: root.path)
        }
        try FileManager.default.removeItem(at: hardlink)

        let symlink = root.appendingPathComponent("symlink.json")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: original)
        #expect(throws: (any Error).self) {
            try LinuxSecureFile.validate(path: symlink.path, authority: authority, allowedRoot: root.path)
        }

        let realDirectory = root.appendingPathComponent("real")
        try FileManager.default.createDirectory(at: realDirectory, withIntermediateDirectories: false)
        let nested = realDirectory.appendingPathComponent("nested.json")
        try Data("{}".utf8).write(to: nested)
        #expect(chmod(nested.path, 0o600) == 0)
        let linkedDirectory = root.appendingPathComponent("linked-directory")
        try FileManager.default.createSymbolicLink(
            at: linkedDirectory,
            withDestinationURL: realDirectory
        )
        #expect(throws: (any Error).self) {
            try LinuxSecureFile.validate(
                path: linkedDirectory.appendingPathComponent("nested.json").path,
                authority: authority,
                allowedRoot: root.path
            )
        }
        #expect(throws: (any Error).self) {
            try LinuxSecureFile.validate(
                path: root.appendingPathComponent("../outside").path,
                authority: authority,
                allowedRoot: root.path
            )
        }
    }
}
