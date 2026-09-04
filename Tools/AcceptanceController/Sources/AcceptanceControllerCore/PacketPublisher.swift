import Foundation
import Darwin

public struct PacketManifestEntry: Codable, Equatable, Sendable {
    public let path: String
    public let sha256: String
    public let mode: UInt16
    public let linkCount: UInt64
    public let logicalBytes: Int64
}

public struct PacketManifest: Codable, Equatable, Sendable {
    public let version: Int
    public let entries: [PacketManifestEntry]
    public let fileCount: Int
    public let logicalBytes: Int64
}

public struct PublishedPacket: Sendable {
    public let rootDigest: String
    public let manifest: PacketManifest
}

public enum PacketPublisher {
    public static func publish(payloads: [String: Data], finalURL: URL) throws -> PublishedPacket {
        guard payloads.count + 1 <= 96, payloads.keys.allSatisfy(validRelativeName) else {
            throw ControllerError.publication("payload-shape")
        }
        let parent = finalURL.deletingLastPathComponent()
        let staging = parent.appendingPathComponent(".\(finalURL.lastPathComponent).staging-\(UUID().uuidString)")
        try DurableFile.createDirectory(staging)
        var committed = false
        defer { if !committed { try? FileManager.default.removeItem(at: staging) } }
        for name in payloads.keys.sorted() {
            guard let data = payloads[name] else { throw ControllerError.publication("payload-missing") }
            try DurableFile.write(data, to: staging.appendingPathComponent(name))
        }
        let entries = try payloads.keys.sorted().map { name -> PacketManifestEntry in
            let url = staging.appendingPathComponent(name)
            var info = stat()
            guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == getuid(), info.st_nlink == 1, (info.st_mode & 0o777) == 0o600 else {
                throw ControllerError.publication("payload-metadata")
            }
            return PacketManifestEntry(
                path: name, sha256: try SHA256.file(url), mode: UInt16(info.st_mode & 0o777),
                linkCount: UInt64(info.st_nlink), logicalBytes: Int64(info.st_size)
            )
        }
        let logical = entries.reduce(Int64(0)) { $0 + $1.logicalBytes }
        let manifest = PacketManifest(version: 1, entries: entries, fileCount: entries.count + 1, logicalBytes: logical)
        let manifestData = try CanonicalJSON.encode(manifest)
        guard logical + Int64(manifestData.count) <= 8_388_608 else { throw ControllerError.publication("packet-byte-limit") }
        try DurableFile.write(manifestData, to: staging.appendingPathComponent("MANIFEST.json"))
        try DurableFile.fsyncDirectory(staging)
        _ = try verifyDirectory(staging, expectedRoot: SHA256.hex(manifestData))
        let status = staging.path.withCString { source in
            finalURL.path.withCString { destination in
                renameatx_np(AT_FDCWD, source, AT_FDCWD, destination, UInt32(RENAME_EXCL))
            }
        }
        guard status == 0 else {
            if errno == EEXIST { throw ControllerError.publication("collision") }
            throw ControllerError.publication("rename-excl-\(errno)")
        }
        committed = true
        try DurableFile.fsyncDirectory(parent)
        return PublishedPacket(rootDigest: SHA256.hex(manifestData), manifest: manifest)
    }

    public static func verify(_ finalURL: URL) throws -> PublishedPacket {
        try verifyDirectory(finalURL, expectedRoot: nil)
    }

    private static func verifyDirectory(_ directory: URL, expectedRoot: String?) throws -> PublishedPacket {
        var directoryInfo = stat()
        guard lstat(directory.path, &directoryInfo) == 0, (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
              directoryInfo.st_uid == getuid(), (directoryInfo.st_mode & 0o777) == 0o700 else {
            throw ControllerError.verification("packet-directory")
        }
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        guard names.lastIndex(of: "MANIFEST.json") != nil else { throw ControllerError.verification("manifest-missing") }
        let manifestURL = directory.appendingPathComponent("MANIFEST.json")
        let manifestData = try Data(contentsOf: manifestURL, options: .mappedIfSafe)
        let root = SHA256.hex(manifestData)
        if let expectedRoot, root != expectedRoot { throw ControllerError.verification("root") }
        let keys: Set<String> = ["entries", "fileCount", "logicalBytes", "version"]
        let manifest = try CanonicalJSON.decode(PacketManifest.self, from: manifestData, allowedTopLevelKeys: keys)
        guard manifest.version == 1, manifest.fileCount == names.count,
              Set(manifest.entries.map(\.path)).count == manifest.entries.count,
              Set(names) == Set(manifest.entries.map(\.path) + ["MANIFEST.json"]) else {
            throw ControllerError.verification("manifest-shape")
        }
        var logical: Int64 = 0
        for entry in manifest.entries {
            guard validRelativeName(entry.path) else { throw ControllerError.verification("entry-path") }
            let url = directory.appendingPathComponent(entry.path)
            var info = stat()
            guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
                  info.st_uid == getuid(), info.st_nlink == 1,
                  UInt16(info.st_mode & 0o777) == entry.mode, entry.mode == 0o600,
                  Int64(info.st_size) == entry.logicalBytes,
                  try SHA256.file(url) == entry.sha256 else {
                throw ControllerError.verification("entry-\(entry.path)")
            }
            logical += entry.logicalBytes
        }
        guard logical == manifest.logicalBytes else { throw ControllerError.verification("logical-total") }
        let outcomeURL = directory.appendingPathComponent("outcome.json")
        let outcomeData = try Data(contentsOf: outcomeURL)
        let outcomeKeys: Set<String> = ["actionTableDigest", "claimBoundaryDigest", "earliestStopOrdinal", "outcome", "packetBasename", "publicResults", "runLedgerDigest", "sliceLaunchSnapshotDigest", "version"]
        let outcome = try CanonicalJSON.decode(OutcomePayload.self, from: outcomeData, allowedTopLevelKeys: outcomeKeys)
        guard outcome.packetBasename == directory.lastPathComponent,
              try SHA256.file(directory.appendingPathComponent("action-table.json")) == outcome.actionTableDigest,
              try SHA256.file(directory.appendingPathComponent("run-ledger.json")) == outcome.runLedgerDigest,
              try SHA256.file(directory.appendingPathComponent("launch-snapshot.json")) == outcome.sliceLaunchSnapshotDigest else {
            throw ControllerError.verification("outcome-join")
        }
        let actionData = try Data(contentsOf: directory.appendingPathComponent("action-table.json"))
        let records = try CanonicalJSON.decode([ActionRecord].self, from: actionData)
        let ledgerData = try Data(contentsOf: directory.appendingPathComponent("run-ledger.json"))
        let ledger = try CanonicalJSON.decode(RunLedgerPayload.self, from: ledgerData, allowedTopLevelKeys: ["records", "resourceVector"])
        guard records == ledger.records else { throw ControllerError.verification("row-vector-disagreement") }
        try ledger.resourceVector.validateComplete(requireExact: true)
        return PublishedPacket(rootDigest: root, manifest: manifest)
    }

    private static func validRelativeName(_ name: String) -> Bool {
        !name.isEmpty && !name.hasPrefix(".") && !name.contains("/") && name != "MANIFEST.json"
    }
}
