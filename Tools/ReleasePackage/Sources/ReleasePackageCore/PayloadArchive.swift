import Darwin
import Foundation

public enum PayloadKind: String, Codable, Sendable {
  case directory
  case file
  case symlink
}

public struct PayloadRecord: Codable, Equatable, Sendable {
  public let path: String
  public let kind: PayloadKind
  public let mode: UInt32
  public let uid: UInt32
  public let gid: UInt32
  public let size: UInt64
  public let posixChecksum: UInt32
  public let sha256: String?
  public let linkTarget: String?

  public var bomMode: String { String(mode, radix: 8) }
}

struct PayloadNode {
  let record: PayloadRecord
  let source: URL?
  let linkTarget: String?

  var payloadData: Data {
    get throws {
      switch record.kind {
      case .directory:
        return Data()
      case .file:
        guard let source else {
          throw ReleasePackageError.verification("missing source for \(record.path)")
        }
        return try Data(contentsOf: source, options: [.mappedIfSafe])
      case .symlink:
        guard let linkTarget else {
          throw ReleasePackageError.verification("missing link target for \(record.path)")
        }
        return Data(linkTarget.utf8)
      }
    }
  }
}

public struct PayloadTree {
  let nodes: [PayloadNode]
  public var records: [PayloadRecord] { nodes.map(\.record) }

  public static func inspect(root: URL) throws -> Self {
    var rootInfo = stat()
    guard lstat(root.path, &rootInfo) == 0,
      (rootInfo.st_mode & S_IFMT) == S_IFDIR,
      (rootInfo.st_mode & 0o7777) == 0o755
    else {
      throw ReleasePackageError.unsafePath(
        "payload root is not a mode-0755 directory: \(root.path)")
    }
    try rejectPayloadExtendedAttributes(root)
    var nodes: [PayloadNode] = [
      PayloadNode(
        record: PayloadRecord(
          path: ".",
          kind: .directory,
          mode: UInt32(S_IFDIR | 0o755),
          uid: 0,
          gid: 0,
          size: 0,
          posixChecksum: 0,
          sha256: nil,
          linkTarget: nil
        ),
        source: nil,
        linkTarget: nil
      )
    ]

    let entries = try SecureFiles.enumerateTree(root).sorted { lhs, rhs in
      lhs.path.utf8.lexicographicallyPrecedes(rhs.path.utf8)
    }
    for entry in entries {
      let relative = String(entry.path.dropFirst(root.path.count + 1))
      try SecureFiles.validateRelativePath(relative)
      guard
        !relative.split(separator: "/").contains(where: { $0 == ".DS_Store" || $0.hasPrefix("._") })
      else {
        throw ReleasePackageError.unsafePath("Apple metadata is not package payload: \(relative)")
      }
      try rejectPayloadExtendedAttributes(entry)
      var info = stat()
      guard lstat(entry.path, &info) == 0 else {
        throw ReleasePackageError.verification("cannot inspect payload member \(relative)")
      }
      let path = "./\(relative)"
      switch info.st_mode & S_IFMT {
      case S_IFDIR:
        guard (info.st_mode & 0o7777) == 0o755 else {
          throw ReleasePackageError.verification("payload directory has noncanonical mode: \(path)")
        }
        nodes.append(
          PayloadNode(
            record: PayloadRecord(
              path: path,
              kind: .directory,
              mode: UInt32(S_IFDIR | 0o755),
              uid: 0,
              gid: 0,
              size: 0,
              posixChecksum: 0,
              sha256: nil,
              linkTarget: nil
            ),
            source: nil,
            linkTarget: nil
          ))
      case S_IFREG:
        guard info.st_nlink == 1 else {
          throw ReleasePackageError.unsafePath("hard link in package payload: \(path)")
        }
        let permissions = info.st_mode & 0o7777
        guard permissions == 0o755 || permissions == 0o644 || permissions == 0o555 else {
          throw ReleasePackageError.verification("payload file has noncanonical mode: \(path)")
        }
        let data = try Data(contentsOf: entry, options: [.mappedIfSafe])
        nodes.append(
          PayloadNode(
            record: PayloadRecord(
              path: path,
              kind: .file,
              mode: UInt32(S_IFREG | permissions),
              uid: 0,
              gid: 0,
              size: UInt64(data.count),
              posixChecksum: POSIXChecksum.checksum(data),
              sha256: Digests.sha256(data),
              linkTarget: nil
            ),
            source: entry,
            linkTarget: nil
          ))
      case S_IFLNK:
        let target = try FileManager.default.destinationOfSymbolicLink(atPath: entry.path)
        guard path == "./usr/local/bin/reachd",
          target == "/Library/Application Support/Reach/Host/reachd"
        else {
          throw ReleasePackageError.unsafePath("unexpected payload symlink: \(path)")
        }
        let data = Data(target.utf8)
        nodes.append(
          PayloadNode(
            record: PayloadRecord(
              path: path,
              kind: .symlink,
              mode: UInt32(S_IFLNK | 0o777),
              uid: 0,
              gid: 0,
              size: UInt64(data.count),
              posixChecksum: POSIXChecksum.checksum(data),
              sha256: Digests.sha256(data),
              linkTarget: target
            ),
            source: nil,
            linkTarget: target
          ))
      default:
        throw ReleasePackageError.unsafePath("special file in package payload: \(path)")
      }
    }
    nodes.sort { $0.record.path.utf8.lexicographicallyPrecedes($1.record.path.utf8) }
    guard nodes.first?.record.path == "." else {
      throw ReleasePackageError.verification("payload root ordering failed")
    }
    return Self(nodes: nodes)
  }

  public func writeODC(to url: URL, modificationTime: Int64) throws {
    guard modificationTime >= 0, modificationTime <= Int64(UInt32.max) else {
      throw ReleasePackageError.verification("payload epoch is outside ODC range")
    }
    var output = Data()
    var inode: UInt32 = 1
    for node in nodes {
      let data = try node.payloadData
      try appendODC(
        name: node.record.path,
        data: data,
        mode: node.record.mode,
        inode: inode,
        linkCount: node.record.kind == .directory ? directoryLinkCount(node.record.path) : 1,
        modificationTime: UInt64(modificationTime),
        to: &output
      )
      inode += 1
    }
    try appendODC(
      name: "TRAILER!!!",
      data: Data(),
      mode: UInt32(S_IFREG),
      inode: inode,
      linkCount: 1,
      modificationTime: UInt64(modificationTime),
      to: &output
    )
    try SecureFiles.atomicWrite(output, to: url)
  }

  public func bomInput() -> Data {
    var lines: [String] = []
    for record in records {
      switch record.kind {
      case .directory:
        lines.append("\(record.path)\t\(record.bomMode)\t0/0")
      case .file:
        lines.append(
          "\(record.path)\t\(record.bomMode)\t0/0\t\(record.size)\t\(record.posixChecksum)")
      case .symlink:
        lines.append(
          "\(record.path)\t\(record.bomMode)\t0/0\t\(record.size)\t\(record.posixChecksum)\t\(record.linkTarget ?? "")"
        )
      }
    }
    return Data((lines.joined(separator: "\n") + "\n").utf8)
  }

  public var installKBytes: UInt64 {
    let bytes = records.reduce(UInt64(0)) { partial, record in
      partial + (record.kind == .directory ? 0 : record.size)
    }
    return (bytes + 1_023) / 1_024
  }

  private func appendODC(
    name: String,
    data: Data,
    mode: UInt32,
    inode: UInt32,
    linkCount: UInt32,
    modificationTime: UInt64,
    to output: inout Data
  ) throws {
    let nameBytes = Data(name.utf8) + Data([0])
    let fields = [
      "070707",
      try octal(0, width: 6, label: "device"),
      try octal(UInt64(inode), width: 6, label: "inode"),
      try octal(UInt64(mode), width: 6, label: "mode"),
      try octal(0, width: 6, label: "uid"),
      try octal(0, width: 6, label: "gid"),
      try octal(UInt64(linkCount), width: 6, label: "nlink"),
      try octal(0, width: 6, label: "rdev"),
      try octal(modificationTime, width: 11, label: "mtime"),
      try octal(UInt64(nameBytes.count), width: 6, label: "name size"),
      try octal(UInt64(data.count), width: 11, label: "file size"),
    ]
    output.append(contentsOf: fields.joined().utf8)
    output.append(nameBytes)
    output.append(data)
  }

  private func directoryLinkCount(_ path: String) -> UInt32 {
    let children = records.filter { record in
      guard record.kind == .directory, record.path != path else { return false }
      let parent: String
      if let slash = record.path.lastIndex(of: "/") {
        let prefix = String(record.path[..<slash])
        parent = prefix.isEmpty ? "." : prefix
      } else {
        parent = "."
      }
      return parent == path
    }.count
    return UInt32(2 + children)
  }

  private func octal(_ value: UInt64, width: Int, label: String) throws -> String {
    let rendered = String(value, radix: 8)
    guard rendered.count <= width else {
      throw ReleasePackageError.verification("ODC \(label) exceeds \(width) octal digits")
    }
    return String(repeating: "0", count: width - rendered.count) + rendered
  }

  private static func rejectPayloadExtendedAttributes(_ url: URL) throws {
    let count = listxattr(url.path, nil, 0, XATTR_NOFOLLOW)
    if count < 0, errno == ENOTSUP { return }
    guard count >= 0 else {
      throw ReleasePackageError.verification("cannot inspect xattrs at \(url.path)")
    }
    guard count > 0 else { return }
    var buffer = [CChar](repeating: 0, count: count)
    let loaded = listxattr(url.path, &buffer, buffer.count, XATTR_NOFOLLOW)
    guard loaded >= 0 else {
      throw ReleasePackageError.verification("cannot inspect xattrs at \(url.path)")
    }
    var names: [String] = []
    var start = 0
    while start < loaded {
      let end = buffer[start..<loaded].firstIndex(of: 0) ?? loaded
      names.append(
        String(decoding: buffer[start..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self))
      start = end + 1
    }
    // macOS 27 attaches this protected provenance marker to files created by
    // the build process and immediately recreates it after removal. It is
    // filesystem metadata, not an ODC member: the canonical writer below
    // has no xattr representation and the parser/allowlist jointly prove it
    // cannot enter the package. Every other attribute remains a refusal.
    let payloadAttributes = names.filter { $0 != "com.apple.provenance" }
    guard payloadAttributes.isEmpty else {
      throw ReleasePackageError.unsafePath(
        "extended attributes are not allowed in payload: \(url.path)")
    }
  }
}

public enum ODCArchive {
  public struct Member: Equatable, Sendable {
    public let record: PayloadRecord
    public let data: Data
  }

  public static func parse(_ data: Data) throws -> [PayloadRecord] {
    try parseMembers(data).map(\.record)
  }

  public static func parseMembers(_ data: Data) throws -> [Member] {
    var offset = 0
    var members: [Member] = []
    var linksByPath: [String: UInt64] = [:]
    var expectedInode: UInt64 = 1
    var commonModificationTime: UInt64?
    var previousName: String?
    while true {
      guard offset + 76 <= data.count else {
        throw ReleasePackageError.verification("truncated ODC header")
      }
      let header = data[offset..<(offset + 76)]
      offset += 76
      guard String(decoding: header.prefix(6), as: UTF8.self) == "070707" else {
        throw ReleasePackageError.verification("invalid ODC magic")
      }
      func field(_ start: Int, _ width: Int) throws -> UInt64 {
        let lower = header.index(header.startIndex, offsetBy: start)
        let upper = header.index(lower, offsetBy: width)
        let value = String(decoding: header[lower..<upper], as: UTF8.self)
        guard let parsed = UInt64(value, radix: 8) else {
          throw ReleasePackageError.verification("invalid ODC octal field")
        }
        return parsed
      }
      let device = try field(6, 6)
      let inode = try field(12, 6)
      let mode = try UInt32(exactly: field(18, 6)).unwrapped("ODC mode")
      let uid = try UInt32(exactly: field(24, 6)).unwrapped("ODC uid")
      let gid = try UInt32(exactly: field(30, 6)).unwrapped("ODC gid")
      let linkCount = try field(36, 6)
      let rdev = try field(42, 6)
      let modificationTime = try field(48, 11)
      let nameSize = try Int(exactly: field(59, 6)).unwrapped("ODC name size")
      let fileSize = try Int(exactly: field(65, 11)).unwrapped("ODC file size")
      guard device == 0, rdev == 0, uid == 0, gid == 0,
        inode == expectedInode, linkCount > 0,
        commonModificationTime == nil || commonModificationTime == modificationTime,
        nameSize > 0,
        offset + nameSize + fileSize <= data.count,
        data[offset + nameSize - 1] == 0
      else {
        throw ReleasePackageError.verification("noncanonical ODC metadata or member bounds")
      }
      commonModificationTime = modificationTime
      expectedInode += 1
      guard let name = String(data: data[offset..<(offset + nameSize - 1)], encoding: .utf8) else {
        throw ReleasePackageError.verification("ODC member name is not UTF-8")
      }
      offset += nameSize
      let memberData = Data(data[offset..<(offset + fileSize)])
      offset += fileSize
      if name == "TRAILER!!!" {
        guard fileSize == 0, linkCount == 1, (mode & UInt32(S_IFMT)) == UInt32(S_IFREG),
          offset == data.count
        else {
          throw ReleasePackageError.verification("ODC trailer is not terminal")
        }
        let records = members.map(\.record)
        for record in records {
          let expectedLinks: UInt64
          if record.kind == .directory {
            let children = records.filter { child in
              guard child.kind == .directory, child.path != record.path else { return false }
              let parent: String
              if let slash = child.path.lastIndex(of: "/") {
                let prefix = String(child.path[..<slash])
                parent = prefix.isEmpty ? "." : prefix
              } else {
                parent = "."
              }
              return parent == record.path
            }.count
            expectedLinks = UInt64(2 + children)
          } else {
            expectedLinks = 1
          }
          guard linksByPath[record.path] == expectedLinks else {
            throw ReleasePackageError.verification("noncanonical ODC link count for \(record.path)")
          }
        }
        return members
      }
      try SecureFiles.validateRelativePath(
        name == "." ? "root" : String(name.dropFirst(name.hasPrefix("./") ? 2 : 0)))
      guard members.isEmpty ? name == "." : name.hasPrefix("./"),
        previousName.map({ $0.utf8.lexicographicallyPrecedes(name.utf8) }) ?? true,
        linksByPath[name] == nil
      else {
        throw ReleasePackageError.unsafePath("noncanonical or duplicate ODC member: \(name)")
      }
      previousName = name
      let type = mode & UInt32(S_IFMT)
      let kind: PayloadKind
      switch type {
      case UInt32(S_IFDIR): kind = .directory
      case UInt32(S_IFREG): kind = .file
      case UInt32(S_IFLNK): kind = .symlink
      default: throw ReleasePackageError.unsafePath("special ODC member: \(name)")
      }
      if kind == .directory, fileSize != 0 {
        throw ReleasePackageError.verification("ODC directory carries payload data")
      }
      let linkTarget: String?
      if kind == .symlink {
        guard let value = String(data: memberData, encoding: .utf8) else {
          throw ReleasePackageError.verification("ODC symlink target is not UTF-8")
        }
        linkTarget = value
      } else {
        linkTarget = nil
      }
      let record = PayloadRecord(
        path: name,
        kind: kind,
        mode: mode,
        uid: uid,
        gid: gid,
        size: UInt64(memberData.count),
        posixChecksum: kind == .directory ? 0 : POSIXChecksum.checksum(memberData),
        sha256: kind == .directory ? nil : Digests.sha256(memberData),
        linkTarget: linkTarget
      )
      linksByPath[name] = linkCount
      members.append(Member(record: record, data: memberData))
    }
  }
}

public enum POSIXChecksum {
  private static let table: [UInt32] = (0..<256).map { index in
    var value = UInt32(index) << 24
    for _ in 0..<8 {
      value = (value & 0x8000_0000) != 0 ? (value << 1) ^ 0x04C1_1DB7 : value << 1
    }
    return value
  }

  public static func checksum(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0
    for byte in data {
      crc = (crc << 8) ^ table[Int(((crc >> 24) ^ UInt32(byte)) & 0xff)]
    }
    var length = UInt64(data.count)
    while length != 0 {
      let byte = UInt8(length & 0xff)
      crc = (crc << 8) ^ table[Int(((crc >> 24) ^ UInt32(byte)) & 0xff)]
      length >>= 8
    }
    return ~crc
  }
}

extension Optional {
  fileprivate func unwrapped(_ label: String) throws -> Wrapped {
    guard let self else {
      throw ReleasePackageError.verification("\(label) is outside representable range")
    }
    return self
  }
}
