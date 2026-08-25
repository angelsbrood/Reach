import Foundation

enum MachORuntimeContentDigest {
  private static let mhMagic64: UInt32 = 0xfeed_facf
  private static let lcSegment64: UInt32 = 0x19
  private static let segmentCommandSize = 72
  private static let sectionSize = 80
  private static let zeroFillTypes: Set<UInt32> = [0x1, 0xc, 0x12]

  static func digest(_ url: URL) throws -> String {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard try u32(data, 0) == mhMagic64 else {
      throw ReleasePackageError.verification("unchanged component leaf is not thin Mach-O 64")
    }
    let commandCount = Int(try u32(data, 16))
    let commandBytes = Int(try u32(data, 20))
    guard commandCount >= 1, 32 + commandBytes <= data.count else {
      throw ReleasePackageError.verification("Mach-O load-command authority is malformed")
    }
    var cursor = 32
    var records: [Data] = []
    for _ in 0..<commandCount {
      let command = try u32(data, cursor)
      let size = Int(try u32(data, cursor + 4))
      guard size >= 8, cursor + size <= 32 + commandBytes else {
        throw ReleasePackageError.verification("Mach-O load command is out of bounds")
      }
      if command == lcSegment64 {
        guard size >= segmentCommandSize else {
          throw ReleasePackageError.verification("Mach-O segment command is truncated")
        }
        let segment = string(data, cursor + 8, 16)
        let sectionCount = Int(try u32(data, cursor + 64))
        guard segment != "__LINKEDIT",
          segmentCommandSize + sectionCount * sectionSize <= size
        else {
          if segment == "__LINKEDIT" {
            cursor += size
            continue
          }
          throw ReleasePackageError.verification("Mach-O section table is out of bounds")
        }
        for index in 0..<sectionCount {
          let offset = cursor + segmentCommandSize + index * sectionSize
          let section = string(data, offset, 16)
          let sectionSegment = string(data, offset + 16, 16)
          let byteCount = try u64(data, offset + 40)
          let fileOffset = UInt64(try u32(data, offset + 48))
          let alignment = try u32(data, offset + 52)
          let flags = try u32(data, offset + 64)
          var record = Data(
            "\(sectionSegment)\0\(section)\0\(byteCount)\0\(alignment)\0\(flags)\0".utf8)
          if !zeroFillTypes.contains(flags & 0xff) {
            guard fileOffset <= UInt64(data.count),
              byteCount <= UInt64(data.count) - fileOffset
            else {
              throw ReleasePackageError.verification("Mach-O section payload is out of bounds")
            }
            record.append(data[Int(fileOffset)..<Int(fileOffset + byteCount)])
          }
          records.append(record)
        }
      }
      cursor += size
    }
    guard !records.isEmpty else {
      throw ReleasePackageError.verification("Mach-O contains no runtime sections")
    }
    return Digests.sha256(records.reduce(into: Data(), { $0.append($1) }))
  }

  private static func u32(_ data: Data, _ offset: Int) throws -> UInt32 {
    guard offset >= 0, offset + 4 <= data.count else {
      throw ReleasePackageError.verification("Mach-O integer is out of bounds")
    }
    return data[offset..<(offset + 4)].enumerated().reduce(UInt32(0)) { value, pair in
      value | UInt32(pair.element) << UInt32(pair.offset * 8)
    }
  }

  private static func u64(_ data: Data, _ offset: Int) throws -> UInt64 {
    guard offset >= 0, offset + 8 <= data.count else {
      throw ReleasePackageError.verification("Mach-O integer is out of bounds")
    }
    return data[offset..<(offset + 8)].enumerated().reduce(UInt64(0)) { value, pair in
      value | UInt64(pair.element) << UInt64(pair.offset * 8)
    }
  }

  private static func string(_ data: Data, _ offset: Int, _ count: Int) -> String {
    let bytes = data[offset..<(offset + count)].prefix { $0 != 0 }
    return String(decoding: bytes, as: UTF8.self)
  }
}
