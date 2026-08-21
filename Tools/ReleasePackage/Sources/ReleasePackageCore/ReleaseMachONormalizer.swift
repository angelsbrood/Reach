import CryptoKit
import Foundation

struct ObjCFastStubNormalizationRecord: Codable, Equatable, Sendable {
  let schemaVersion: Int
  let strategy: String
  let objCFastStubCount: Int
  let ordinaryStubCount: Int
  let ordinaryMessageSendStubCount: Int
  let bindingCount: Int
  let originalObjCFastBindingOrdinal: Int
  let originalOrdinaryBindingOrdinal: Int
  let canonicalBindingOrdinal: Int
  let normalizedUUID: String
}

enum ReleaseMachONormalizer {
  private static let machO64Magic: UInt32 = 0xFEED_FACF
  private static let arm64CPUType: UInt32 = 0x0100_000C
  private static let executableFileType: UInt32 = 2
  private static let segment64Command: UInt32 = 0x19
  private static let uuidCommand: UInt32 = 0x1B
  private static let codeSignatureCommand: UInt32 = 0x1D
  private static let fastStubSize = 32

  struct Result: Equatable, Sendable {
    let data: Data
    let record: ObjCFastStubNormalizationRecord
  }

  static func normalizeDefaultObjCFastStubs(
    at executable: URL,
    dyldFixups: String,
    recordURL: URL
  ) throws {
    let source = try Data(contentsOf: executable, options: [.mappedIfSafe])
    let result = try normalizeDefaultObjCFastStubs(data: source, dyldFixups: dyldFixups)
    try SecureFiles.atomicWrite(result.data, to: executable, mode: 0o755)
    try SecureFiles.atomicWrite(try CanonicalJSON.encode(result.record), to: recordURL)
  }

  static func normalizeDefaultObjCFastStubs(data: Data, dyldFixups: String) throws -> Result {
    var image = data
    let authority = try parseAuthority(image)
    let bindings = try parseMessageSendBindings(dyldFixups, got: authority.got)

    guard authority.ordinaryStubs.alignment == 2,
      authority.ordinaryStubs.size > 0,
      authority.ordinaryStubs.size % 12 == 0,
      authority.ordinaryStubs.size <= UInt64(Int.max)
    else {
      throw ReleasePackageError.verification(
        "release reachd does not use the expected 12-byte ordinary symbol stubs")
    }
    let ordinaryStubCount = Int(authority.ordinaryStubs.size) / 12
    let ordinaryRange = try fileRange(authority.ordinaryStubs, in: image)
    var ordinaryMessageSendStubs: [(offset: Int, pc: UInt64, target: UInt64)] = []
    for index in 0..<ordinaryStubCount {
      let offset = ordinaryRange.lowerBound + index * 12
      let words = try (0..<3).map { try readUInt32(image, at: offset + $0 * 4) }
      guard words[0] & 0x9F00_001F == 0x9000_0010,
        words[1] & 0xFFC0_03FF == 0xF940_0210,
        words[2] == 0xD61F_0200
      else {
        throw ReleasePackageError.verification(
          "ordinary symbol stub \(index) does not match the pinned default dispatch shape")
      }
      let pc = authority.ordinaryStubs.address + UInt64(index * 12)
      let target = try adrpLDRTarget(adrp: words[0], ldr: words[1], pc: pc)
      if bindings.contains(target) {
        ordinaryMessageSendStubs.append((offset: offset, pc: pc, target: target))
      }
    }
    guard ordinaryMessageSendStubs.count == 1,
      let ordinaryMessageSend = ordinaryMessageSendStubs.first
    else {
      throw ReleasePackageError.verification(
        "release reachd must contain exactly one ordinary _objc_msgSend symbol stub")
    }

    guard authority.stubs.alignment == 5,
      authority.stubs.size > 0,
      authority.stubs.size % UInt64(fastStubSize) == 0,
      authority.stubs.size <= UInt64(Int.max)
    else {
      throw ReleasePackageError.verification(
        "release reachd does not use the expected 32-byte default Objective-C fast stubs")
    }
    let stubCount = Int(authority.stubs.size) / fastStubSize
    let range = try fileRange(authority.stubs, in: image)
    guard range.count == stubCount * fastStubSize else {
      throw ReleasePackageError.verification("Objective-C stub section size is inconsistent")
    }

    var originalTargets = Set<UInt64>()
    for index in 0..<stubCount {
      let offset = range.lowerBound + index * fastStubSize
      let words = try (0..<8).map { try readUInt32(image, at: offset + $0 * 4) }
      guard words[0] & 0x9F00_001F == 0x9000_0001,
        words[1] & 0xFFC0_03FF == 0xF940_0021,
        words[2] & 0x9F00_001F == 0x9000_0010,
        words[3] & 0xFFC0_03FF == 0xF940_0210,
        words[4] == 0xD61F_0200,
        words[5] == 0xD420_0020,
        words[6] == 0xD420_0020,
        words[7] == 0xD420_0020
      else {
        throw ReleasePackageError.verification(
          "Objective-C fast stub (index) does not match the pinned default dispatch shape")
      }
      let pc = authority.stubs.address + UInt64(index * fastStubSize + 8)
      let target = try adrpLDRTarget(adrp: words[2], ldr: words[3], pc: pc)
      guard bindings.contains(target) else {
        throw ReleasePackageError.verification(
          "Objective-C fast stub (index) does not use an authenticated _objc_msgSend binding")
      }
      originalTargets.insert(target)
    }
    guard originalTargets.count == 1, let originalTarget = originalTargets.first else {
      throw ReleasePackageError.verification(
        "Objective-C fast stubs do not share one linker-selected _objc_msgSend binding")
    }

    let canonicalTarget = bindings[0]
    let ordinaryADRP = try readUInt32(image, at: ordinaryMessageSend.offset)
    let ordinaryReplacement = try ldrInstruction(
      try readUInt32(image, at: ordinaryMessageSend.offset + 4),
      for: canonicalTarget,
      adrp: ordinaryADRP,
      pc: ordinaryMessageSend.pc
    )
    try writeUInt32(ordinaryReplacement, to: &image, at: ordinaryMessageSend.offset + 4)
    for index in 0..<stubCount {
      let offset = range.lowerBound + index * fastStubSize
      let adrp = try readUInt32(image, at: offset + 8)
      let pc = authority.stubs.address + UInt64(index * fastStubSize + 8)
      let replacement = try ldrInstruction(
        try readUInt32(image, at: offset + 12),
        for: canonicalTarget,
        adrp: adrp,
        pc: pc
      )
      try writeUInt32(replacement, to: &image, at: offset + 12)
    }

    image.replaceSubrange(
      authority.uuidOffset..<(authority.uuidOffset + 16), with: repeatElement(0, count: 16))
    var uuidBytes = Array(SHA256.hash(data: image).prefix(16))
    uuidBytes[6] = (uuidBytes[6] & 0x0F) | 0x80
    uuidBytes[8] = (uuidBytes[8] & 0x3F) | 0x80
    image.replaceSubrange(authority.uuidOffset..<(authority.uuidOffset + 16), with: uuidBytes)

    let originalObjCFastOrdinal = bindings.firstIndex(of: originalTarget)!
    let originalOrdinaryOrdinal = bindings.firstIndex(of: ordinaryMessageSend.target)!
    return Result(
      data: image,
      record: ObjCFastStubNormalizationRecord(
        schemaVersion: 1,
        strategy: "default-fast-objc-msgsend-got-order",
        objCFastStubCount: stubCount,
        ordinaryStubCount: ordinaryStubCount,
        ordinaryMessageSendStubCount: ordinaryMessageSendStubs.count,
        bindingCount: bindings.count,
        originalObjCFastBindingOrdinal: originalObjCFastOrdinal,
        originalOrdinaryBindingOrdinal: originalOrdinaryOrdinal,
        canonicalBindingOrdinal: 0,
        normalizedUUID: uuidString(uuidBytes)
      )
    )
  }

  private struct Section: Equatable, Sendable {
    let address: UInt64
    let size: UInt64
    let fileOffset: UInt64
    let alignment: UInt32
  }

  private struct Authority: Equatable, Sendable {
    let ordinaryStubs: Section
    let stubs: Section
    let got: Section
    let uuidOffset: Int
  }

  private static func parseAuthority(_ data: Data) throws -> Authority {
    guard data.count >= 32,
      try readUInt32(data, at: 0) == machO64Magic,
      try readUInt32(data, at: 4) == arm64CPUType,
      try readUInt32(data, at: 12) == executableFileType
    else {
      throw ReleasePackageError.verification(
        "release reachd must be one thin little-endian arm64 Mach-O executable")
    }
    let commandCount = Int(try readUInt32(data, at: 16))
    let commandBytes = Int(try readUInt32(data, at: 20))
    guard commandCount > 0, commandBytes >= 0, commandBytes <= data.count - 32 else {
      throw ReleasePackageError.verification("Mach-O load-command authority is malformed")
    }

    var ordinaryStubs: Section?
    var stubs: Section?
    var got: Section?
    var uuidOffset: Int?
    var cursor = 32
    let commandEnd = 32 + commandBytes
    for _ in 0..<commandCount {
      guard cursor <= commandEnd - 8 else {
        throw ReleasePackageError.verification("Mach-O load command is truncated")
      }
      let command = try readUInt32(data, at: cursor)
      let commandSize = Int(try readUInt32(data, at: cursor + 4))
      guard commandSize >= 8, cursor <= commandEnd - commandSize else {
        throw ReleasePackageError.verification("Mach-O load-command size is invalid")
      }
      if command == codeSignatureCommand {
        throw ReleasePackageError.verification(
          "Objective-C stub normalization requires the linker signature to be removed first")
      } else if command == uuidCommand {
        guard commandSize == 24, uuidOffset == nil else {
          throw ReleasePackageError.verification("Mach-O must contain exactly one UUID command")
        }
        uuidOffset = cursor + 8
      } else if command == segment64Command {
        guard commandSize >= 72 else {
          throw ReleasePackageError.verification("Mach-O segment command is truncated")
        }
        let segment = try fixedString(data, at: cursor + 8, count: 16)
        let sectionCount = Int(try readUInt32(data, at: cursor + 64))
        guard sectionCount >= 0, commandSize == 72 + sectionCount * 80 else {
          throw ReleasePackageError.verification("Mach-O section table is malformed")
        }
        for index in 0..<sectionCount {
          let sectionOffset = cursor + 72 + index * 80
          let sectionName = try fixedString(data, at: sectionOffset, count: 16)
          let sectionSegment = try fixedString(data, at: sectionOffset + 16, count: 16)
          guard sectionSegment == segment else {
            throw ReleasePackageError.verification("Mach-O section segment authority disagrees")
          }
          let section = Section(
            address: try readUInt64(data, at: sectionOffset + 32),
            size: try readUInt64(data, at: sectionOffset + 40),
            fileOffset: UInt64(try readUInt32(data, at: sectionOffset + 48)),
            alignment: try readUInt32(data, at: sectionOffset + 52)
          )
          if segment == "__TEXT", sectionName == "__stubs" {
            guard ordinaryStubs == nil else {
              throw ReleasePackageError.verification("Mach-O has duplicate ordinary stub sections")
            }
            ordinaryStubs = section
          } else if segment == "__TEXT", sectionName == "__objc_stubs" {
            guard stubs == nil else {
              throw ReleasePackageError.verification(
                "Mach-O has duplicate Objective-C stub sections")
            }
            stubs = section
          } else if segment == "__DATA_CONST", sectionName == "__got" {
            guard got == nil else {
              throw ReleasePackageError.verification(
                "Mach-O has duplicate authenticated GOT sections")
            }
            got = section
          }
        }
      }
      cursor += commandSize
    }
    guard cursor == commandEnd, let ordinaryStubs, let stubs, let got, let uuidOffset else {
      throw ReleasePackageError.verification(
        "Mach-O lacks exact ordinary stub, Objective-C stub, GOT, or UUID authority")
    }
    return Authority(ordinaryStubs: ordinaryStubs, stubs: stubs, got: got, uuidOffset: uuidOffset)
  }

  private static func parseMessageSendBindings(_ output: String, got: Section) throws -> [UInt64] {
    var bindings: [UInt64] = []
    for line in output.split(separator: "\n") {
      let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
      guard fields.last == "libobjc/_objc_msgSend" else { continue }
      guard fields.count == 5,
        fields[0] == "__DATA_CONST",
        fields[1] == "__got",
        fields[3] == "bind",
        fields[2].hasPrefix("0x"),
        let address = UInt64(fields[2].dropFirst(2), radix: 16),
        got.size <= UInt64.max - got.address,
        address >= got.address,
        address < got.address + got.size,
        address % 8 == 0
      else {
        throw ReleasePackageError.verification(
          "dyld fixups contain an unexpected _objc_msgSend binding")
      }
      bindings.append(address)
    }
    bindings.sort()
    guard bindings.count == 2,
      Set(bindings).count == 2,
      bindings[1] == bindings[0] + 8
    else {
      throw ReleasePackageError.verification(
        "release reachd must expose exactly two adjacent authenticated _objc_msgSend bindings")
    }
    return bindings
  }

  private static func fileRange(_ section: Section, in data: Data) throws -> Range<Int> {
    guard section.fileOffset <= UInt64(Int.max),
      section.size <= UInt64(Int.max),
      section.fileOffset <= UInt64(data.count),
      section.size <= UInt64(data.count) - section.fileOffset
    else {
      throw ReleasePackageError.verification("Mach-O section lies outside the executable")
    }
    let start = Int(section.fileOffset)
    return start..<(start + Int(section.size))
  }

  private static func adrpLDRTarget(adrp: UInt32, ldr: UInt32, pc: UInt64) throws -> UInt64 {
    let immHigh = Int64((adrp >> 5) & 0x7_FFFF)
    let immLow = Int64((adrp >> 29) & 0x3)
    var pages = (immHigh << 2) | immLow
    if pages & (1 << 20) != 0 { pages -= 1 << 21 }
    let pcPage = Int64(bitPattern: pc & ~UInt64(0xFFF))
    let targetPage = pcPage + (pages << 12)
    guard targetPage >= 0 else {
      throw ReleasePackageError.verification("Objective-C fast stub ADRP underflowed")
    }
    let displacement = UInt64((ldr >> 10) & 0xFFF) * 8
    return UInt64(targetPage) + displacement
  }

  private static func ldrInstruction(
    _ original: UInt32,
    for target: UInt64,
    adrp: UInt32,
    pc: UInt64
  ) throws -> UInt32 {
    let currentPageTarget = try adrpLDRTarget(adrp: adrp, ldr: original & ~(0xFFF << 10), pc: pc)
    guard target >= currentPageTarget,
      target - currentPageTarget <= UInt64(0xFFF * 8),
      (target - currentPageTarget) % 8 == 0
    else {
      throw ReleasePackageError.verification(
        "canonical _objc_msgSend binding is outside the existing ADRP page")
    }
    let immediate = UInt32((target - currentPageTarget) / 8)
    return (original & ~(0xFFF << 10)) | (immediate << 10)
  }

  private static func readUInt32(_ data: Data, at offset: Int) throws -> UInt32 {
    guard offset >= 0, offset <= data.count - 4 else {
      throw ReleasePackageError.verification("Mach-O 32-bit field is truncated")
    }
    return (0..<4).reduce(UInt32(0)) { value, index in
      value | UInt32(data[offset + index]) << UInt32(index * 8)
    }
  }

  private static func readUInt64(_ data: Data, at offset: Int) throws -> UInt64 {
    guard offset >= 0, offset <= data.count - 8 else {
      throw ReleasePackageError.verification("Mach-O 64-bit field is truncated")
    }
    return (0..<8).reduce(UInt64(0)) { value, index in
      value | UInt64(data[offset + index]) << UInt64(index * 8)
    }
  }

  private static func writeUInt32(_ value: UInt32, to data: inout Data, at offset: Int) throws {
    guard offset >= 0, offset <= data.count - 4 else {
      throw ReleasePackageError.verification("Mach-O instruction write is outside the executable")
    }
    for index in 0..<4 {
      data[offset + index] = UInt8(truncatingIfNeeded: value >> UInt32(index * 8))
    }
  }

  private static func fixedString(_ data: Data, at offset: Int, count: Int) throws -> String {
    guard offset >= 0, count >= 0, offset <= data.count - count else {
      throw ReleasePackageError.verification("Mach-O fixed string is truncated")
    }
    let bytes = data[offset..<(offset + count)]
    let prefix = bytes.prefix { $0 != 0 }
    guard prefix.allSatisfy({ $0 >= 0x20 && $0 <= 0x7E }) else {
      throw ReleasePackageError.verification("Mach-O section name is non-ASCII")
    }
    return String(decoding: prefix, as: UTF8.self)
  }

  private static func uuidString(_ bytes: [UInt8]) -> String {
    let hex = bytes.map { String(format: "%02X", $0) }.joined()
    let boundaries = [8, 12, 16, 20]
    var result = ""
    for (index, character) in hex.enumerated() {
      if boundaries.contains(index) { result.append("-") }
      result.append(character)
    }
    return result
  }
}
