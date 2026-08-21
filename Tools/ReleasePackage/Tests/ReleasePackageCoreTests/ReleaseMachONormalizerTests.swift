import Foundation
import Testing

@testable import ReleasePackageCore

@Test func defaultFastObjCStubOrderingCanonicalizesWithoutChangingDispatchShape() throws {
  let lower = makeMachOFixture(bindingOrdinal: 0, uuidByte: 0x11)
  let upper = makeMachOFixture(bindingOrdinal: 1, uuidByte: 0x22)
  let fixups = machOFixups()

  let normalizedLower = try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
    data: lower, dyldFixups: fixups)
  let normalizedUpper = try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
    data: upper, dyldFixups: fixups)

  #expect(normalizedLower.data == normalizedUpper.data)
  #expect(normalizedLower.data.count == lower.count)
  #expect(normalizedLower.record.objCFastStubCount == 1)
  #expect(normalizedLower.record.ordinaryStubCount == 1)
  #expect(normalizedLower.record.ordinaryMessageSendStubCount == 1)
  #expect(normalizedLower.record.bindingCount == 2)
  #expect(normalizedLower.record.originalObjCFastBindingOrdinal == 0)
  #expect(normalizedUpper.record.originalObjCFastBindingOrdinal == 1)
  #expect(normalizedLower.record.originalOrdinaryBindingOrdinal == 0)
  #expect(normalizedUpper.record.originalOrdinaryBindingOrdinal == 1)
  #expect(normalizedLower.record.canonicalBindingOrdinal == 0)
  #expect(normalizedLower.record.normalizedUUID == normalizedUpper.record.normalizedUUID)

  let ordinaryStubOffset = 0x200
  #expect(
    readFixtureUInt32(normalizedUpper.data, at: ordinaryStubOffset) & 0x9F00_001F == 0x9000_0010)
  #expect(
    readFixtureUInt32(normalizedUpper.data, at: ordinaryStubOffset + 4) & 0xFFC0_03FF == 0xF940_0210
  )
  #expect(readFixtureUInt32(normalizedUpper.data, at: ordinaryStubOffset + 8) == 0xD61F_0200)

  let stubOffset = 0x220
  #expect(readFixtureUInt32(normalizedUpper.data, at: stubOffset + 8) & 0x9F00_001F == 0x9000_0010)
  #expect(readFixtureUInt32(normalizedUpper.data, at: stubOffset + 12) & 0xFFC0_03FF == 0xF940_0210)
  #expect(readFixtureUInt32(normalizedUpper.data, at: stubOffset + 16) == 0xD61F_0200)
  #expect(readFixtureUInt32(normalizedUpper.data, at: stubOffset + 20) == 0xD420_0020)
  #expect(readFixtureUInt32(normalizedUpper.data, at: stubOffset + 24) == 0xD420_0020)
  #expect(readFixtureUInt32(normalizedUpper.data, at: stubOffset + 28) == 0xD420_0020)
}

@Test func objCStubNormalizationRefusesSizeFirstOrUnknownStubShapes() throws {
  var small = makeMachOFixture(bindingOrdinal: 0, uuidByte: 0x11)
  let textSection = 32 + 152 + 72
  writeFixtureUInt64(12, to: &small, at: textSection + 40)
  writeFixtureUInt32(2, to: &small, at: textSection + 52)

  #expect(throws: ReleasePackageError.self) {
    try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
      data: small, dyldFixups: machOFixups())
  }

  var changed = makeMachOFixture(bindingOrdinal: 0, uuidByte: 0x11)
  writeFixtureUInt32(0xD503_201F, to: &changed, at: 0x220 + 20)
  #expect(throws: ReleasePackageError.self) {
    try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
      data: changed, dyldFixups: machOFixups())
  }
}

@Test func objCStubNormalizationRequiresTwoExactAuthenticatedMessageSendBindings() throws {
  let image = makeMachOFixture(bindingOrdinal: 0, uuidByte: 0x11)
  let oneBinding =
    "        __DATA_CONST    __got            0x1000012A0           bind  libobjc/_objc_msgSend\n"
  #expect(throws: ReleasePackageError.self) {
    try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
      data: image, dyldFixups: oneBinding)
  }

  let wrongSymbol =
    oneBinding
    + "        __DATA_CONST    __got            0x1000012A8           bind  libobjc/_objc_msgSendSuper2\n"
  #expect(throws: ReleasePackageError.self) {
    try ReleaseMachONormalizer.normalizeDefaultObjCFastStubs(
      data: image, dyldFixups: wrongSymbol)
  }
}

private func makeMachOFixture(bindingOrdinal: Int, uuidByte: UInt8) -> Data {
  precondition(bindingOrdinal == 0 || bindingOrdinal == 1)
  var data = Data(repeating: 0, count: 0x400)
  writeFixtureUInt32(0xFEED_FACF, to: &data, at: 0)
  writeFixtureUInt32(0x0100_000C, to: &data, at: 4)
  writeFixtureUInt32(0, to: &data, at: 8)
  writeFixtureUInt32(2, to: &data, at: 12)
  writeFixtureUInt32(4, to: &data, at: 16)
  writeFixtureUInt32(480, to: &data, at: 20)

  writeFixtureSegment(
    to: &data,
    at: 32,
    segment: "__TEXT",
    section: "__stubs",
    address: 0x1_0000_0200,
    size: 12,
    fileOffset: 0x200,
    alignment: 2
  )
  writeFixtureSegment(
    to: &data,
    at: 32 + 152,
    segment: "__TEXT",
    section: "__objc_stubs",
    address: 0x1_0000_0220,
    size: 32,
    fileOffset: 0x220,
    alignment: 5
  )
  writeFixtureSegment(
    to: &data,
    at: 32 + 152 + 152,
    segment: "__DATA_CONST",
    section: "__got",
    address: 0x1_0000_12A0,
    size: 24,
    fileOffset: 0x300,
    alignment: 3
  )
  let uuidCommand = 32 + 152 + 152 + 152
  writeFixtureUInt32(0x1B, to: &data, at: uuidCommand)
  writeFixtureUInt32(24, to: &data, at: uuidCommand + 4)
  data.replaceSubrange(
    (uuidCommand + 8)..<(uuidCommand + 24), with: repeatElement(uuidByte, count: 16))

  let ordinaryStubAddress: UInt64 = 0x1_0000_0200
  let stubAddress: UInt64 = 0x1_0000_0220
  let gotAddress: UInt64 = 0x1_0000_12A0 + UInt64(bindingOrdinal * 8)
  writeFixtureUInt32(
    encodeFixtureADRP(register: 16, pc: ordinaryStubAddress, targetPage: gotAddress & ~0xFFF),
    to: &data,
    at: 0x200
  )
  writeFixtureUInt32(
    0xF940_0210 | UInt32((gotAddress & 0xFFF) / 8) << 10,
    to: &data,
    at: 0x204
  )
  writeFixtureUInt32(0xD61F_0200, to: &data, at: 0x208)
  writeFixtureUInt32(
    encodeFixtureADRP(register: 1, pc: stubAddress, targetPage: 0x1_0000_2000),
    to: &data,
    at: 0x220
  )
  writeFixtureUInt32(0xF940_0021, to: &data, at: 0x224)
  writeFixtureUInt32(
    encodeFixtureADRP(register: 16, pc: stubAddress + 8, targetPage: gotAddress & ~0xFFF),
    to: &data,
    at: 0x228
  )
  writeFixtureUInt32(
    0xF940_0210 | UInt32((gotAddress & 0xFFF) / 8) << 10,
    to: &data,
    at: 0x22C
  )
  writeFixtureUInt32(0xD61F_0200, to: &data, at: 0x230)
  writeFixtureUInt32(0xD420_0020, to: &data, at: 0x234)
  writeFixtureUInt32(0xD420_0020, to: &data, at: 0x238)
  writeFixtureUInt32(0xD420_0020, to: &data, at: 0x23C)
  return data
}

private func writeFixtureSegment(
  to data: inout Data,
  at offset: Int,
  segment: String,
  section: String,
  address: UInt64,
  size: UInt64,
  fileOffset: UInt32,
  alignment: UInt32
) {
  writeFixtureUInt32(0x19, to: &data, at: offset)
  writeFixtureUInt32(152, to: &data, at: offset + 4)
  writeFixtureString(segment, to: &data, at: offset + 8, count: 16)
  writeFixtureUInt64(address & ~0xFFF, to: &data, at: offset + 24)
  writeFixtureUInt64(0x1000, to: &data, at: offset + 32)
  writeFixtureUInt64(UInt64(fileOffset), to: &data, at: offset + 40)
  writeFixtureUInt64(0x100, to: &data, at: offset + 48)
  writeFixtureUInt32(5, to: &data, at: offset + 56)
  writeFixtureUInt32(5, to: &data, at: offset + 60)
  writeFixtureUInt32(1, to: &data, at: offset + 64)

  let sectionOffset = offset + 72
  writeFixtureString(section, to: &data, at: sectionOffset, count: 16)
  writeFixtureString(segment, to: &data, at: sectionOffset + 16, count: 16)
  writeFixtureUInt64(address, to: &data, at: sectionOffset + 32)
  writeFixtureUInt64(size, to: &data, at: sectionOffset + 40)
  writeFixtureUInt32(fileOffset, to: &data, at: sectionOffset + 48)
  writeFixtureUInt32(alignment, to: &data, at: sectionOffset + 52)
}

private func encodeFixtureADRP(register: UInt32, pc: UInt64, targetPage: UInt64) -> UInt32 {
  let pcPage = pc & ~0xFFF
  let pages = Int64(targetPage) - Int64(pcPage)
  precondition(pages % 0x1000 == 0)
  let signed = pages / 0x1000
  let encoded = UInt64(bitPattern: signed) & 0x1F_FFFF
  let immLow = UInt32(encoded & 0x3)
  let immHigh = UInt32((encoded >> 2) & 0x7_FFFF)
  return 0x9000_0000 | (immLow << 29) | (immHigh << 5) | register
}

private func machOFixups() -> String {
  """
          __DATA_CONST    __got            0x1000012A0           bind  libobjc/_objc_msgSend
          __DATA_CONST    __got            0x1000012A8           bind  libobjc/_objc_msgSend
          __DATA_CONST    __got            0x1000012B0           bind  libobjc/_objc_msgSendSuper2
  """
}

private func writeFixtureString(_ value: String, to data: inout Data, at offset: Int, count: Int) {
  let bytes = Array(value.utf8)
  precondition(bytes.count < count)
  data.replaceSubrange(offset..<(offset + bytes.count), with: bytes)
}

private func readFixtureUInt32(_ data: Data, at offset: Int) -> UInt32 {
  (0..<4).reduce(UInt32(0)) { value, index in
    value | UInt32(data[offset + index]) << UInt32(index * 8)
  }
}

private func writeFixtureUInt32(_ value: UInt32, to data: inout Data, at offset: Int) {
  for index in 0..<4 {
    data[offset + index] = UInt8(truncatingIfNeeded: value >> UInt32(index * 8))
  }
}

private func writeFixtureUInt64(_ value: UInt64, to data: inout Data, at offset: Int) {
  for index in 0..<8 {
    data[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64(index * 8))
  }
}
