import Foundation
import Testing

@testable import ReleasePackageCore

private func putU32(_ value: UInt32, at offset: Int, in data: inout Data) {
  for index in 0..<4 { data[offset + index] = UInt8((value >> UInt32(index * 8)) & 0xff) }
}

private func putU64(_ value: UInt64, at offset: Int, in data: inout Data) {
  for index in 0..<8 { data[offset + index] = UInt8((value >> UInt64(index * 8)) & 0xff) }
}

private func putName(_ value: String, at offset: Int, in data: inout Data) {
  for (index, byte) in value.utf8.prefix(16).enumerated() { data[offset + index] = byte }
}

private func syntheticMachO(uuidSeed: UInt8, signatureSeed: UInt8, runtimeSeed: UInt8)
  -> Data
{
  var data = Data(repeating: 0, count: 0x300)
  putU32(0xfeed_facf, at: 0, in: &data)
  putU32(0x0100_000c, at: 4, in: &data)
  putU32(0, at: 8, in: &data)
  putU32(2, at: 12, in: &data)
  putU32(3, at: 16, in: &data)
  putU32(192, at: 20, in: &data)

  let segment = 32
  putU32(0x19, at: segment, in: &data)
  putU32(152, at: segment + 4, in: &data)
  putName("__TEXT", at: segment + 8, in: &data)
  putU64(0x300, at: segment + 32, in: &data)
  putU32(1, at: segment + 64, in: &data)
  let section = segment + 72
  putName("__text", at: section, in: &data)
  putName("__TEXT", at: section + 16, in: &data)
  putU64(4, at: section + 40, in: &data)
  putU32(0x200, at: section + 48, in: &data)
  putU32(2, at: section + 52, in: &data)
  putU32(0x8000_0400, at: section + 64, in: &data)

  let uuid = segment + 152
  putU32(0x1b, at: uuid, in: &data)
  putU32(24, at: uuid + 4, in: &data)
  for index in 0..<16 { data[uuid + 8 + index] = uuidSeed &+ UInt8(index) }

  let signature = uuid + 24
  putU32(0x1d, at: signature, in: &data)
  putU32(16, at: signature + 4, in: &data)
  putU32(0x240, at: signature + 8, in: &data)
  putU32(16, at: signature + 12, in: &data)
  for index in 0..<16 { data[0x240 + index] = signatureSeed &+ UInt8(index) }
  for index in 0..<4 { data[0x200 + index] = runtimeSeed &+ UInt8(index) }
  return data
}

@Test func runtimeDigestIgnoresUUIDAndSignatureButDetectsExecutedBytes() throws {
  let root = try makeTemporaryDirectory("runtime-content")
  defer { removeTemporaryDirectory(root) }
  let first = root.appendingPathComponent("first")
  let second = root.appendingPathComponent("second")
  let changed = root.appendingPathComponent("changed")
  try SecureFiles.atomicWrite(
    syntheticMachO(uuidSeed: 1, signatureSeed: 2, runtimeSeed: 3), to: first)
  try SecureFiles.atomicWrite(
    syntheticMachO(uuidSeed: 40, signatureSeed: 80, runtimeSeed: 3), to: second)
  try SecureFiles.atomicWrite(
    syntheticMachO(uuidSeed: 1, signatureSeed: 2, runtimeSeed: 4), to: changed)
  let firstDigest = try MachORuntimeContentDigest.digest(first)
  #expect(firstDigest == (try MachORuntimeContentDigest.digest(second)))
  #expect(firstDigest != (try MachORuntimeContentDigest.digest(changed)))
}

@Test func runtimeDigestRefusesTruncatedAndOutOfBoundsMachO() throws {
  let root = try makeTemporaryDirectory("runtime-content-refusal")
  defer { removeTemporaryDirectory(root) }
  let truncated = root.appendingPathComponent("truncated")
  try SecureFiles.atomicWrite(Data(repeating: 0, count: 16), to: truncated)
  #expect(throws: ReleasePackageError.self) {
    try MachORuntimeContentDigest.digest(truncated)
  }

  var escaped = syntheticMachO(uuidSeed: 1, signatureSeed: 2, runtimeSeed: 3)
  putU64(32, at: 32 + 72 + 40, in: &escaped)
  putU32(0x2f8, at: 32 + 72 + 48, in: &escaped)
  let escapedURL = root.appendingPathComponent("escaped")
  try SecureFiles.atomicWrite(escaped, to: escapedURL)
  #expect(throws: ReleasePackageError.self) {
    try MachORuntimeContentDigest.digest(escapedURL)
  }
}
