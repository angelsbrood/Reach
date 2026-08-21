import Darwin
import Foundation
import Testing

@testable import ReleasePackageCore

func makeTemporaryDirectory(_ label: String) throws -> URL {
  let root = URL(fileURLWithPath: "/private/tmp")
    .appendingPathComponent("reach-release-package-tests-\(label)-\(UUID().uuidString)")
  try SecureFiles.createPrivateDirectory(root)
  return root
}

func removeTemporaryDirectory(_ url: URL) {
  try? FileManager.default.removeItem(at: url)
}

func repositoryRoot() -> URL {
  var value = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
  for _ in 0..<4 { value.deleteLastPathComponent() }
  return value
}

func canonicalPayloadFixture(at root: URL, includeAlias: Bool = true) throws -> URL {
  let payload = root.appendingPathComponent("payload")
  try SecureFiles.createDirectory(payload, mode: 0o755)
  var current = payload
  for component in ["Library", "Application Support", "Reach", "Host"] {
    current.appendPathComponent(component)
    try SecureFiles.createDirectory(current, mode: 0o755)
  }
  try SecureFiles.atomicWrite(
    Data("reach\n".utf8), to: current.appendingPathComponent("reachd"), mode: 0o755)
  if includeAlias {
    current = payload
    for component in ["usr", "local", "bin"] {
      current.appendPathComponent(component)
      try SecureFiles.createDirectory(current, mode: 0o755)
    }
    try SecureFiles.createSymlink(
      at: current.appendingPathComponent("reachd"),
      target: "/Library/Application Support/Reach/Host/reachd"
    )
  }
  return payload
}

func mutateJSON(_ source: URL, _ mutation: (inout [String: Any]) -> Void, to destination: URL)
  throws
{
  var object = try #require(
    try JSONSerialization.jsonObject(with: Data(contentsOf: source)) as? [String: Any])
  mutation(&object)
  let data = try JSONSerialization.data(
    withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
  try SecureFiles.atomicWrite(data, to: destination)
}
