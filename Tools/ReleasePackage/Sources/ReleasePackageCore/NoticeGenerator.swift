import Foundation

public struct NoticeManifest: Codable, Equatable, Sendable {
  public struct Input: Codable, Equatable, Sendable {
    public let kind: String
    public let declaredPath: String
    public let sha256: String
  }

  public struct Family: Codable, Equatable, Sendable {
    public let id: String
    public let scope: String
    public let sourceRoot: String
    public let inputs: [Input]
  }

  public let schemaVersion: Int
  public let noticeSetSHA256: String
  public let noticesPath: String
  public let noticesSHA256: String
  public let families: [Family]
}

public struct GeneratedNotices: Equatable, Sendable {
  public let markdown: Data
  public let manifest: NoticeManifest
}

public enum NoticeGenerator {
  public static func generate(
    authority: NoticeAuthority,
    depot: DependencyDepotManifest,
    depotRoot: URL
  ) throws -> GeneratedNotices {
    let inputByFamily = Dictionary(grouping: depot.noticeInputs, by: \.familyID)
    guard Set(inputByFamily.keys) == Set(authority.families.map(\.id)) else {
      throw ReleasePackageError.verification("notice depot contains an unknown or missing family")
    }
    var manifestFamilies: [NoticeManifest.Family] = []
    var markdown = """
      # Reach third-party and shipped-source notices

      This file is generated from the exact dependency depot used to build this unsigned package. It records license and notice texts; it does not state a legal or export-control conclusion.

      """

    for family in authority.families.sorted(by: { $0.id < $1.id }) {
      let expected =
        family.licensePaths.map { ("license", $0) } + family.noticePaths.map { ("notice", $0) }
      let retained = (inputByFamily[family.id] ?? []).sorted {
        ($0.kind, $0.declaredPath) < ($1.kind, $1.declaredPath)
      }
      let retainedKeys = retained.map { "\($0.kind)\u{0}\($0.declaredPath)" }
      let expectedKeys = expected.map { "\($0.0)\u{0}\($0.1)" }.sorted()
      guard retainedKeys == expectedKeys else {
        throw ReleasePackageError.verification("notice input set changed for \(family.id)")
      }

      markdown += "## \(family.id)\n\n"
      markdown += "Scope: `\(family.scope)`  \n"
      markdown += "Source authority: `\(family.sourceRoot)`\n\n"
      var inputs: [NoticeManifest.Input] = []
      for item in retained {
        let url = depotRoot.appendingPathComponent(item.depotPath)
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        guard Digests.sha256(data) == item.sha256 else {
          throw ReleasePackageError.verification("notice input digest changed for \(family.id)")
        }
        guard let text = String(data: data, encoding: .utf8) else {
          throw ReleasePackageError.verification("notice input is not UTF-8 for \(family.id)")
        }
        markdown += "### \(item.kind): `\(item.declaredPath)`\n\n"
        markdown += "SHA-256: `\(item.sha256)`\n\n"
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
          .replacingOccurrences(of: "\r", with: "\n")
        for line in normalized.split(separator: "\n", omittingEmptySubsequences: false) {
          markdown += "    \(line)\n"
        }
        markdown += "\n"
        inputs.append(.init(kind: item.kind, declaredPath: item.declaredPath, sha256: item.sha256))
      }
      manifestFamilies.append(
        .init(
          id: family.id,
          scope: family.scope,
          sourceRoot: family.sourceRoot,
          inputs: inputs
        ))
    }

    let familyAuthority =
      manifestFamilies.map { family in
        "\(family.id)\t\(family.scope)\t\(family.sourceRoot)\t"
          + family.inputs.map {
            "\($0.kind):\($0.declaredPath):\($0.sha256)"
          }.joined(separator: ",")
      }.joined(separator: "\n") + "\n"
    let noticeSet = Digests.sha256(Data(familyAuthority.utf8))
    let markdownData = Data(markdown.utf8)
    let manifest = NoticeManifest(
      schemaVersion: 1,
      noticeSetSHA256: noticeSet,
      noticesPath: "/Library/Application Support/Reach/Release/THIRD-PARTY-NOTICES.md",
      noticesSHA256: Digests.sha256(markdownData),
      families: manifestFamilies
    )
    return GeneratedNotices(markdown: markdownData, manifest: manifest)
  }
}
