import Foundation

public struct ToolchainAuthority: Codable, Equatable, Sendable {
  public let xcode: String
  public let swift: String
  public let sdkPath: String
  public let sdkVersion: String
  public let macOSBuild: String
  public let go: String
}

public struct ManifestPayloadMember: Codable, Equatable, Sendable {
  public let path: String
  public let componentIdentifier: String
  public let type: String
  public let owner: String
  public let group: String
  public let mode: String
  public let size: UInt64
  public let sha256: String?
  public let linkTarget: String?

  init(record: PayloadRecord, componentIdentifier: String) throws {
    guard record.uid == 0, record.gid == 0 else {
      throw ReleasePackageError.verification("payload member is not root:wheel: \(record.path)")
    }
    let absolute: String
    if record.path == "." {
      absolute = "/"
    } else {
      guard record.path.hasPrefix("./") else {
        throw ReleasePackageError.unsafePath(record.path)
      }
      absolute = "/" + record.path.dropFirst(2)
    }
    path = absolute
    self.componentIdentifier = componentIdentifier
    type = record.kind.rawValue
    owner = "root"
    group = "wheel"
    mode = String(format: "%04o", record.mode & 0o7777)
    size = record.size
    sha256 = record.sha256
    linkTarget = record.linkTarget
  }
}

public struct PayloadManifest: Codable, Equatable, Sendable {
  public struct ProductAuthority: Codable, Equatable, Sendable {
    public let name: String
    public let version: DottedVersion
    public let architecture: String
    public let minimumMacOS: DottedVersion
  }

  public struct ComponentAuthority: Codable, Equatable, Sendable {
    public let identifier: String
    public let version: DottedVersion
  }

  public struct DependencyPin: Codable, Equatable, Sendable {
    public let identity: String
    public let revision: String
    public let version: String?
    public let tree: String?
  }

  public let schemaVersion: Int
  public let product: ProductAuthority
  public let host: ComponentAuthority
  public let helper: ComponentAuthority
  public let compatibility: ReleaseConfiguration.Compatibility
  public let source: SourceAuthority
  public let releaseConfigurationSHA256: String
  public let releaseToolSourceSHA256: String
  public let noticeAuthoritySHA256: String
  public let dependencyDepotSHA256: String
  public let swiftPins: [DependencyPin]
  public let goModules: [DependencyPin]
  public let toolchain: ToolchainAuthority
  public let packageIdentifiers: [String]
  public let linkedSystemLibraries: [String]
  public let noticeSetSHA256: String
  public let bundleTreeSHA256: String
  public let payload: [ManifestPayloadMember]

  public static func make(
    configuration: ReleaseConfiguration,
    source: SourceAuthority,
    releaseConfigurationSHA256: String,
    releaseToolSourceSHA256: String,
    noticeAuthoritySHA256: String,
    dependencyDepotSHA256: String,
    depot: DependencyDepotManifest,
    toolchain: ToolchainAuthority,
    linkedSystemLibraries: [String],
    noticeSetSHA256: String,
    hostRecords: [PayloadRecord],
    helperRecords: [PayloadRecord]
  ) throws -> Self {
    let manifestPath = "/Library/Application Support/Reach/Release/payload-manifest.json"
    var members =
      try hostRecords.map {
        try ManifestPayloadMember(
          record: $0, componentIdentifier: configuration.components.host.identifier)
      }
      + helperRecords.map {
        try ManifestPayloadMember(
          record: $0, componentIdentifier: configuration.components.helper.identifier)
      }
    members.removeAll { $0.path == manifestPath }
    guard !members.contains(where: { $0.path == manifestPath }) else {
      throw ReleasePackageError.verification("payload manifest contains a self-entry")
    }
    members.sort {
      ($0.path, $0.componentIdentifier) < ($1.path, $1.componentIdentifier)
    }
    let bundleLines =
      members.filter {
        $0.path.hasPrefix("/Library/Application Support/Reach/Host/") && $0.path.contains(".bundle")
      }.map {
        "\($0.path)\t\($0.type)\t\($0.mode)\t\($0.size)\t\($0.sha256 ?? "-")"
      }.joined(separator: "\n") + "\n"
    return Self(
      schemaVersion: 1,
      product: .init(
        name: configuration.product.name,
        version: configuration.product.version,
        architecture: configuration.product.architecture,
        minimumMacOS: configuration.product.minimumMacOS
      ),
      host: .init(
        identifier: configuration.components.host.identifier,
        version: configuration.components.host.version),
      helper: .init(
        identifier: configuration.components.helper.identifier,
        version: configuration.components.helper.version),
      compatibility: configuration.compatibility,
      source: source,
      releaseConfigurationSHA256: releaseConfigurationSHA256,
      releaseToolSourceSHA256: releaseToolSourceSHA256,
      noticeAuthoritySHA256: noticeAuthoritySHA256,
      dependencyDepotSHA256: dependencyDepotSHA256,
      swiftPins: depot.swiftPins.map {
        .init(identity: $0.identity, revision: $0.revision, version: $0.version, tree: $0.tree)
      },
      goModules: depot.goModules.map {
        .init(identity: $0.path, revision: $0.version, version: $0.version, tree: $0.treeSHA256)
      },
      toolchain: toolchain,
      packageIdentifiers: [
        configuration.components.host.identifier, configuration.components.helper.identifier,
      ],
      linkedSystemLibraries: linkedSystemLibraries.sorted(),
      noticeSetSHA256: noticeSetSHA256,
      bundleTreeSHA256: Digests.sha256(Data(bundleLines.utf8)),
      payload: members
    )
  }
}

public struct ComponentSemantics: Codable, Equatable, Sendable {
  public let identifier: String
  public let version: DottedVersion
  public let packageInfoSHA256: String
  public let bomSHA256: String
  public let bomListingSHA256: String
  public let payloadSHA256: String
  public let uncompressedPayloadSHA256: String
  public let payload: [PayloadRecord]
}

public struct UnsignedPackageSemantics: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let productVersion: DottedVersion
  public let architecture: String
  public let distributionSHA256: String
  public let outerMemberOrder: [String]
  public let scriptsPresent: Bool
  public let resourcesPresent: Bool
  public let components: [ComponentSemantics]
}

public struct ReleaseProvenance: Codable, Equatable, Sendable {
  public struct Artifact: Codable, Equatable, Sendable {
    public let path: String
    public let size: UInt64
    public let sha256: String
  }

  public struct SourceStage: Codable, Equatable, Sendable {
    public let name: String
    public let authority: SourceAuthority
    public let releaseConfigurationSHA256: String
    public let releaseToolSourceSHA256: String
    public let noticeAuthoritySHA256: String
    public let dependencyDepotSHA256: String
  }

  public struct PayloadStage: Codable, Equatable, Sendable {
    public let name: String
    public let embeddedManifest: Artifact
    public let notices: Artifact
    public let hostComponents: [Artifact]
    public let helperComponents: [Artifact]
    public let hostBOMs: [Artifact]
    public let helperBOMs: [Artifact]
  }

  public struct UnsignedStage: Codable, Equatable, Sendable {
    public let name: String
    public let containers: [Artifact]
    public let selectedContainer: Artifact
    public let normalizedSemanticSHA256: String
    public let distributionSHA256: String
  }

  public let schemaVersion: Int
  public let p0: SourceStage
  public let p1: PayloadStage
  public let u1: UnsignedStage
}

public enum PackageDocuments {
  public static func packageInfo(
    identifier: String,
    version: DottedVersion,
    tree: PayloadTree
  ) -> Data {
    Data(
      """
      <?xml version="1.0" encoding="utf-8"?>
      <pkg-info overwrite-permissions="true" relocatable="false" identifier="\(identifier)" postinstall-action="none" version="\(version)" format-version="2" generator-version="Reach" auth="root">
          <payload numberOfFiles="\(tree.records.count)" installKBytes="\(tree.installKBytes)"/>
          <bundle-version/>
          <upgrade-bundle/>
          <update-bundle/>
          <atomic-update-bundle/>
          <strict-identifier/>
          <relocate/>
      </pkg-info>
      """.utf8)
  }

  public static func distribution(configuration: ReleaseConfiguration) -> Data {
    Data(
      """
      <?xml version="1.0" encoding="utf-8"?>
      <installer-gui-script minSpecVersion="1">
          <title>Reach</title>
          <options customize="never" require-scripts="false" hostArchitectures="arm64"/>
          <choices-outline>
              <line choice="default">
                  <line choice="systems.reach.host"/>
                  <line choice="systems.reach.meshd"/>
              </line>
          </choices-outline>
          <choice id="default"/>
          <choice id="systems.reach.host" visible="false" selected="true" enabled="false">
              <pkg-ref id="systems.reach.host"/>
          </choice>
          <choice id="systems.reach.meshd" visible="false" selected="true" enabled="false">
              <pkg-ref id="systems.reach.meshd"/>
          </choice>
          <pkg-ref id="systems.reach.host" version="\(configuration.components.host.version)" active="true" onConclusion="none">systems.reach.host.pkg</pkg-ref>
          <pkg-ref id="systems.reach.meshd" version="\(configuration.components.helper.version)" active="true" onConclusion="none">systems.reach.meshd.pkg</pkg-ref>
      </installer-gui-script>
      """.utf8)
  }

  public static func productbuildDistribution(
    configuration: ReleaseConfiguration,
    hostInstallKBytes: UInt64,
    helperInstallKBytes: UInt64
  ) -> Data {
    Data(
      """
      <?xml version="1.0" encoding="utf-8" standalone="yes"?>
      <installer-gui-script minSpecVersion="1">
          <title>Reach</title>
          <options customize="never" require-scripts="false" hostArchitectures="arm64"/>
          <choices-outline>
              <line choice="default">
                  <line choice="systems.reach.host"/>
                  <line choice="systems.reach.meshd"/>
              </line>
          </choices-outline>
          <choice id="default"/>
          <choice id="systems.reach.host" visible="false" selected="true" enabled="false">
              <pkg-ref id="systems.reach.host"/>
          </choice>
          <choice id="systems.reach.meshd" visible="false" selected="true" enabled="false">
              <pkg-ref id="systems.reach.meshd"/>
          </choice>
          <pkg-ref id="systems.reach.host" version="\(configuration.components.host.version)" active="true" onConclusion="none" installKBytes="\(hostInstallKBytes)" updateKBytes="0">#systems.reach.host.pkg</pkg-ref>
          <pkg-ref id="systems.reach.meshd" version="\(configuration.components.helper.version)" active="true" onConclusion="none" installKBytes="\(helperInstallKBytes)" updateKBytes="0">#systems.reach.meshd.pkg</pkg-ref>
          <pkg-ref id="systems.reach.host">
              <bundle-version/>
          </pkg-ref>
          <pkg-ref id="systems.reach.meshd">
              <bundle-version/>
          </pkg-ref>
      </installer-gui-script>
      """.utf8)
  }
}
