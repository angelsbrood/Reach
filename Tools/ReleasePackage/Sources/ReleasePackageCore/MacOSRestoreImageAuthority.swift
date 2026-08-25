import Darwin
import Foundation
import Virtualization

public struct MacOSRestoreImageRecord: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let sourceHost: String
  public let sourceURLSHA256: String
  public let fileName: String
  public let fileSize: UInt64
  public let fileSHA256: String
  public let productVersion: String
  public let buildVersion: String
  public let supported: Bool
  public let mostFeaturefulConfigurationPresent: Bool
  public let minimumCPUCount: Int
  public let minimumMemoryBytes: UInt64
  public let hardwareModelSHA256: String
  public let inspectionAuthority: String

  public func validate() throws {
    let finalBuild = #"^[0-9]+[A-Z][0-9]+$"#
    guard schemaVersion == 1,
      ["updates.cdn-apple.com", "oscdn.apple.com"].contains(sourceHost),
      Self.validSHA256(sourceURLSHA256), !fileName.isEmpty,
      fileName == URL(fileURLWithPath: fileName).lastPathComponent,
      fileName.lowercased().hasSuffix(".ipsw"), fileSize > 0,
      Self.validSHA256(fileSHA256), productVersion == "27.0.0",
      buildVersion.range(of: finalBuild, options: .regularExpression) != nil,
      supported, mostFeaturefulConfigurationPresent,
      minimumCPUCount > 0, minimumCPUCount <= TartHostController.cpuCount,
      minimumMemoryBytes > 0,
      minimumMemoryBytes <= TartHostController.memoryMiB * 1_024 * 1_024,
      Self.validSHA256(hardwareModelSHA256),
      inspectionAuthority == "VZMacOSRestoreImage.load(local-file)"
    else {
      throw ReleasePackageError.verification(
        "macOS restore-image authority is unsupported, nonfinal, or malformed")
    }
  }

  private static func validSHA256(_ value: String) -> Bool {
    value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
  }
}

struct LoadedMacOSRestoreImage: Equatable, Sendable {
  let localURL: URL
  let productVersion: String
  let buildVersion: String
  let supported: Bool
  let minimumCPUCount: Int
  let minimumMemoryBytes: UInt64
  let hardwareModelSHA256: String?
}

protocol MacOSRestoreImageLoading {
  func load(from localURL: URL) throws -> LoadedMacOSRestoreImage
}

protocol MacOSRestoreImageVerifying {
  func verify(recordURL: URL, localIPSW: URL) throws -> MacOSRestoreImageRecord
}

private final class RestoreImageResultBox: @unchecked Sendable {
  private let lock = NSLock()
  private var result: Result<VZMacOSRestoreImage, Error>?

  func store(_ value: Result<VZMacOSRestoreImage, Error>) {
    lock.lock()
    result = value
    lock.unlock()
  }

  func take() -> Result<VZMacOSRestoreImage, Error>? {
    lock.lock()
    defer { lock.unlock() }
    let value = result
    result = nil
    return value
  }
}

struct VirtualizationRestoreImageLoader: MacOSRestoreImageLoading {
  func load(from localURL: URL) throws -> LoadedMacOSRestoreImage {
    let semaphore = DispatchSemaphore(value: 0)
    let box = RestoreImageResultBox()
    VZMacOSRestoreImage.load(from: localURL) { result in
      box.store(result)
      semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + 120) == .success,
      let result = box.take()
    else {
      throw ReleasePackageError.processFailure(
        "Virtualization restore-image inspection exceeded 120 seconds")
    }
    let image: VZMacOSRestoreImage
    do {
      image = try result.get()
    } catch {
      throw ReleasePackageError.verification(
        "Virtualization refused the local restore image: \(error)")
    }
    let physicalInput = try ReleasePathAuthority.absoluteURL(
      localURL.path, label: "restore image")
    let physicalResult = try ReleasePathAuthority.absoluteURL(
      image.url.path, label: "loaded restore image")
    guard physicalInput.path.utf8.elementsEqual(physicalResult.path.utf8) else {
      throw ReleasePackageError.verification(
        "Virtualization loaded a different restore-image path")
    }
    let version = image.operatingSystemVersion
    let requirements = image.mostFeaturefulSupportedConfiguration
    return LoadedMacOSRestoreImage(
      localURL: physicalResult,
      productVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
      buildVersion: image.buildVersion,
      supported: image.isSupported,
      minimumCPUCount: requirements?.minimumSupportedCPUCount ?? 0,
      minimumMemoryBytes: requirements?.minimumSupportedMemorySize ?? 0,
      hardwareModelSHA256: requirements.map {
        Digests.sha256($0.hardwareModel.dataRepresentation)
      })
  }
}

public struct MacOSRestoreImageInspector {
  private let loader: any MacOSRestoreImageLoading

  public init() { loader = VirtualizationRestoreImageLoader() }

  init(loader: any MacOSRestoreImageLoading) { self.loader = loader }

  public func inspect(
    localIPSW: URL,
    expectedSHA256: String,
    sourceURL: String
  ) throws -> MacOSRestoreImageRecord {
    let local = try ReleasePathAuthority.absoluteURL(localIPSW.path, label: "local IPSW")
    var info = stat()
    guard lstat(local.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1,
      expectedSHA256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      try Digests.sha256(file: local) == expectedSHA256
    else {
      throw ReleasePackageError.verification("local IPSW bytes changed")
    }
    guard let source = URL(string: sourceURL), source.scheme == "https",
      source.user == nil, source.password == nil, source.query == nil, source.fragment == nil,
      let host = source.host?.lowercased(),
      ["updates.cdn-apple.com", "oscdn.apple.com"].contains(host),
      source.lastPathComponent.utf8.elementsEqual(local.lastPathComponent.utf8)
    else {
      throw ReleasePackageError.verification("restore-image source is not an exact Apple URL")
    }
    let loaded = try loader.load(from: local)
    guard loaded.localURL.path.utf8.elementsEqual(local.path.utf8),
      let hardware = loaded.hardwareModelSHA256
    else {
      throw ReleasePackageError.verification(
        "restore image lacks a supported local hardware configuration")
    }
    let value = MacOSRestoreImageRecord(
      schemaVersion: 1,
      sourceHost: host,
      sourceURLSHA256: Digests.sha256(Data(sourceURL.utf8)),
      fileName: local.lastPathComponent,
      fileSize: UInt64(info.st_size),
      fileSHA256: expectedSHA256,
      productVersion: loaded.productVersion,
      buildVersion: loaded.buildVersion,
      supported: loaded.supported,
      mostFeaturefulConfigurationPresent: true,
      minimumCPUCount: loaded.minimumCPUCount,
      minimumMemoryBytes: loaded.minimumMemoryBytes,
      hardwareModelSHA256: hardware,
      inspectionAuthority: "VZMacOSRestoreImage.load(local-file)")
    try value.validate()
    return value
  }

  public func verify(
    recordURL: URL,
    localIPSW: URL
  ) throws -> MacOSRestoreImageRecord {
    let data = try Data(contentsOf: recordURL, options: [.mappedIfSafe])
    let value = try JSONDecoder().decode(MacOSRestoreImageRecord.self, from: data)
    guard data == (try CanonicalJSON.encode(value)) else {
      throw ReleasePackageError.verification("restore-image record is not canonical JSON")
    }
    try value.validate()
    let local = try ReleasePathAuthority.absoluteURL(localIPSW.path, label: "local IPSW")
    var info = stat()
    guard lstat(local.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
      info.st_nlink == 1, local.lastPathComponent.utf8.elementsEqual(value.fileName.utf8),
      UInt64(info.st_size) == value.fileSize,
      try Digests.sha256(file: local) == value.fileSHA256
    else {
      throw ReleasePackageError.verification("local IPSW no longer matches its authority record")
    }
    let loaded = try loader.load(from: local)
    guard loaded.localURL.path.utf8.elementsEqual(local.path.utf8),
      loaded.productVersion == value.productVersion,
      loaded.buildVersion == value.buildVersion,
      loaded.supported == value.supported,
      loaded.minimumCPUCount == value.minimumCPUCount,
      loaded.minimumMemoryBytes == value.minimumMemoryBytes,
      loaded.hardwareModelSHA256 == value.hardwareModelSHA256
    else {
      throw ReleasePackageError.verification(
        "Virtualization restore-image semantics changed from the sealed authority")
    }
    return value
  }
}

extension MacOSRestoreImageInspector: MacOSRestoreImageVerifying {}
