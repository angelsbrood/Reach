// swift-tools-version: 6.1
import PackageDescription

let package = Package(
  name: "ReleasePackage",
  platforms: [.macOS("27.0")],
  products: [
    .library(name: "ReleasePackageCore", targets: ["ReleasePackageCore"]),
    .executable(name: "reach-release-package", targets: ["reach-release-package"]),
    .executable(name: "reach-release-acceptance", targets: ["reach-release-acceptance"]),
  ],
  targets: [
    .target(
      name: "ReleasePackageCore",
      linkerSettings: [
        .linkedFramework("LocalAuthentication"),
        .linkedFramework("Security"),
        .linkedFramework("Virtualization"),
      ]
    ),
    .executableTarget(
      name: "reach-release-package",
      dependencies: ["ReleasePackageCore"]
    ),
    .executableTarget(
      name: "reach-release-acceptance",
      dependencies: ["ReleasePackageCore"]
    ),
    .testTarget(
      name: "ReleasePackageCoreTests",
      dependencies: ["ReleasePackageCore"]
    ),
  ]
)
