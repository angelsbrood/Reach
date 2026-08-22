// swift-tools-version: 6.1
import PackageDescription

let package = Package(
  name: "ReleasePackage",
  platforms: [.macOS("27.0")],
  products: [
    .library(name: "ReleasePackageCore", targets: ["ReleasePackageCore"]),
    .executable(name: "reach-release-package", targets: ["reach-release-package"]),
  ],
  targets: [
    .target(
      name: "ReleasePackageCore",
      linkerSettings: [
        .linkedFramework("LocalAuthentication"),
        .linkedFramework("Security"),
      ]
    ),
    .executableTarget(
      name: "reach-release-package",
      dependencies: ["ReleasePackageCore"]
    ),
    .testTarget(
      name: "ReleasePackageCoreTests",
      dependencies: ["ReleasePackageCore"]
    ),
  ]
)
