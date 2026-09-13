// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CrossBootTimePolicy",
    platforms: [.macOS(.v14)],
    products: [.library(name: "ClockPolicy", targets: ["ClockPolicy"]), .executable(name: "clock-qualification", targets: ["ClockQualification"])],
    targets: [
        .target(name: "ClockPolicy"),
        .executableTarget(name: "ClockQualification", dependencies: ["ClockPolicy"]),
        .testTarget(name: "ClockPolicyTests", dependencies: ["ClockPolicy"])
    ]
)
