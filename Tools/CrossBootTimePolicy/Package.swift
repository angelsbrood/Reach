// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CrossBootTimePolicy",
    platforms: [.macOS(.v14)],
    products: [.library(name: "ClockPolicy", targets: ["ClockPolicy"]), .executable(name: "clock-qualification", targets: ["ClockQualification"]),
               .library(name: "WitnessAccess", targets: ["WitnessAccess"]),
               .executable(name: "witness-access-qualification", targets: ["WitnessAccessQualification"])],
    targets: [
        .target(name: "ClockPolicy"),
        .target(name: "WitnessAccess", dependencies: ["ClockPolicy"]),
        .executableTarget(name: "WitnessAccessQualification", dependencies: ["ClockPolicy", "WitnessAccess"]),
        .testTarget(name: "WitnessAccessTests", dependencies: ["ClockPolicy", "WitnessAccess"]),
        .executableTarget(name: "ClockQualification", dependencies: ["ClockPolicy"]),
        .testTarget(name: "ClockPolicyTests", dependencies: ["ClockPolicy"])
    ]
)
