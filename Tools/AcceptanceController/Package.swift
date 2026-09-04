// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AcceptanceController",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AcceptanceControllerCore", targets: ["AcceptanceControllerCore"]),
        .executable(name: "reach-acceptance-controller", targets: ["reach-acceptance-controller"]),
    ],
    targets: [
        .target(name: "AcceptanceControllerCore"),
        .executableTarget(
            name: "reach-acceptance-controller",
            dependencies: ["AcceptanceControllerCore"]
        ),
        .testTarget(
            name: "AcceptanceControllerCoreTests",
            dependencies: ["AcceptanceControllerCore"]
        ),
    ]
)
