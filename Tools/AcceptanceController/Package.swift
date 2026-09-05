// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "AcceptanceController",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AcceptanceControllerCore", targets: ["AcceptanceControllerCore"]),
        .executable(name: "reach-acceptance-controller", targets: ["reach-acceptance-controller"]),
        .executable(name: "reach-acceptance-driver", targets: ["reach-acceptance-driver"]),
        .executable(name: "reach-acceptance-launcher", targets: ["reach-acceptance-launcher"]),
    ],
    targets: [
        .executableTarget(name: "reach-acceptance-driver", dependencies: ["AcceptanceControllerCore"],
                          path: ".", exclude: ["Sources", "Tests", "BootstrapLauncher.swift"], sources: ["CampaignDriver.swift"]),
        .executableTarget(name: "reach-acceptance-launcher", dependencies: ["AcceptanceControllerCore"],
                          path: ".", exclude: ["Sources", "Tests", "CampaignDriver.swift"], sources: ["BootstrapLauncher.swift"]),
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
