// swift-tools-version: 6.4
import PackageDescription

// run.py copies the real ReachWire sources and selected tests beside this file.
let package = Package(
    name: "DurableSessionProtocol",
    platforms: [.macOS(.v27)],
    products: [.library(name: "ReachWire", targets: ["ReachWire"])],
    targets: [
        .target(name: "ReachWire"),
        .testTarget(name: "ReachWireTests", dependencies: ["ReachWire"]),
    ]
)
