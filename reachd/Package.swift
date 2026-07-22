// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "reachd",
    platforms: [.macOS("27.0")],
    products: [
        .executable(name: "reachd", targets: ["reachd"]),
        .library(name: "ReachDaemon", targets: ["ReachDaemon"]),
    ],
    dependencies: [
        .package(path: "../ReachKit"),
        .package(url: "https://github.com/ml-explore/mlx-swift-lm.git", from: "3.31.3"),
        .package(url: "https://github.com/huggingface/swift-transformers.git", from: "1.3.0"),
        .package(url: "https://github.com/huggingface/swift-huggingface.git", from: "0.9.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
    ],
    targets: [
        // Thin CLI over the daemon library: serve, pair, ca, wg, status.
        .executableTarget(
            name: "reachd",
            dependencies: [
                "ReachDaemon",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),

        // The daemon's organs: slot host, MLX filling, session residency,
        // enrollment, cluster CA, mesh hosting.
        .target(
            name: "ReachDaemon",
            dependencies: [
                .product(name: "ReachWire", package: "ReachKit"),
                .product(name: "ReachTransport", package: "ReachKit"),
                .product(name: "ReachIdentity", package: "ReachKit"),
                .product(name: "MLXLLM", package: "mlx-swift-lm"),
                .product(name: "MLXLMCommon", package: "mlx-swift-lm"),
                .product(name: "MLXHuggingFace", package: "mlx-swift-lm"),
                .product(name: "Transformers", package: "swift-transformers"),
                .product(name: "HuggingFace", package: "swift-huggingface"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),

        .testTarget(name: "ReachDaemonTests", dependencies: ["ReachDaemon"]),
    ]
)
