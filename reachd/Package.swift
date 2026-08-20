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
        // Pinned to a revision, not a version: Gemma 4 landed on main after the
        // last tag (3.31.4), so `from:` cannot reach it. The commit is the one
        // the take was shot on — a filing artifact, so it names itself.
        .package(
            url: "https://github.com/ml-explore/mlx-swift-lm.git",
            revision: "83f3ef6dc5bc24daeea33cfd9e18ab1383bb0bc8",
            // reachd uses MLX's container loader, LLM, and guided-generation
            // products directly. The package's default-on Foundation Models
            // adapter is a separate, unused surface whose SDK signatures can
            // move between Xcode seeds; do not compile or link it into the
            // daemon merely because the dependency enables it by default.
            traits: []
        ),
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
                .product(name: "ReachKit", package: "ReachKit"),
            ]
        ),

        // The daemon's organs: slot host, MLX filling, session residency,
        // enrollment, cluster CA, mesh hosting.
        //
        // `ReachKit` — the client — is here for one organ, `ClusterDial`, and
        // the reason is the difference between a diagnostic that can be
        // asserted and one that can only be run by hand. A dial that proves
        // the cluster answers has to cross the real listener with the
        // ordinary client stack, and the alternative placement (the `reachd`
        // executable target, beside `Selftest`) puts it somewhere
        // `ReachDaemonTests` cannot reach, which would leave the tests
        // re-implementing the thing under test. There is no cycle — ReachKit
        // knows nothing of the daemon — and nothing new enters the shipped
        // binary, which already links it.
        .target(
            name: "ReachDaemon",
            dependencies: [
                .product(name: "ReachKit", package: "ReachKit"),
                .product(name: "ReachWire", package: "ReachKit"),
                .product(name: "ReachTransport", package: "ReachKit"),
                .product(name: "ReachIdentity", package: "ReachKit"),
                .product(name: "MLXLLM", package: "mlx-swift-lm"),
                .product(name: "MLXLMCommon", package: "mlx-swift-lm"),
                .product(name: "MLXHuggingFace", package: "mlx-swift-lm"),
                .product(name: "MLXGuidedGeneration", package: "mlx-swift-lm"),
                .product(name: "Transformers", package: "swift-transformers"),
                .product(name: "HuggingFace", package: "swift-huggingface"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),

        .testTarget(
            name: "ReachDaemonTests",
            dependencies: [
                "ReachDaemon",
                .product(name: "ReachKit", package: "ReachKit"),
                .product(name: "ReachWire", package: "ReachKit"),
                .product(name: "MLXLMCommon", package: "mlx-swift-lm"),
                .product(name: "MLXGuidedGeneration", package: "mlx-swift-lm"),
            ]
        ),
    ]
)
