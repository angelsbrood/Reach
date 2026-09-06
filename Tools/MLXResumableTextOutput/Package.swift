// swift-tools-version: 6.1
// Offline template: run.py copies exact local sources under the private harness.
import PackageDescription
let package = Package(
    name: "MLXResumableTextOutputCandidate",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "TextOutputWorker", targets: ["TextOutputWorker"])],
    dependencies: [.package(path: "../mlx-swift")],
    targets: [
        .target(name: "MLXLMCommon", dependencies: [
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
            .product(name: "MLXOptimizers", package: "mlx-swift"),
        ], path: "mlx-swift-lm/Libraries/MLXLMCommon", exclude: ["README.md"]),
        .target(name: "MLXLLM", dependencies: ["MLXLMCommon",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ], path: "TinyLlama", sources: ["LLMModel.swift", "Llama.swift"]),
        .executableTarget(name: "TextOutputWorker", dependencies: ["MLXLMCommon", "MLXLLM",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ]),
        .testTarget(name: "MLXLMTests", dependencies: ["MLXLMCommon", "MLXLLM",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ], path: "FocusedTests", sources: [
            "StreamingDetokenizerTests.swift", "ResumableTextOutputTests.swift",
            "ResumableTextCheckpointTests.swift",
        ]),
    ]
)
