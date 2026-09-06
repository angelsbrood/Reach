// swift-tools-version: 6.1
// Offline template: run.py copies exact local sources under the private harness.
import PackageDescription
let package = Package(
    name: "MLXResumableToolGenerationCandidate",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "ToolGenerationWorker", targets: ["ToolGenerationWorker"])],
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
        .executableTarget(name: "ToolGenerationWorker", dependencies: ["MLXLMCommon", "MLXLLM",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ]),
        .testTarget(name: "MLXLMTests", dependencies: ["MLXLMCommon", "MLXLLM",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ], path: "FocusedTests", sources: [
            "ResumableToolGenerationTests.swift", "ResumableToolGenerationCheckpointTests.swift",
        ]),
    ]
)
