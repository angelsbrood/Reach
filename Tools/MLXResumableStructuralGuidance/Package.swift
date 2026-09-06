// swift-tools-version: 6.1
// Offline template: run.py copies exact local sources under the private harness.
import PackageDescription
let package = Package(
    name: "MLXResumableStructuralGuidanceCandidate",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "StructuralGuidanceWorker", targets: ["StructuralGuidanceWorker"])],
    dependencies: [.package(path: "../mlx-swift")],
    targets: [
        .target(
            name: "MLXCXGrammar",
            path: "mlx-swift-lm/Libraries/MLXCXGrammar",
            exclude: [
                // Compiled via Libraries/MLXCXGrammar/grammar_functor_wrapper.cc to
                // provide out-of-class definitions for static const members that
                // clang ODR-uses through variadic templates.
                "xgrammar/cpp/grammar_functor.cc"
            ],
            publicHeadersPath: "include",
            cxxSettings: [
                .headerSearchPath("xgrammar/include"),
                .headerSearchPath("xgrammar/cpp"),
                .headerSearchPath("xgrammar/3rdparty/picojson"),
                .headerSearchPath("xgrammar/3rdparty/dlpack/include"),
                .define("XGRAMMAR_ENABLE_CPPTRACE", to: "0"),
                .define("XGRAMMAR_ENABLE_INTERNAL_CHECK", to: "0"),
                // Rename the vendored C++ namespaces at compile time so this
                // target's symbols cannot collide with another xgrammar in the
                // same binary (e.g. CoreAI's prebuilt copy). Token-level
                // substitution: it rewrites bare `xgrammar` / `picojson`
                // identifiers (namespace decls and `::` uses) but not header
                // names, string literals, `XGRAMMAR_*` macros, or `xg_*` tokens.
                .define("xgrammar", to: "mlx_xgrammar"),
                .define("picojson", to: "mlx_picojson"),
                // Vendored upstream xgrammar/picojson is compiled as-is and is
                // not warning-clean under Xcode's default warning set (e.g.
                // -Wshorten-64-to-32). Suppress all warnings for this target so
                // the unmodified upstream C++ does not spam consumers' builds.
                // `-w` wins over any preceding -W flags. Scoped to this target
                // only; our own shim (shim.cc) is small and stable.
                .unsafeFlags(["-w"], .when(platforms: [.macOS, .iOS, .visionOS, .tvOS])),
            ],
            linkerSettings: [
                // Apple platforms only: on Linux the Swift toolchain links libstdc++,
                // and there is no libc++ to link against.
                .linkedLibrary("c++", .when(platforms: [.macOS, .iOS, .visionOS, .tvOS]))
            ]
        ),
        .target(
            name: "MLXGuidedGeneration",
            dependencies: [
                "MLXLMCommon",
                "MLXCXGrammar",
                .product(name: "MLX", package: "mlx-swift"),
            ],
            path: "mlx-swift-lm/Libraries/MLXGuidedGeneration"
        ),
        .target(name: "MLXLMCommon", dependencies: [
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
            .product(name: "MLXOptimizers", package: "mlx-swift"),
        ], path: "mlx-swift-lm/Libraries/MLXLMCommon", exclude: ["README.md"]),
        .target(name: "MLXLLM", dependencies: ["MLXLMCommon",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ], path: "TinyLlama", sources: ["LLMModel.swift", "Llama.swift"]),
        .executableTarget(name: "StructuralGuidanceWorker", dependencies: ["MLXLMCommon", "MLXLLM", "MLXGuidedGeneration",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ]),
        .testTarget(name: "MLXGuidedGenerationTests", dependencies: ["MLXLMCommon", "MLXLLM", "MLXGuidedGeneration",
            .product(name: "MLX", package: "mlx-swift"),
            .product(name: "MLXNN", package: "mlx-swift"),
        ], path: "FocusedTests", sources: [
            "ResumableStructuralGuidanceTests.swift", "ResumableStructuralGuidanceCheckpointTests.swift",
        ]),
    ],
    cxxLanguageStandard: .cxx17
)
