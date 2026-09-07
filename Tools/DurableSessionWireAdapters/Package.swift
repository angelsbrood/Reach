// swift-tools-version: 6.1
// Offline template: run.py copies exact local sources under the private harness.
import PackageDescription
let package = Package(
    name: "DurableSessionWireAdaptersCandidate",
    platforms: [.macOS("27.0")],
    products: [.executable(name: "KeychainWorker", targets: ["KeychainWorker"]), .executable(name: "HostWireWorker", targets: ["HostWireWorker"]), .executable(name: "ClientWireWorker", targets: ["ClientWireWorker"])],
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
        .target(name: "ReachWire", path: "Sources/ReachWire"),
        .target(name: "RequiredToolCoordinator", dependencies: ["MLXLMCommon", "MLXGuidedGeneration", "ReachWire"]),
        .target(name: "AllowedToolCoordinator", dependencies: ["RequiredToolCoordinator", "MLXLMCommon", "MLXGuidedGeneration", "ReachWire"]),
        .target(name: "ResumableMLXProvider", dependencies: ["AllowedToolCoordinator", "RequiredToolCoordinator", "MLXLMCommon", "MLXGuidedGeneration", "ReachWire"]),
        .target(name: "DurableHostStore", dependencies: ["ResumableMLXProvider", "ReachWire"]),
        .target(name: "HostClientContract"),
        .target(name: "RecoveryContract"),
        .target(name: "DurableClientReceipts", dependencies: ["ReachWire", "HostClientContract", "RecoveryContract"]),
        .target(name: "DurableSessionLifecycle", dependencies: ["DurableHostStore", "ResumableMLXProvider", "ReachWire", "DurableClientReceipts", "HostClientContract"]),
        .target(name: "LifecycleFixtures", dependencies: ["DurableSessionLifecycle", "DurableHostStore", "ResumableMLXProvider", "AllowedToolCoordinator", "RequiredToolCoordinator", "MLXLMCommon", "MLXLLM", "MLXGuidedGeneration", "ReachWire",
            .product(name: "MLX", package: "mlx-swift"), .product(name: "MLXNN", package: "mlx-swift")]),
        .target(name: "DurableRootKeys"),
        .target(name: "DurableStoreBootstrap", dependencies: ["DurableRootKeys"]),
        .target(name: "WireAdapterContract", dependencies: ["ReachWire", "HostClientContract", "RecoveryContract", "DurableClientReceipts", "DurableRootKeys", "DurableStoreBootstrap"]),
        .target(name: "DurableHostWireAdapter", dependencies: ["WireAdapterContract", "ReachWire", "DurableSessionLifecycle", "ResumableMLXProvider", "DurableClientReceipts", "HostClientContract", "RecoveryContract"]),
        .target(name: "DurableClientWireAdapter", dependencies: ["WireAdapterContract", "ReachWire", "DurableClientReceipts", "DurableStoreBootstrap", "HostClientContract", "RecoveryContract"]),
        .target(name: "WireAdapterFixtures", dependencies: ["WireAdapterContract", "ReachWire", "LifecycleFixtures", "ResumableMLXProvider", .product(name: "MLX", package: "mlx-swift")]),
        .executableTarget(name: "KeychainWorker", dependencies: ["WireAdapterContract", "DurableRootKeys", "DurableStoreBootstrap"]),
        .executableTarget(name: "ClientWireWorker", dependencies: ["WireAdapterContract", "DurableClientWireAdapter", "DurableRootKeys", "DurableStoreBootstrap", "DurableClientReceipts"]),
        .executableTarget(name: "HostWireWorker", dependencies: ["WireAdapterContract", "DurableHostWireAdapter", "WireAdapterFixtures", "DurableRootKeys", "DurableStoreBootstrap", "DurableClientReceipts", "DurableSessionLifecycle", .product(name: "MLX", package: "mlx-swift")]),
        .testTarget(name: "DurableSessionWireAdapterTests", dependencies: ["WireAdapterContract", "DurableHostWireAdapter", "DurableClientWireAdapter", "WireAdapterFixtures", "ReachWire", "DurableSessionLifecycle", "DurableClientReceipts", "DurableRootKeys", "DurableStoreBootstrap", "HostClientContract", "RecoveryContract", "ResumableMLXProvider", .product(name: "MLX", package: "mlx-swift")]),
        .testTarget(name: "ReachWireTests", dependencies: ["ReachWire"]),
    ],
    swiftLanguageModes: [.v5],
    cxxLanguageStandard: .cxx17
)
