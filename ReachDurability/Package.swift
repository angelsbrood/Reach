// swift-tools-version: 6.1
import PackageDescription
let native="mlx-swift-lm"
func lm(_ name:String)->Target.Dependency { .product(name:name,package:native) }
func wire()->Target.Dependency { .product(name:"ReachWire",package:"ReachKit") }
let package=Package(
    name:"ReachDurability", platforms:[.macOS("27.0")],
    products:[.library(name:"ReachDurableRuntime",targets:["ReachDurableRuntime"])],
    dependencies:[.package(path:"../ReachKit"),.package(path:"../Vendor/mlx-swift-lm",traits:[]),
        .package(url:"https://github.com/ml-explore/mlx-swift",.upToNextMinor(from:"0.31.4"))],
    targets:[
        .target(name:"RequiredToolCoordinator",dependencies:[lm("MLXLMCommon"),lm("MLXGuidedGeneration"),wire()]),
        .target(name:"AllowedToolCoordinator",dependencies:["RequiredToolCoordinator",lm("MLXLMCommon"),lm("MLXGuidedGeneration"),wire()]),
        .target(name:"ResumableMLXProvider",dependencies:["AllowedToolCoordinator","RequiredToolCoordinator",lm("MLXLMCommon"),lm("MLXGuidedGeneration"),wire()]),
        .target(name:"DurableHostStore",dependencies:["ResumableMLXProvider",wire()]),
        .target(name:"HostClientContract"),.target(name:"RecoveryContract"),
        .target(name:"DurableClientReceipts",dependencies:[wire(),"HostClientContract","RecoveryContract"]),
        .target(name:"DurableSessionLifecycle",dependencies:["DurableHostStore","ResumableMLXProvider",wire(),"DurableClientReceipts","HostClientContract"]),
        .target(name:"DurableRootKeys"),.target(name:"DurableStoreBootstrap",dependencies:["DurableRootKeys"]),
        .target(name:"WireAdapterContract",dependencies:[wire(),"HostClientContract","RecoveryContract","DurableClientReceipts","DurableRootKeys","DurableStoreBootstrap"]),
        .target(name:"DurableHostWireAdapter",dependencies:["WireAdapterContract",wire(),"DurableSessionLifecycle","ResumableMLXProvider","DurableClientReceipts","HostClientContract","RecoveryContract"]),
        .target(name:"DurableClientWireAdapter",dependencies:["WireAdapterContract",wire(),"DurableClientReceipts","DurableStoreBootstrap","HostClientContract","RecoveryContract"]),
        .target(name:"RequestPreparationContract",dependencies:["DurableClientReceipts",wire(),"RecoveryContract","HostClientContract","WireAdapterContract"]),
        .target(name:"DurableRequestPreparation",dependencies:["RequestPreparationContract",wire(),lm("MLXLMCommon"),lm("MLXGuidedGeneration"),"RequiredToolCoordinator","AllowedToolCoordinator","ResumableMLXProvider","WireAdapterContract"]),
        .target(name:"ReachDurableRuntime",dependencies:["DurableRootKeys","DurableStoreBootstrap","DurableClientReceipts","DurableSessionLifecycle","DurableHostWireAdapter","DurableClientWireAdapter","RequestPreparationContract","DurableRequestPreparation","WireAdapterContract","RecoveryContract","HostClientContract","ResumableMLXProvider","RequiredToolCoordinator","AllowedToolCoordinator",wire(),lm("MLXLLM"),lm("MLXLMCommon"),lm("MLXGuidedGeneration"),.product(name:"MLX",package:"mlx-swift"),.product(name:"MLXNN",package:"mlx-swift")])
    ],swiftLanguageModes:[.v5],cxxLanguageStandard:.cxx17)
