// swift-tools-version: 6.1
// Offline template. run.py exports only the selected pinned sources into lm/.
import PackageDescription
let package = Package(
    name: "ResumableToolCallCandidate",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "ToolCallCheckpointWorker", targets: ["ToolCallCheckpointWorker"])],
    targets: [
        .target(name: "MLXLMCommon", path: "lm/Libraries/MLXLMCommon"),
        .executableTarget(name: "ToolCallCheckpointWorker", dependencies: ["MLXLMCommon"]),
        .testTarget(name: "MLXLMTests", dependencies: ["MLXLMCommon"], path: "lm/Tests/MLXLMTests"),
    ]
)
