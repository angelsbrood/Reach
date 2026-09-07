// swift-tools-version: 6.1
// run.py supplies the byte-exact, local WireEvent.swift in private scratch.
import PackageDescription
let package = Package(name: "DurableClientReceiptsCandidate", platforms: [.macOS(.v14)],
    products: [.executable(name: "ClientReceiptWorker", targets: ["ClientReceiptWorker"])],
    targets: [
        .target(name: "ReachWire"),
        .target(name: "DurableClientReceipts", dependencies: ["ReachWire"]),
        .target(name: "ClientReceiptFixtures", dependencies: ["DurableClientReceipts", "ReachWire"]),
        .executableTarget(name: "ClientReceiptWorker", dependencies: ["ClientReceiptFixtures", "DurableClientReceipts"]),
        .testTarget(name: "DurableClientReceiptsTests", dependencies: ["ClientReceiptFixtures", "DurableClientReceipts", "ReachWire"]),
    ], swiftLanguageModes: [.v5])
