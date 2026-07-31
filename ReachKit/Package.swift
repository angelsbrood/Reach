// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "ReachKit",
    platforms: [
        .iOS("27.0"),
        .macOS("27.0"),
        .visionOS("27.0"),
    ],
    products: [
        .library(name: "ReachWire", targets: ["ReachWire"]),
        .library(name: "ReachTransport", targets: ["ReachTransport"]),
        .library(name: "ReachIdentity", targets: ["ReachIdentity"]),
        .library(name: "ReachKit", targets: ["ReachKit"]),
    ],
    targets: [
        // The wire codec: versioned envelope frames carrying the framework's
        // transcript and generation types across the trust boundary.
        .target(name: "ReachWire"),

        // QUIC with mutual TLS, Bonjour advertise/browse, stream framing.
        .target(name: "ReachTransport", dependencies: ["ReachWire"]),

        // Device and app identities: keys, keychain, certificate pinning.
        .target(name: "ReachIdentity"),

        // The conforming model provider apps link.
        .target(
            name: "ReachKit",
            dependencies: ["ReachWire", "ReachTransport", "ReachIdentity"]
        ),

        .testTarget(name: "ReachWireTests", dependencies: ["ReachWire"]),
        .testTarget(name: "ReachTransportTests", dependencies: ["ReachTransport", "ReachIdentity", "ReachWire"]),
        .testTarget(name: "ReachKitTests", dependencies: ["ReachKit"]),
    ]
)
