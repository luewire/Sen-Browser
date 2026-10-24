// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Search",
    platforms: [.macOS(.v14)],
    targets: [
        .target(
            name: "CAdblock",
            path: "Sources/CAdblock",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "Search",
            dependencies: ["CAdblock"],
            path: "Sources/Search",
            resources: [
                .process("Resources")
            ],
            // Same reasoning as the canvas app next door: the whole interface is
            // main-thread by nature, and Swift 6's strict isolation buys nothing
            // here but ceremony.
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [
                .unsafeFlags([
                    "-Lcrates/adblock_engine/target/release",
                    "-ladblock_engine"
                ])
            ]
        ),
        .testTarget(
            name: "SearchTests",
            dependencies: ["Search"],
            path: "Tests/SearchTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)
