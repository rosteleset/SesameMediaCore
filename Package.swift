// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SesameMediaCore",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "SesameMediaCore", targets: ["SesameMediaCore"]),
    ],
    targets: [
        .binaryTarget(
            name: "SesameMediaCore",
            path: "apple/SesameMediaCore.xcframework"
        ),
    ]
)
