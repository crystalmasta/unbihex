// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "tauri-plugin-unbihex-vpn",
    platforms: [
        .macOS(.v10_13),
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "tauri-plugin-unbihex-vpn",
            type: .static,
            targets: ["tauri-plugin-unbihex-vpn"])
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-unbihex-vpn",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources")
    ]
)
