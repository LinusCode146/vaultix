use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // The app icon is embedded at compile time; without these, changing only
    // the icon files leaves the old icon in the binary (and in the Dock).
    println!("cargo:rerun-if-changed=icons");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "macos" {
        build_swift();
    }
    tauri_build::build()
}

/// Compile swift/*.swift into a static library (CryptoKit's Secure Enclave
/// API, ScreenCaptureKit and Vision are Swift/Objective-C only) and link it, plus the Swift runtime that ships
/// with macOS.
fn build_swift() {
    println!("cargo:rerun-if-changed=swift/TouchID.swift");
    println!("cargo:rerun-if-changed=swift/System.swift");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        other => other,
    }
    .to_string();
    let lib = out.join("libvaultix_touchid.a");
    let status = Command::new("xcrun")
        .args(["swiftc", "-emit-library", "-static", "-parse-as-library", "-O", "-module-name", "VaultixTouchID"])
        .args(["-target", &format!("{arch}-apple-macos13.0")])
        .args(["swift/TouchID.swift", "swift/System.swift"])
        .arg("-o")
        .arg(&lib)
        .status()
        .expect("xcrun swiftc not found: install the Xcode command line tools (xcode-select --install)");
    assert!(status.success(), "compiling swift/TouchID.swift failed");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=vaultix_touchid");
    for framework in ["CryptoKit", "LocalAuthentication", "Security", "Foundation", "AppKit", "Vision", "ScreenCaptureKit", "CoreGraphics", "ImageIO"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    // The Swift runtime is part of macOS; the toolchain's copy is only needed to link.
    let toolchain = Command::new("xcrun").args(["--toolchain", "default", "--find", "swiftc"]).output().unwrap();
    let swiftc = PathBuf::from(String::from_utf8_lossy(&toolchain.stdout).trim().to_string());
    if let Some(usr) = swiftc.parent().and_then(|bin| bin.parent()) {
        println!("cargo:rustc-link-search=native={}", usr.join("lib/swift/macosx").display());
    }
    let sdk = Command::new("xcrun").args(["--sdk", "macosx", "--show-sdk-path"]).output().unwrap();
    let sdk = String::from_utf8_lossy(&sdk.stdout).trim().to_string();
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
