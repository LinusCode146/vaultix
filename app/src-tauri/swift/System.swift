// macOS events and services the Rust side can't reach directly. Linked into
// the app with TouchID.swift; the Rust side is src/system/macos.rs.

import AppKit
import Foundation
import ImageIO
import ScreenCaptureKit
import Security
import Vision

/// Why the Mac is going away; the codes are shared with src/system/macos.rs.
private enum Away: Int32 {
    case sleep = 1
    case screensSleep = 2
    case sessionSwitched = 3
    case screenLocked = 4
}

public typealias AwayCallback = @convention(c) (Int32) -> Void

private var observers: [NSObjectProtocol] = []

/// Call `callback` (on the main thread) when the Mac sleeps, its displays
/// sleep, the screen locks, or another user takes over the session.
@_cdecl("vx_watch_away")
public func vxWatchAway(_ callback: AwayCallback) {
    let workspace = NSWorkspace.shared.notificationCenter
    let events: [(Notification.Name, Away)] = [
        (NSWorkspace.willSleepNotification, .sleep),
        (NSWorkspace.screensDidSleepNotification, .screensSleep),
        (NSWorkspace.sessionDidResignActiveNotification, .sessionSwitched),
    ]
    for (name, away) in events {
        observers.append(workspace.addObserver(forName: name, object: nil, queue: .main) { _ in callback(away.rawValue) })
    }
    // Not in any public header, but posted by loginwindow for every screen
    // lock (⌃⌘Q, hot corners, the lid of a Mac with "require password").
    let locked = Notification.Name("com.apple.screenIsLocked")
    observers.append(DistributedNotificationCenter.default().addObserver(forName: locked, object: nil, queue: .main) { _ in
        callback(Away.screenLocked.rawValue)
    })
}

/// Move a file to the Trash (not a permanent delete). 0 on success.
@_cdecl("vx_trash")
public func vxTrash(_ path: UnsafePointer<CChar>) -> Int32 {
    let url = URL(fileURLWithPath: String(cString: path))
    do {
        try FileManager.default.trashItem(at: url, resultingItemURL: nil)
        return 0
    } catch {
        return 1
    }
}

// ---------- QR codes ----------

/// Status codes shared with src/system.rs.
private enum Scan: Int32 {
    case ok = 0
    case noCode = 1
    case noPermission = 2
    case notOneTimePassword = 3
    case migration = 4
    case failed = 5
    case bufferTooSmall = 6
}

private func payloads(in image: CGImage) -> [String] {
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    try? VNImageRequestHandler(cgImage: image, options: [:]).perform([request])
    return (request.results ?? []).compactMap { $0.payloadStringValue }
}

/// The first `otpauth://` code among `images`, written to `out` as UTF-8 with a trailing NUL.
private func pick(_ images: [CGImage], _ out: UnsafeMutablePointer<CChar>, _ cap: Int) -> Int32 {
    let found = images.flatMap(payloads)
    guard let uri = found.first(where: { $0.lowercased().hasPrefix("otpauth://") }) else {
        if found.contains(where: { $0.lowercased().hasPrefix("otpauth-migration://") }) { return Scan.migration.rawValue }
        return (found.isEmpty ? Scan.noCode : Scan.notOneTimePassword).rawValue
    }
    let bytes = Array(uri.utf8CString)
    guard bytes.count <= cap else { return Scan.bufferTooSmall.rawValue }
    for (i, b) in bytes.enumerated() { out[i] = b }
    return Scan.ok.rawValue
}

private final class Shots: @unchecked Sendable {
    var images: [CGImage] = []
    var failed = false
}

/// Look for a two-factor QR code on every display, leaving out Vaultix's own
/// windows. Needs Screen Recording permission: the first call asks for it.
@_cdecl("vx_scan_screen_qr")
public func vxScanScreenQr(_ out: UnsafeMutablePointer<CChar>, _ cap: Int) -> Int32 {
    guard CGPreflightScreenCaptureAccess() else {
        CGRequestScreenCaptureAccess()
        return Scan.noPermission.rawValue
    }
    guard #available(macOS 14.0, *) else { return Scan.failed.rawValue }
    let shots = Shots()
    let done = DispatchSemaphore(value: 0)
    Task {
        do {
            let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
            let mine = content.applications.filter { $0.processID == ProcessInfo.processInfo.processIdentifier }
            for display in content.displays {
                let filter = SCContentFilter(display: display, excludingApplications: mine, exceptingWindows: [])
                let config = SCStreamConfiguration()
                config.width = Int(Float(display.width) * filter.pointPixelScale)
                config.height = Int(Float(display.height) * filter.pointPixelScale)
                config.showsCursor = false
                shots.images.append(try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config))
            }
        } catch {
            shots.failed = true
        }
        done.signal()
    }
    done.wait()
    if shots.failed && shots.images.isEmpty { return Scan.failed.rawValue }
    return pick(shots.images, out, cap)
}

/// Look for a two-factor QR code in an image file's contents (PNG, JPEG, …).
@_cdecl("vx_scan_image_qr")
public func vxScanImageQr(_ data: UnsafePointer<UInt8>, _ len: Int, _ out: UnsafeMutablePointer<CChar>, _ cap: Int) -> Int32 {
    let bytes = Data(bytes: data, count: len) as CFData
    guard let source = CGImageSourceCreateWithData(bytes, nil),
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
    else { return Scan.failed.rawValue }
    return pick([image], out, cap)
}

// ---------- Code signatures ----------

/// Status codes shared with src/system.rs.
private enum Signature: Int32 {
    case valid = 0
    case requirementNotMet = 1
    case unknown = 2
    /// The app was updated on disk while running; it must be restarted.
    case changedOnDisk = 3
}

/// Check a running process's code signature against a code requirement
/// (e.g. `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`).
/// The process is given by its audit token (`token`, 32 bytes) when known,
/// which can't be confused with a later process reusing the same pid.
@_cdecl("vx_check_code")
public func vxCheckCode(_ pid: Int32, _ token: UnsafePointer<UInt8>?, _ tokenLen: Int, _ requirement: UnsafePointer<CChar>) -> Int32 {
    var attributes: [CFString: Any] = [:]
    if let token {
        attributes[kSecGuestAttributeAudit] = Data(bytes: token, count: tokenLen)
    } else {
        attributes[kSecGuestAttributePid] = pid
    }
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess, let code else {
        return Signature.unknown.rawValue
    }
    var req: SecRequirement?
    guard SecRequirementCreateWithString(String(cString: requirement) as CFString, [], &req) == errSecSuccess, let req else {
        return Signature.unknown.rawValue
    }
    switch SecCodeCheckValidity(code, [], req) {
    case errSecSuccess: return Signature.valid.rawValue
    case errSecCSStaticCodeChanged: return Signature.changedOnDisk.rawValue
    case errSecCSReqFailed: return Signature.requirementNotMet.rawValue
    default: return Signature.requirementNotMet.rawValue
    }
}

/// The Apple team this app is signed by, or an empty string for a development
/// build (unsigned or ad-hoc signed).
@_cdecl("vx_own_team_id")
public func vxOwnTeamId(_ out: UnsafeMutablePointer<CChar>, _ cap: Int) {
    out[0] = 0
    var code: SecCode?
    var staticCode: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
          SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
          SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let team = (info as? [CFString: Any])?[kSecCodeInfoTeamIdentifier] as? String
    else { return }
    let bytes = Array(team.utf8CString)
    guard bytes.count <= cap else { return }
    for (i, b) in bytes.enumerated() { out[i] = b }
}
