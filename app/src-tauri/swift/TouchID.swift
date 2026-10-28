// Touch ID unlock, backed by the Secure Enclave. Linked into the app as a
// static library; the Rust side is src/touchid.rs.
//
// Enrolling creates a P-256 key inside the Secure Enclave that can only be
// used after a Touch ID match with the fingers enrolled right now
// (.biometryCurrentSet). Its private half never leaves the chip; what we store
// is an opaque blob only this Mac's Secure Enclave can load. The 32-byte
// unlock key is derived by ECDH between that key and a one-off software key
// whose private half is thrown away, so recomputing it needs the enclave key,
// and therefore a fingerprint.

import CryptoKit
import Foundation
import LocalAuthentication

private let salt = Data("vaultix/touch-id/v1".utf8)

private func deriveKey(_ secret: SharedSecret) -> SymmetricKey {
    secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32)
}

private func copy(_ key: SymmetricKey, to out: UnsafeMutablePointer<UInt8>) {
    key.withUnsafeBytes { bytes in
        for i in 0..<32 { out[i] = bytes[i] }
    }
}

/// Status codes shared with src/touchid.rs.
private enum Status: Int32 {
    case ok = 0
    case cancelled = 1
    case unavailable = 2
    case invalidated = 3
    case lockout = 4
    case failed = 5
    case bufferTooSmall = 6
}

@_cdecl("vx_touchid_available")
public func vxTouchIdAvailable() -> Bool {
    var error: NSError?
    return SecureEnclave.isAvailable
        && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
}

/// Create the enclave key. Writes its blob, the public half of the one-off
/// key (65 bytes, X9.63), and the derived 32-byte unlock key. No prompt.
@_cdecl("vx_touchid_enroll")
public func vxTouchIdEnroll(
    _ blobOut: UnsafeMutablePointer<UInt8>, _ blobCapacity: Int, _ blobLen: UnsafeMutablePointer<Int>,
    _ publicOut: UnsafeMutablePointer<UInt8>, _ keyOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard vxTouchIdAvailable() else { return Status.unavailable.rawValue }
    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &acError
    ) else { return Status.failed.rawValue }
    do {
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let blob = enclaveKey.dataRepresentation
        guard blob.count <= blobCapacity else { return Status.bufferTooSmall.rawValue }
        let oneOff = P256.KeyAgreement.PrivateKey()
        let secret = try oneOff.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        blob.copyBytes(to: blobOut, count: blob.count)
        blobLen.pointee = blob.count
        let publicKey = oneOff.publicKey.x963Representation
        publicKey.copyBytes(to: publicOut, count: 65)
        copy(deriveKey(secret), to: keyOut)
        return Status.ok.rawValue
    } catch {
        return Status.failed.rawValue
    }
}

/// Recompute the unlock key. Shows the Touch ID prompt with `reason`, and
/// blocks until the user responds, so never call it on the main thread.
@_cdecl("vx_touchid_derive")
public func vxTouchIdDerive(
    _ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ publicKey: UnsafePointer<UInt8>,
    _ reason: UnsafePointer<CChar>, _ keyOut: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    context.localizedFallbackTitle = "" // no "Enter Password": the master password is entered in Vaultix itself
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return derive(Data(bytes: blob, count: blobLen), Data(bytes: publicKey, count: 65), context, keyOut).rawValue
}

private func derive(_ blob: Data, _ publicKey: Data, _ context: LAContext, _ keyOut: UnsafeMutablePointer<UInt8>) -> Status {
    let enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
    } catch {
        // Fingerprints were added or removed (the key is gone), or the blob
        // isn't from this Mac's enclave.
        return .invalidated
    }
    do {
        let other = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        let secret = try enclaveKey.sharedSecretFromKeyAgreement(with: other)
        copy(deriveKey(secret), to: keyOut)
        return .ok
    } catch {
        return status(for: error)
    }
}

private func status(for error: Error) -> Status {
    if let error = error as? LAError {
        switch error.code {
        case .userCancel, .appCancel, .systemCancel, .userFallback, .notInteractive:
            return .cancelled
        case .biometryLockout:
            return .lockout
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet:
            return .unavailable
        case .invalidContext, .authenticationFailed:
            return .cancelled
        default:
            return .failed
        }
    }
    // CryptoKit wraps Security errors; a cancelled prompt surfaces as
    // errSecUserCanceled (-128) or errSecAuthFailed (-25293).
    let ns = error as NSError
    if ns.code == -128 || ns.code == Int(errSecUserCanceled) { return .cancelled }
    if ns.code == Int(errSecAuthFailed) { return .cancelled }
    if let inner = ns.userInfo[NSUnderlyingErrorKey] as? NSError, inner.domain == LAErrorDomain {
        return inner.code == LAError.biometryLockout.rawValue ? .lockout : .cancelled
    }
    return .failed
}
