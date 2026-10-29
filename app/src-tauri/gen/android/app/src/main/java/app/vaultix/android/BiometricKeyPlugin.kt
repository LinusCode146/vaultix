package app.vaultix.android

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class SealArgs {
  lateinit var data: String
  var reason: String = "Unlock Vaultix"
}

@InvokeArg
class OpenArgs {
  lateinit var sealed: String
  var reason: String = "Unlock Vaultix"
}

/**
 * Fingerprint or face unlock (see src/touchid/android.rs): seals and opens
 * the unlock key with an AES key in the Android Keystore that only works
 * right after a strong biometric match, and is destroyed when fingerprints or
 * faces are added. Rejects with the codes the UI uses (touch-id-cancelled, …).
 */
@TauriPlugin
class BiometricKeyPlugin(private val activity: Activity) : Plugin(activity) {
  private val alias = "vaultix-unlock"
  private val ivLength = 12

  @Command
  fun status(invoke: Invoke) {
    val result = JSObject()
    result.put("available", canAuthenticate())
    invoke.resolve(result)
  }

  /** A new Keystore key, then encrypt `data` with it after a biometric match. */
  @Command
  fun seal(invoke: Invoke) {
    val args = invoke.parseArgs(SealArgs::class.java)
    if (!canAuthenticate()) return invoke.reject("touch-id-unavailable")
    val cipher = try {
      Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, newKey()) }
    } catch (e: Exception) {
      return invoke.reject("touch-id-failed: ${e.message}")
    }
    prompt(invoke, cipher, args.reason, "Turn on") { c ->
      val sealed = c.iv + c.doFinal(Base64.decode(args.data, Base64.NO_WRAP))
      Base64.encodeToString(sealed, Base64.NO_WRAP)
    }
  }

  @Command
  fun open(invoke: Invoke) {
    val args = invoke.parseArgs(OpenArgs::class.java)
    val sealed = Base64.decode(args.sealed, Base64.NO_WRAP)
    if (sealed.size <= ivLength) return invoke.reject("touch-id-failed: bad blob")
    val key = existingKey() ?: return invoke.reject("touch-id-invalidated")
    val cipher = try {
      Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed, 0, ivLength))
      }
    } catch (e: KeyPermanentlyInvalidatedException) {
      deleteKey()
      return invoke.reject("touch-id-invalidated")
    } catch (e: Exception) {
      return invoke.reject("touch-id-failed: ${e.message}")
    }
    prompt(invoke, cipher, args.reason, "Use password") { c ->
      Base64.encodeToString(c.doFinal(sealed, ivLength, sealed.size - ivLength), Base64.NO_WRAP)
    }
  }

  private fun canAuthenticate(): Boolean =
    BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

  private fun prompt(invoke: Invoke, cipher: Cipher, reason: String, negative: String, use: (Cipher) -> String) {
    activity.runOnUiThread {
      val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          val c = result.cryptoObject?.cipher ?: return invoke.reject("touch-id-failed: no cipher")
          try {
            val out = JSObject()
            out.put("data", use(c))
            invoke.resolve(out)
          } catch (e: Exception) {
            invoke.reject("touch-id-failed: ${e.message}")
          }
        }

        override fun onAuthenticationError(code: Int, message: CharSequence) {
          when (code) {
            BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED ->
              invoke.reject("touch-id-cancelled")
            BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> invoke.reject("touch-id-lockout")
            BiometricPrompt.ERROR_NO_BIOMETRICS, BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE ->
              invoke.reject("touch-id-unavailable")
            else -> invoke.reject("touch-id-failed: $message")
          }
        }
      }
      val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Vaultix")
        .setSubtitle(reason)
        .setNegativeButtonText(negative)
        .setAllowedAuthenticators(BIOMETRIC_STRONG)
        .build()
      BiometricPrompt(activity as FragmentActivity, ContextCompat.getMainExecutor(activity), callback)
        .authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
  }

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

  private fun existingKey(): SecretKey? = keyStore().getKey(alias, null) as SecretKey?

  private fun deleteKey() {
    keyStore().deleteEntry(alias)
  }

  private fun newKey(): SecretKey {
    deleteKey()
    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .apply {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
      }
      .build()
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
      init(spec)
      generateKey()
    }
  }
}
