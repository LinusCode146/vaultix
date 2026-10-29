package app.vaultix.android

import android.content.Context
import android.net.wifi.WifiManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  private var multicast: WifiManager.MulticastLock? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    // No screenshots or screen recording of passwords, and a blank preview in recent apps.
    // (Debug builds allow them, for testing the UI.)
    if (!BuildConfig.DEBUG) {
      window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    }
    super.onCreate(savedInstanceState)
    // Keep the page clear of the status bar, the gesture bar and the keyboard.
    ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { view, insets ->
      val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime())
      view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      WindowInsetsCompat.CONSUMED
    }
  }

  // Android drops multicast packets unless an app asks for them; finding the
  // computer on the network (mDNS) needs them while the app is open.
  override fun onResume() {
    super.onResume()
    val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    multicast = wifi.createMulticastLock("vaultix-mdns").apply {
      setReferenceCounted(false)
      acquire()
    }
  }

  override fun onPause() {
    multicast?.release()
    multicast = null
    super.onPause()
  }
}
