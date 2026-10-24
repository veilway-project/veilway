package io.github.veilwayproject.app

import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // The screens are the desktop window's and know nothing of status bars: the system bars, the cutout and the keyboard are padding of the content view, so nothing is drawn under them.
    ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { view, insets ->
      val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime())
      view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      WindowInsetsCompat.CONSUMED
    }
  }

  /** The web view keeps running in the background unless it is told: pausing it makes the page hidden (visibilitychange), and the screens stop their one second timers. */
  private fun webView(view: View): WebView? {
    if (view is WebView) return view
    if (view is ViewGroup) for (i in 0 until view.childCount) webView(view.getChildAt(i))?.let { return it }
    return null
  }

  override fun onStop() {
    super.onStop()
    webView(findViewById(android.R.id.content))?.onPause()
  }

  override fun onStart() {
    super.onStart()
    webView(findViewById(android.R.id.content))?.onResume()
  }
}
