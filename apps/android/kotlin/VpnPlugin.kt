package io.github.veilwayproject.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
internal class StartArgs {
	lateinit var subscription: String
	lateinit var profile: String
	var options: String = "{}"
}

/** What the window may ask of Android: the VPN consent, starting and stopping the service, and the system's VPN settings. The tunnel itself is never here: the service and the engine run without this plugin or any window. */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
	override fun load(webView: WebView) {
		super.load(webView)
		Native.init(activity.filesDir.absolutePath)
	}

	/** The system's own consent dialog, the first time. A notification permission is asked for too (Android 13 and later); the service runs without it, the notification is just hidden. */
	@Command
	fun prepare(invoke: Invoke) {
		if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
			activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
		}
		val consent = VpnService.prepare(activity)
		if (consent == null) invoke.resolve(JSObject().put("granted", true)) else startActivityForResult(invoke, consent, "prepareResult")
	}

	@ActivityCallback
	fun prepareResult(invoke: Invoke, result: ActivityResult) {
		invoke.resolve(JSObject().put("granted", result.resultCode == Activity.RESULT_OK))
	}

	@Command
	fun start(invoke: Invoke) {
		val args = invoke.parseArgs(StartArgs::class.java)
		val intent = Intent(activity, VeilwayVpnService::class.java)
			.putExtra(VeilwayVpnService.EXTRA_SUBSCRIPTION, args.subscription)
			.putExtra(VeilwayVpnService.EXTRA_PROFILE, args.profile)
			.putExtra(VeilwayVpnService.EXTRA_OPTIONS, args.options)
		ContextCompat.startForegroundService(activity, intent)
		invoke.resolve()
	}

	@Command
	fun stop(invoke: Invoke) {
		if (VeilwayVpnService.instance == null) {
			// No service means no connection; the window still gets its "ended".
			Wanted(activity).wanted = false
			Thread { Native.disconnect() }.start()
		} else {
			activity.startService(Intent(activity, VeilwayVpnService::class.java).setAction(VeilwayVpnService.ACTION_STOP))
		}
		invoke.resolve()
	}

	/** Where Always-on VPN and "Block connections without VPN" are turned on. Android keeps them out of reach of an app on purpose. */
	@Command
	fun openVpnSettings(invoke: Invoke) {
		activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
		invoke.resolve()
	}
}
