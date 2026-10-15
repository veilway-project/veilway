package io.github.veilwayproject.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat

/** Brings the connection back after a reboot or an app update, when the user had it on and the VPN permission is still there. Without the permission nothing starts: it cannot be asked for without a window. */
class BootReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
		if (!Wanted(context).wanted || VpnService.prepare(context) != null) return
		ContextCompat.startForegroundService(context, Intent(context, VeilwayVpnService::class.java))
	}
}
