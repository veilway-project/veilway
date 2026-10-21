package io.github.veilwayproject.app

import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log

/** Hears from the system's installer about the update session. When the installer needs the user's yes it hands over its own confirmation screen: it is opened here while Veilway is on screen (Android lets an app with a visible window start a screen), and otherwise offered as a notification on its own channel, since the VPN's channel is silent. A failed install is logged and shown, so a refused update does not look like nothing happened. Not exported: only the PendingIntent given to that session reaches it. */
class InstallReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1)
		val manager = context.getSystemService(NotificationManager::class.java)
		manager.createNotificationChannel(NotificationChannel(CHANNEL, VeilwayVpnService.label("Veilway updates", "به‌روزرسانی وی‌ال‌وی"), NotificationManager.IMPORTANCE_HIGH))
		if (status == PackageInstaller.STATUS_SUCCESS) return
		if (status != PackageInstaller.STATUS_PENDING_USER_ACTION) {
			val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "status $status"
			Log.w("veilway", "update install failed: $message")
			manager.notify(VeilwayVpnService.UPDATE_NOTICE, Notification.Builder(context, CHANNEL).setSmallIcon(android.R.drawable.stat_notify_error).setContentTitle(VeilwayVpnService.label("Veilway update failed", "به‌روزرسانی وی‌ال‌وی نصب نشد")).setContentText(message).setStyle(Notification.BigTextStyle().bigText(message)).setAutoCancel(true).build())
			return
		}
		@Suppress("DEPRECATION")
		val confirm = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) else intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
		if (confirm == null) return
		confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
		val state = ActivityManager.RunningAppProcessInfo().also { ActivityManager.getMyMemoryState(it) }
		if (Build.VERSION.SDK_INT < 29 || state.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
			try { context.startActivity(confirm); return } catch (error: Exception) { Log.w("veilway", "update prompt could not open: ${error.message}") }
		}
		val open = PendingIntent.getActivity(context, 0, confirm, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
		manager.notify(VeilwayVpnService.UPDATE_NOTICE, Notification.Builder(context, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_download_done).setContentTitle(VeilwayVpnService.label("Veilway update ready", "به‌روزرسانی وی‌ال‌وی آماده است")).setContentText(VeilwayVpnService.label("Tap to install", "برای نصب ضربه بزنید")).setContentIntent(open).setAutoCancel(true).build())
	}

	companion object {
		private const val CHANNEL = "update"
	}
}
