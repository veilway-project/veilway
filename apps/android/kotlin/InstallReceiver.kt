package io.github.veilwayproject.app

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

/** Hears from the system's installer about the update session. When the installer needs the user's yes it hands over its own confirmation screen: it is opened here, or from Android 10 on, where a receiver may not start a screen, offered as a notification. Not exported: only the PendingIntent given to that session reaches it. */
class InstallReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1) != PackageInstaller.STATUS_PENDING_USER_ACTION) return
		@Suppress("DEPRECATION")
		val confirm = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) else intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
		if (confirm == null) return
		confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
		if (Build.VERSION.SDK_INT < 29) {
			context.startActivity(confirm)
			return
		}
		VeilwayVpnService.ensureChannel(context)
		val open = PendingIntent.getActivity(context, 0, confirm, PendingIntent.FLAG_IMMUTABLE)
		val notice = Notification.Builder(context, VeilwayVpnService.CHANNEL).setSmallIcon(android.R.drawable.stat_sys_download_done).setContentTitle(VeilwayVpnService.label("Veilway update ready", "به‌روزرسانی وی‌ال‌وی آماده است")).setContentText(VeilwayVpnService.label("Tap to install", "برای نصب ضربه بزنید")).setContentIntent(open).setAutoCancel(true).build()
		context.getSystemService(NotificationManager::class.java).notify(VeilwayVpnService.UPDATE_NOTICE, notice)
	}
}
