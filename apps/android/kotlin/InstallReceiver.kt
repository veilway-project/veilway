package io.github.veilwayproject.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

/** Hears from the system's installer about the update session. When the installer needs the user's yes it hands over its own confirmation screen, which is opened here. Not exported: only the PendingIntent given to that session reaches it. */
class InstallReceiver : BroadcastReceiver() {
	override fun onReceive(context: Context, intent: Intent) {
		if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -1) != PackageInstaller.STATUS_PENDING_USER_ACTION) return
		@Suppress("DEPRECATION")
		val confirm = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) else intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
		if (confirm != null) context.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
	}
}
