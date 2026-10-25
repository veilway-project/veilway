package io.github.veilwayproject.app

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat

/** The one switch behind the quick settings tile and the home screen shortcut: off while the service runs, else on with the last connection the window made. It never asks for anything, so with no connection made yet or the VPN permission gone it opens the window instead. */
object Toggle {
	fun on() = VeilwayVpnService.instance != null

	/** False when the window has to do it. A start that Android refuses from the background throws, and the caller then goes through [ToggleActivity]. */
	fun flip(context: Context): Boolean {
		if (on()) {
			context.startService(Intent(context, VeilwayVpnService::class.java).setAction(VeilwayVpnService.ACTION_STOP))
			return true
		}
		val wanted = Wanted(context)
		if (!wanted.known() || VpnService.prepare(context) != null) return false
		wanted.wanted = true
		ContextCompat.startForegroundService(context, Intent(context, VeilwayVpnService::class.java))
		return true
	}

	/** Asks the system to redraw the tile, after the service started or ended. */
	fun refresh(context: Context) = TileService.requestListeningState(context, ComponentName(context, VeilwayTile::class.java))
}

/** The home screen shortcut's target, and the tile's way around a refused background start: an activity with no window of its own, so the app is in front for the moment the start needs. */
class ToggleActivity : Activity() {
	override fun onCreate(savedInstanceState: Bundle?) {
		super.onCreate(savedInstanceState)
		if (!Toggle.flip(this)) startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
		finish()
	}
}
