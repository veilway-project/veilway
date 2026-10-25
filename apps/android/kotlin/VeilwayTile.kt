package io.github.veilwayproject.app

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** The quick settings tile: lit while the VPN service runs, a tap turns it off or connects the last connection again. */
class VeilwayTile : TileService() {
	override fun onStartListening() {
		super.onStartListening()
		draw()
	}

	override fun onClick() {
		super.onClick()
		// Android may refuse a start from the background (ForegroundServiceStartNotAllowedException is an IllegalStateException): the activity with no window then does it from the front.
		val done = try { Toggle.flip(this) } catch (e: IllegalStateException) { return open(ToggleActivity::class.java) }
		if (done) draw() else open(MainActivity::class.java)
	}

	/** Shows the state the service has now; it changes again when the service calls [Toggle.refresh]. */
	private fun draw() {
		val tile = qsTile ?: return
		val on = Toggle.on()
		tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
		if (Build.VERSION.SDK_INT >= 29) tile.subtitle = VeilwayVpnService.label(if (on) "On" else "Off", if (on) "روشن" else "خاموش")
		tile.updateTile()
	}

	/** From Android 14 an activity opens from a tile only through a PendingIntent. */
	@SuppressLint("StartActivityAndCollapseDeprecated")
	private fun open(target: Class<*>) {
		val intent = Intent(this, target).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
		if (Build.VERSION.SDK_INT >= 34) startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)) else @Suppress("DEPRECATION") startActivityAndCollapse(intent)
	}
}
