package io.github.veilwayproject.app

import android.content.Context

/** The last connection the user asked for, kept so that the system's always-on start, a restart of the service and a reboot can bring it back without the window. It holds ids and options only, never a key. */
class Wanted(context: Context) {
	private val prefs = context.getSharedPreferences("veilway-vpn", Context.MODE_PRIVATE)

	val subscription: String?
		get() = prefs.getString("subscription", null)

	val profile: String?
		get() = prefs.getString("profile", null)

	val options: String
		get() = prefs.getString("options", "{}") ?: "{}"

	/** True from the user's connect until the user's disconnect: what a reboot or a restart of the service brings back. */
	var wanted: Boolean
		get() = prefs.getBoolean("wanted", false)
		set(value) { prefs.edit().putBoolean("wanted", value).apply() }

	fun remember(subscription: String, profile: String, options: String) {
		prefs.edit().putString("subscription", subscription).putString("profile", profile).putString("options", options).putBoolean("wanted", true).apply()
	}

	fun known() = subscription != null && profile != null
}
