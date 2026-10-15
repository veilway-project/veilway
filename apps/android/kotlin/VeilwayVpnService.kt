package io.github.veilwayproject.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import java.net.Inet6Address
import java.util.Locale
import java.util.concurrent.Executors

/**
 * Owns the VPN interface and the foreground notification. The engine runs in this process (Rust, through [Native]); this service only builds the interface when the engine asks ([establish]), keeps the engine's sockets out of it ([protect]) and tells the engine which networks the phone is on.
 *
 * Started three ways, all ending in [Native.connect] with the last connection the user asked for ([Wanted]): by the window (extras), by the system's always-on VPN setting (the VpnService action, no extras, no window), and by [BootReceiver] or a restart after the process was killed (no extras, only when the user left the connection on).
 */
class VeilwayVpnService : VpnService() {
	companion object {
		const val ACTION_STOP = "io.github.veilwayproject.app.STOP"
		const val EXTRA_SUBSCRIPTION = "subscription"
		const val EXTRA_PROFILE = "profile"
		const val EXTRA_OPTIONS = "options"
		private const val CHANNEL = "vpn"
		private const val ONGOING = 1
		private const val FAILED = 2

		@Volatile var instance: VeilwayVpnService? = null
	}

	private val worker = Executors.newSingleThreadExecutor()
	private val networks = LinkedHashMap<Network, LinkProperties>()
	private var callback: ConnectivityManager.NetworkCallback? = null
	private var state = "connecting"
	private var finished = false

	override fun onCreate() {
		super.onCreate()
		instance = this
		Native.init(filesDir.absolutePath)
		getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(CHANNEL, label("Veilway VPN", "وی‌ال‌وی"), NotificationManager.IMPORTANCE_LOW))
	}

	override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
		val wanted = Wanted(this)
		if (intent?.action == ACTION_STOP) {
			wanted.wanted = false
			startForegroundNow()
			worker.execute { Native.disconnect(); finish(null) }
			return START_NOT_STICKY
		}
		val fromWindow = intent?.hasExtra(EXTRA_SUBSCRIPTION) == true
		// The system's always-on start names the VpnService action and carries nothing; a restart or the boot receiver carries nothing either, and only counts if the user left the connection on.
		val fromSystem = intent?.action == SERVICE_INTERFACE
		if (fromWindow) wanted.remember(intent!!.getStringExtra(EXTRA_SUBSCRIPTION)!!, intent.getStringExtra(EXTRA_PROFILE)!!, intent.getStringExtra(EXTRA_OPTIONS) ?: "{}")
		startForegroundNow()
		if (!wanted.known() || !(fromWindow || fromSystem || wanted.wanted)) {
			finish(null)
			return START_NOT_STICKY
		}
		finished = false
		watchNetworks()
		val (subscription, profile, options) = Triple(wanted.subscription!!, wanted.profile!!, wanted.options)
		worker.execute {
			val error = Native.connect(subscription, profile, options)
			if (error != null) finish(error)
		}
		return START_STICKY
	}

	/** Builds the interface for the engine and hands over its descriptor. Returns -1 when the system refuses. */
	fun establish(addresses: Array<String>, dns: Array<String>, routes: Array<String>, mtu: Int): Int {
		val builder = Builder().setSession("Veilway").setMtu(mtu).setBlocking(false)
		fun split(item: String) = item.substringBeforeLast('/') to item.substringAfterLast('/').toInt()
		addresses.forEach { val (ip, prefix) = split(it); builder.addAddress(ip, prefix) }
		dns.forEach { builder.addDnsServer(it) }
		routes.forEach { val (ip, prefix) = split(it); builder.addRoute(ip, prefix) }
		if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
		best()?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
		return try {
			builder.establish()?.detachFd() ?: -1
		} catch (e: Exception) { -1 }
	}

	fun show(newState: String) {
		state = newState
		getSystemService(NotificationManager::class.java).notify(ONGOING, ongoing())
	}

	/** The engine's connection ended (or the user asked it to): the service goes, and says why when it was not the user. */
	@Synchronized fun finish(error: String?) {
		if (finished) return
		finished = true
		unwatchNetworks()
		stopForeground(STOP_FOREGROUND_REMOVE)
		if (error != null) {
			Wanted(this).wanted = false
			getSystemService(NotificationManager::class.java).notify(FAILED, notification(label("Veilway disconnected", "اتصال وی‌ال‌وی قطع شد"), error, false))
		}
		stopSelf()
	}

	/** The user turned the VPN off in the system's settings, or another VPN app took over. */
	override fun onRevoke() {
		Wanted(this).wanted = false
		worker.execute { Native.disconnect(); finish(null) }
	}

	override fun onDestroy() {
		unwatchNetworks()
		instance = null
		worker.shutdown()
		super.onDestroy()
	}

	private fun label(english: String, persian: String) = if (Locale.getDefault().language == "fa") persian else english

	private fun ongoing(): Notification {
		val text = when (state) {
			"connected" -> label("Connected", "متصل است")
			"reconnecting" -> label("Reconnecting", "در حال اتصال دوباره")
			else -> label("Connecting", "در حال اتصال")
		}
		return notification("Veilway", text, true)
	}

	private fun notification(title: String, text: String, ongoing: Boolean): Notification {
		val open = packageManager.getLaunchIntentForPackage(packageName)?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE) }
		val builder = Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle(title).setContentText(text).setContentIntent(open).setOngoing(ongoing)
		if (ongoing) {
			val stop = PendingIntent.getService(this, 1, Intent(this, VeilwayVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
			builder.addAction(Notification.Action.Builder(null, label("Disconnect", "قطع اتصال"), stop).build())
		}
		return builder.build()
	}

	private fun startForegroundNow() {
		if (Build.VERSION.SDK_INT >= 34) startForeground(ONGOING, ongoing(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED) else startForeground(ONGOING, ongoing())
	}

	/** Prefers wifi and ethernet over mobile data, and the newest of equals. */
	private fun best(): Network? {
		val manager = getSystemService(ConnectivityManager::class.java)
		fun rank(network: Network): Int {
			val caps = manager.getNetworkCapabilities(network) ?: return 0
			return if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) 2 else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) 1 else 0
		}
		return synchronized(networks) { networks.keys.withIndex().maxWithOrNull(compareBy({ rank(it.value) }, { it.index }))?.value }
	}

	/** Tells the engine which networks the phone is on, and the system which one carries the VPN, so that the engine reconnects when the phone moves from wifi to mobile data and back. */
	private fun update() {
		val network = best()
		val properties = synchronized(networks) { network?.let { networks[it] } }
		val found = ArrayList<String>()
		var description = "android:none"
		if (properties != null) {
			properties.linkAddresses.forEach { val ip = it.address; if (!ip.isLinkLocalAddress && !ip.isLoopbackAddress) found.add("${ip.hostAddress?.substringBefore('%')}/${it.prefixLength}") }
			val gateway = properties.routes.firstOrNull { it.isDefaultRoute && it.gateway != null }?.gateway
			if (gateway != null) found.add("${gateway.hostAddress?.substringBefore('%')}/${if (gateway is Inet6Address) 128 else 32}")
			description = "android:${properties.interfaceName}:${gateway?.hostAddress ?: "?"}"
		}
		try { setUnderlyingNetworks(network?.let { arrayOf(it) }) } catch (e: Exception) { }
		Native.networkChanged(description, found.toTypedArray())
	}

	private fun watchNetworks() {
		if (callback != null) return
		val manager = getSystemService(ConnectivityManager::class.java)
		val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
		val watcher = object : ConnectivityManager.NetworkCallback() {
			override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) { synchronized(networks) { networks.remove(network); networks[network] = properties }; update() }
			override fun onLost(network: Network) { synchronized(networks) { networks.remove(network) }; update() }
		}
		callback = watcher
		manager.registerNetworkCallback(request, watcher)
	}

	private fun unwatchNetworks() {
		val watcher = callback ?: return
		callback = null
		try { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(watcher) } catch (e: Exception) { }
		synchronized(networks) { networks.clear() }
	}
}
