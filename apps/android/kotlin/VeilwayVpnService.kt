package io.github.veilwayproject.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.BroadcastReceiver
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
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
		internal const val CHANNEL = "vpn"
		internal const val UPDATE_NOTICE = 3
		private const val ONGOING = 1
		private const val FAILED = 2
		private const val RETRIES = 4

		@Volatile var instance: VeilwayVpnService? = null

		/** Also called by the install receiver, because the update notice can come before the service has ever run. */
		fun ensureChannel(context: Context) {
			context.getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(CHANNEL, label("Veilway VPN", "وی‌ال‌وی"), NotificationManager.IMPORTANCE_LOW))
		}

		internal fun label(english: String, persian: String) = if (Locale.getDefault().language == "fa") persian else english
	}

	private val worker = Executors.newSingleThreadExecutor()
	/** The default network the system reports, the one the phone's packets leave by (the service's own sockets are kept out of the VPN). */
	@Volatile private var underlying: Pair<Network, LinkProperties>? = null
	private var callback: ConnectivityManager.NetworkCallback? = null
	private var idleWatcher: BroadcastReceiver? = null
	/** What the ongoing notification says now, so that a status that changes only counters does not post it again. */
	private var shown = ""
	private var state = "connecting"
	private var finished = false
	/** The connection has no VPN interface: only programs set to use the local proxy go through it, and the phone's other traffic is not blocked. */
	@Volatile var proxyOnly = false
	private var retries = 0
	/** The VPN interface as the system holds it for this service. It stays up while the engine reconnects and after it gave up, so that the phone's traffic is dropped and does not leave outside the VPN, until [finish] ends the service. */
	private var held: ParcelFileDescriptor? = null

	override fun onCreate() {
		super.onCreate()
		instance = this
		Native.init(filesDir.absolutePath)
		ensureChannel(this)
		Toggle.refresh(this)
	}

	override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
		val wanted = Wanted(this)
		Native.lockdown(Build.VERSION.SDK_INT >= 29 && isLockdownEnabled)
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
		// A start while a session runs asks for the same connection again; the engine answers yes to that, and refuses another one.
		val resumed = callback != null
		finished = false
		if (fromWindow) retries = 0
		watchNetworks()
		watchIdle()
		start(resumed, 0)
		return START_STICKY
	}

	/** Builds the interface for the engine and hands over a copy of its descriptor, keeping the interface itself in [held]. Returns -1 when the system refuses, and then the interface that was up stays. */
	@Synchronized fun establish(addresses: Array<String>, dns: Array<String>, routes: Array<String>, mtu: Int): Int {
		val builder = Builder().setSession("Veilway").setMtu(mtu).setBlocking(false)
		fun split(item: String) = item.substringBeforeLast('/') to item.substringAfterLast('/').toInt()
		addresses.forEach { val (ip, prefix) = split(it); builder.addAddress(ip, prefix) }
		dns.forEach { builder.addDnsServer(it) }
		routes.forEach { val (ip, prefix) = split(it); builder.addRoute(ip, prefix) }
		underlying?.first?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
		return try {
			val fresh = builder.establish() ?: return -1
			val copy = fresh.dup()
			held?.close()
			held = fresh
			copy.detachFd()
		} catch (e: Exception) { -1 }
	}

	@Synchronized fun show(newState: String) {
		state = newState
		if (newState == "connected") retries = 0
		if (shown == "$proxyOnly $newState") return
		shown = "$proxyOnly $newState"
		getSystemService(NotificationManager::class.java).notify(ONGOING, ongoing())
	}

	/**
	 * The engine's connection ended (or the user asked it to): the service goes, and says why when it was not the user. A connection that ended on its own is started again, a few times with a longer pause each time, while the user still wants it.
	 * While that goes on, and after the last try, the interface stays up and drops the phone's traffic: the service ends, and the interface with it, only when the user disconnects.
	 */
	@Synchronized fun finish(error: String?) {
		if (finished) return
		val wanted = Wanted(this)
		if (error != null && wanted.wanted && retries < RETRIES) {
			retries += 1
			show("blocked")
			start(false, 1000L shl retries)
			return
		}
		if (error != null && held != null) {
			wanted.wanted = false
			show("stopped")
			alert(error)
			return
		}
		finished = true
		held?.close()
		held = null
		unwatchNetworks()
		unwatchIdle()
		stopForeground(STOP_FOREGROUND_REMOVE)
		if (error != null) {
			wanted.wanted = false
			alert(error)
		}
		stopSelf()
	}

	/** Starts the wanted connection on the worker, after a pause that a stop cuts short. A refusal from the engine is final; a failure to open the storage is not. */
	private fun start(resumed: Boolean, pause: Long) {
		worker.execute {
			val end = System.currentTimeMillis() + pause
			while (Wanted(this).wanted && System.currentTimeMillis() < end) Thread.sleep(100)
			val wanted = Wanted(this)
			if (!wanted.wanted) return@execute finish(null)
			if (!open()) return@execute finish("Veilway could not open its storage. Try again.")
			val error = Native.connect(wanted.subscription!!, wanted.profile!!, wanted.options) ?: return@execute
			if (resumed) return@execute alert(error)
			wanted.wanted = false
			finish(error)
		}
	}

	/** The engine's storage opens once the Keystore answers, so a failed try is repeated a few times with a growing pause. */
	private fun open(): Boolean {
		for (attempt in 0 until 4) {
			if (Native.init(filesDir.absolutePath)) return true
			Thread.sleep(500L shl attempt)
		}
		return false
	}

	/** A failure notice. Its text stays off the lock screen: the public version says only that the connection ended. */
	private fun alert(text: String) {
		val alert = notification(label("Veilway lost the connection", "اتصال وی‌ال‌وی از دست رفت"), text, false).apply {
			visibility = Notification.VISIBILITY_PRIVATE
			publicVersion = notification("Veilway", label("Connection lost", "اتصال از دست رفت"), false)
		}
		getSystemService(NotificationManager::class.java).notify(FAILED, alert)
	}

	/** The user turned the VPN off in the system's settings, or another VPN app took over. */
	override fun onRevoke() {
		Wanted(this).wanted = false
		worker.execute { Native.disconnect(); finish(null) }
	}

	override fun onDestroy() {
		held?.close()
		held = null
		unwatchNetworks()
		unwatchIdle()
		instance = null
		Toggle.refresh(this)
		worker.shutdown()
		super.onDestroy()
	}

	private fun ongoing(): Notification {
		val text = if (proxyOnly) when (state) {
			"connected" -> label("Proxy only: connected", "فقط پروکسی: متصل است")
			"reconnecting", "blocked", "stopped" -> label("Proxy only: no connection", "فقط پروکسی: اتصال برقرار نیست")
			else -> label("Connecting", "در حال اتصال")
		} else when (state) {
			"connected" -> label("Connected", "متصل است")
			"reconnecting", "blocked" -> label("No connection. Internet blocked until the VPN is back", "اتصال برقرار نیست. اینترنت تا بازگشت وی‌پی‌ان مسدود است")
			"stopped" -> label("Internet blocked until you reconnect", "اینترنت تا اتصال دوباره مسدود است")
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
		shown = "$proxyOnly $state"
		if (Build.VERSION.SDK_INT >= 34) startForeground(ONGOING, ongoing(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED) else startForeground(ONGOING, ongoing())
	}

	/** Tells the engine which networks the phone is on, and the system which one carries the VPN, so that the engine reconnects when the phone moves from wifi to mobile data and back. */
	private fun update() {
		val current = underlying
		val properties = current?.second
		val found = ArrayList<String>()
		var description = "android:none"
		// Mobile data, or a network whose kind the system will not say: the engine lets nothing local out there.
		val capabilities = current?.let { getSystemService(ConnectivityManager::class.java).getNetworkCapabilities(it.first) }
		val cellular = capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
		if (properties != null) {
			properties.linkAddresses.forEach { val ip = it.address; if (!ip.isLinkLocalAddress && !ip.isLoopbackAddress) found.add("${ip.hostAddress?.substringBefore('%')}/${it.prefixLength}") }
			val gateway = properties.routes.firstOrNull { it.isDefaultRoute && it.gateway != null }?.gateway
			if (gateway != null) found.add("${gateway.hostAddress?.substringBefore('%')}/${if (gateway is Inet6Address) 128 else 32}")
			description = "android:${properties.interfaceName}:${gateway?.hostAddress ?: "?"}"
		}
		try { setUnderlyingNetworks(current?.let { arrayOf(it.first) }) } catch (e: Exception) { }
		Native.networkChanged(description, found.toTypedArray(), cellular)
	}

	private fun watchNetworks() {
		if (callback != null) return
		val watcher = object : ConnectivityManager.NetworkCallback() {
			override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) { underlying = network to properties; update() }
			override fun onLost(network: Network) { if (underlying?.first == network) underlying = null; update() }
		}
		callback = watcher
		getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(watcher)
	}

	/** Tells the engine when the phone goes idle (screen off, or Doze), so that it can keep fewer timers running. */
	private fun watchIdle() {
		if (idleWatcher != null) return
		val power = getSystemService(PowerManager::class.java)
		val tell = { Native.lowPower(!power.isInteractive || power.isDeviceIdleMode) }
		val watcher = object : BroadcastReceiver() { override fun onReceive(context: Context, intent: Intent) = tell() }
		idleWatcher = watcher
		registerReceiver(watcher, IntentFilter().apply { addAction(Intent.ACTION_SCREEN_OFF); addAction(Intent.ACTION_SCREEN_ON); addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED) })
		tell()
	}

	private fun unwatchIdle() {
		val watcher = idleWatcher ?: return
		idleWatcher = null
		try { unregisterReceiver(watcher) } catch (e: Exception) { }
	}

	private fun unwatchNetworks() {
		val watcher = callback ?: return
		callback = null
		underlying = null
		try { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(watcher) } catch (e: Exception) { }
	}
}
