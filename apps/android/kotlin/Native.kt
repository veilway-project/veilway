package io.github.veilwayproject.app

/** The Rust engine in libveilway_android_lib.so (bridge.rs). Every function may block: call them off the main thread, except init. */
object Native {
	init { System.loadLibrary("veilway_android_lib") }

	/** Looks up [Bridge] for Rust and opens the vault, the store and the engine's runtime. Safe to call again. */
	@JvmStatic external fun init(dir: String): Boolean

	/** Starts a connection. Null when it started, else the words to show the user. */
	@JvmStatic external fun connect(subscription: String, profile: String, options: String): String?

	/** Stops the connection the clean way and returns when it has ended. */
	@JvmStatic external fun disconnect(): String?

	/** Whether the system's always-on VPN blocks the internet without the tunnel. Rust refuses to fetch subscriptions while no tunnel is up. */
	@JvmStatic external fun lockdown(on: Boolean)

	/** The device's own networks as "address/prefix" strings, a description of them, and whether the phone's packets leave by mobile data (true when that cannot be told). */
	@JvmStatic external fun networkChanged(description: String, networks: Array<String>, cellular: Boolean)
}
