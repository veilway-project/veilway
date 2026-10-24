package io.github.veilwayproject.app

/** What Rust calls (bridge.rs). Static so that a native thread can reach it through a class reference kept from [Native.init]. */
object Bridge {
	@JvmStatic fun establish(addresses: Array<String>, dns: Array<String>, routes: Array<String>, mtu: Int): Int =
		VeilwayVpnService.instance?.establish(addresses, dns, routes, mtu) ?: -1

	@JvmStatic fun protect(fd: Int): Boolean = VeilwayVpnService.instance?.protect(fd) ?: false

	@JvmStatic fun wrap(plain: ByteArray): ByteArray? = Keystore.wrap(plain)

	@JvmStatic fun unwrap(sealed: ByteArray): ByteArray? = Keystore.unwrap(sealed)

	@JvmStatic fun proxyOnly(on: Boolean) { VeilwayVpnService.instance?.proxyOnly = on }

	@JvmStatic fun state(state: String) { VeilwayVpnService.instance?.show(state) }

	@JvmStatic fun ended(error: String?) { VeilwayVpnService.instance?.finish(error) }
}
