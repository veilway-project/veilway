package io.github.veilwayproject.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** An AES-256-GCM key that lives in the Android Keystore (StrongBox where the phone has it) and wraps the vault key. The key cannot be exported and needs no lock screen secret, so the service can open the vault at boot. */
object Keystore {
	private const val ALIAS = "veilway-vault-wrapper"
	private const val IV = 12

	private fun key(): SecretKey {
		val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
		(store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
		fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
			.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
			.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
			.setKeySize(256)
			.setRandomizedEncryptionRequired(true)
			.apply { if (strongBox && android.os.Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true) }
			.build()
		val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
		return try {
			generator.init(spec(true))
			generator.generateKey()
		} catch (e: StrongBoxUnavailableException) {
			generator.init(spec(false))
			generator.generateKey()
		}
	}

	fun wrap(plain: ByteArray): ByteArray? = try {
		val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
		cipher.iv + cipher.doFinal(plain)
	} catch (e: Exception) { null }

	fun unwrap(sealed: ByteArray): ByteArray? = try {
		if (sealed.size <= IV) null else Cipher.getInstance("AES/GCM/NoPadding").apply {
			init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, IV))
		}.doFinal(sealed, IV, sealed.size - IV)
	} catch (e: Exception) { null }
}
