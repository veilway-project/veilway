package io.github.veilwayproject.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** An AES-256-GCM key that lives in the Android Keystore (StrongBox where the phone has it) and wraps the vault key. The key cannot be exported and needs no lock screen secret, so the service can open the vault at boot. */
object Keystore {
	private const val ALIAS = "veilway-vault-wrapper"
	private const val IV = 12

	private fun existing(): SecretKey? = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(ALIAS, null) as? SecretKey

	/** Only [wrap] makes a key. [unwrap] never does, so a key that is gone stays gone until the vault asks for a new one. */
	private fun create(): SecretKey {
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
		val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, existing() ?: create()) }
		cipher.iv + cipher.doFinal(plain)
	} catch (e: Exception) { null }

	/** The plain bytes. An empty array when the key is gone for good (no key, or the wrapped copy does not open with it). Null when the Keystore failed for now, which the caller tries again. */
	fun unwrap(sealed: ByteArray): ByteArray? {
		val key = try { existing() } catch (e: UnrecoverableKeyException) { null } catch (e: Exception) { return null }
		if (key == null || sealed.size <= IV) return ByteArray(0)
		return try {
			Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed, 0, IV)) }.doFinal(sealed, IV, sealed.size - IV)
		} catch (e: AEADBadTagException) { ByteArray(0) } catch (e: Exception) { null }
	}
}
