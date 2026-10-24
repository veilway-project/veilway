package io.github.veilwayproject.app

import android.Manifest
import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.util.Base64
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File

@InvokeArg
internal class InstallArgs {
	lateinit var path: String
}

@InvokeArg
internal class StartArgs {
	lateinit var subscription: String
	lateinit var profile: String
	var options: String = "{}"
}

@InvokeArg
internal class SaveArgs {
	lateinit var name: String
	lateinit var data: String
}

@InvokeArg
internal class ShareArgs {
	lateinit var text: String
}

/** What the window may ask of Android: the VPN consent, starting and stopping the service, and the system's VPN settings. The tunnel itself is never here: the service and the engine run without this plugin or any window. */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
	override fun load(webView: WebView) {
		super.load(webView)
		Native.init(activity.filesDir.absolutePath)
	}

	/** The system's own consent dialog, the first time. A notification permission is asked for too (Android 13 and later); the service runs without it, the notification is just hidden. */
	@Command
	fun prepare(invoke: Invoke) {
		if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(activity, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
			activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
		}
		val consent = VpnService.prepare(activity)
		if (consent == null) invoke.resolve(JSObject().put("granted", true)) else startActivityForResult(invoke, consent, "prepareResult")
	}

	@ActivityCallback
	fun prepareResult(invoke: Invoke, result: ActivityResult) {
		invoke.resolve(JSObject().put("granted", result.resultCode == Activity.RESULT_OK))
	}

	@Command
	fun start(invoke: Invoke) {
		val args = invoke.parseArgs(StartArgs::class.java)
		val intent = Intent(activity, VeilwayVpnService::class.java)
			.putExtra(VeilwayVpnService.EXTRA_SUBSCRIPTION, args.subscription)
			.putExtra(VeilwayVpnService.EXTRA_PROFILE, args.profile)
			.putExtra(VeilwayVpnService.EXTRA_OPTIONS, args.options)
		ContextCompat.startForegroundService(activity, intent)
		invoke.resolve()
	}

	@Command
	fun stop(invoke: Invoke) {
		if (VeilwayVpnService.instance == null) {
			// No service means no connection; the window still gets its "ended".
			Wanted(activity).wanted = false
			Thread { Native.disconnect() }.start()
		} else {
			activity.startService(Intent(activity, VeilwayVpnService::class.java).setAction(VeilwayVpnService.ACTION_STOP))
		}
		invoke.resolve()
	}

	private var fileToSave: ByteArray? = null

	/** The system's save screen for a sealed subscription file, with a name suggested. The file is already encrypted under the user's password. Nothing is written unless the user picks a place. */
	@Command
	fun saveFile(invoke: Invoke) {
		val args = invoke.parseArgs(SaveArgs::class.java)
		fileToSave = Base64.decode(args.data, Base64.DEFAULT)
		val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, args.name)
		startActivityForResult(invoke, intent, "saveFileResult")
	}

	@ActivityCallback
	fun saveFileResult(invoke: Invoke, result: ActivityResult) {
		val bytes = fileToSave
		fileToSave = null
		val uri = result.data?.data
		if (result.resultCode != Activity.RESULT_OK || uri == null || bytes == null) {
			invoke.resolve(JSObject().put("saved", false))
			return
		}
		try {
			activity.contentResolver.openOutputStream(uri)?.use { it.write(bytes) } ?: throw java.io.IOException("no stream")
			invoke.resolve(JSObject().put("saved", true))
		} catch (e: java.io.IOException) {
			invoke.reject("The file could not be saved.")
		}
	}

	/** The system's file picker for an offline bundle. The file is copied into the app's own folder, up to 1 GiB, and nothing is read from the picked place again. */
	@Command
	fun pickBundle(invoke: Invoke) {
		startActivityForResult(invoke, Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), "pickBundleResult")
	}

	@ActivityCallback
	fun pickBundleResult(invoke: Invoke, result: ActivityResult) {
		val uri = result.data?.data
		if (result.resultCode != Activity.RESULT_OK || uri == null) {
			invoke.resolve(JSObject().put("picked", false))
			return
		}
		Thread {
			val target = File(File(activity.filesDir, "bundle").apply { mkdirs() }, "incoming.vwbundle")
			try {
				target.delete()
				val source = activity.contentResolver.openInputStream(uri) ?: throw java.io.IOException("no stream")
				source.use { input ->
					target.outputStream().use { out ->
						val buffer = ByteArray(65536)
						var total = 0L
						while (true) {
							val read = input.read(buffer)
							if (read < 0) break
							total += read
							if (total > 1073741824L) throw java.io.IOException("too large")
							out.write(buffer, 0, read)
						}
					}
				}
				invoke.resolve(JSObject().put("picked", true))
			} catch (e: java.io.IOException) {
				target.delete()
				invoke.reject("bundle_copy")
			}
		}.start()
	}

	/** The system's share sheet with a piece of text, the link the user chose to pass on. */
	@Command
	fun shareText(invoke: Invoke) {
		val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, invoke.parseArgs(ShareArgs::class.java).text)
		activity.startActivity(Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
		invoke.resolve()
	}

	/** Where Always-on VPN and "Block connections without VPN" are turned on. Android keeps them out of reach of an app on purpose. */
	@Command
	fun openVpnSettings(invoke: Invoke) {
		activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
		invoke.resolve()
	}

	/** Whether the phone shows clocks as 24 hours, so times read the way the rest of the phone does. */
	@Command
	fun clock(invoke: Invoke) {
		invoke.resolve(JSObject().put("h24", android.text.format.DateFormat.is24HourFormat(activity)))
	}

	/** Deletes the photos the camera app took for the scanner. The web view's capture writes them to the app's Pictures folder and never removes them, and each one shows a subscription link. */
	@Command
	fun forgetPhotos(invoke: Invoke) {
		activity.getExternalFilesDir(android.os.Environment.DIRECTORY_PICTURES)?.listFiles()?.filter { it.name.startsWith("JPEG_") }?.forEach { it.delete() }
		invoke.resolve()
	}

	@Command
	fun canInstall(invoke: Invoke) {
		invoke.resolve(JSObject().put("granted", activity.packageManager.canRequestPackageInstalls()))
	}

	/** The page where the user lets Veilway install apps. Android keeps this switch out of reach of an app on purpose. */
	@Command
	fun allowInstalls(invoke: Invoke) {
		activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + activity.packageName)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
		invoke.resolve()
	}

	/**
	 * Hands an APK that Rust has already verified (signature and release tag) to the system's installer, which asks the user. Only the one file in the update folder is accepted, and only an update of this app can be installed. The connection stays up until Android replaces the app; it stays wanted, so BootReceiver brings it back after the update. Android refuses an APK signed with another key than this app's, which is a second guard behind the one in Rust.
	 */
	@Command
	fun install(invoke: Invoke) {
		val file = File(invoke.parseArgs(InstallArgs::class.java).path).canonicalFile
		if (file.parentFile != File(activity.filesDir, "update").canonicalFile || !file.isFile) {
			invoke.reject("The update file is not where it should be.")
			return
		}
		Thread {
			val installer = activity.packageManager.packageInstaller
			var id = -1
			try {
				val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
				params.setSize(file.length())
				params.setAppPackageName(activity.packageName)
				id = installer.createSession(params)
				installer.openSession(id).use { session ->
					file.inputStream().use { input -> session.openWrite("veilway.apk", 0, file.length()).use { out -> input.copyTo(out); session.fsync(out) } }
					val result = PendingIntent.getBroadcast(activity, id, Intent(activity, InstallReceiver::class.java).setPackage(activity.packageName), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
					session.commit(result.intentSender)
				}
				file.delete()
				invoke.resolve()
			} catch (error: Exception) {
				if (id >= 0) try { installer.abandonSession(id) } catch (_: Exception) {}
				invoke.reject(error.message ?: "The installer could not take the update.")
			}
		}.start()
	}
}
