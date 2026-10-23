"""Applies what the generated Gradle project (gen/android, made by `tauri android init`) does not have: the Kotlin sources of the VPN plugin, the service and receiver in the manifest, and their permissions. Run by build.sh after init, safe to run again."""
import re
import shutil
import sys
from pathlib import Path

root = Path(sys.argv[1])
gen = root / "src-tauri" / "gen" / "android" / "app" / "src" / "main"
target = gen / "java" / "io" / "github" / "veilwayproject" / "app"
target.mkdir(parents=True, exist_ok=True)
for source in (root / "kotlin").glob("*.kt"):
    shutil.copy(source, target / source.name)
manifest = gen / "AndroidManifest.xml"
text = manifest.read_text()
permissions = """
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />"""
components = """
        <service
            android:name=".VeilwayVpnService"
            android:exported="false"
            android:foregroundServiceType="systemExempted"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
            <meta-data android:name="android.net.VpnService.SUPPORTS_ALWAYS_ON" android:value="true" />
        </service>
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
            </intent-filter>
        </receiver>
"""
if "VeilwayVpnService" not in text:
    text = re.sub(r"(<manifest[^>]*>)", lambda m: m.group(1) + permissions, text, count=1)
    text = text.replace("</application>", components + "    </application>", 1)
# The in-app updater: the PackageInstaller session needs this permission, and its result goes to a receiver that only the session's PendingIntent reaches.
if "InstallReceiver" not in text:
    text = re.sub(r"(<manifest[^>]*>)", lambda m: m.group(1) + '\n    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />', text, count=1)
    text = text.replace("</application>", '        <receiver android:name=".InstallReceiver" android:exported="false" />\n    </application>', 1)
# The scanner plugin declares a required camera; a phone without one can still install the app and use links, files and pictures.
if "android.hardware.camera.any" not in text or 'tools:replace="android:required"' not in text:
    if "xmlns:tools=" not in text:
        text = re.sub(r"<manifest\b", '<manifest xmlns:tools="http://schemas.android.com/tools"', text, count=1)
    text = re.sub(r"(<manifest[^>]*>)", lambda m: m.group(1) + '\n    <uses-feature android:name="android.hardware.camera.any" android:required="false" tools:replace="android:required" />', text, count=1)
# The vault and its key are not backed up or transferred: the key is wrapped by a Keystore key that no restore brings back, so a restored vault could not be opened.
text = re.sub(r"\s+android:(allowBackup|dataExtractionRules|fullBackupContent)=\"[^\"]*\"", "", text)
text = re.sub(r"<application\b", "<application android:allowBackup=\"false\" android:dataExtractionRules=\"@xml/data_extraction_rules\" android:fullBackupContent=\"@xml/backup_rules\"", text, count=1)
manifest.write_text(text)
xml = gen / "res" / "xml"
xml.mkdir(parents=True, exist_ok=True)
(xml / "data_extraction_rules.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup><exclude domain="root" path="." /></cloud-backup>
    <device-transfer><exclude domain="root" path="." /></device-transfer>
</data-extraction-rules>
""")
(xml / "backup_rules.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<full-backup-content><exclude domain="root" path="." /></full-backup-content>
""")
# The template targets the newest SDK; androidx needs at least 36 to compile, and the SDK volume has 35 and 36.
gradle = root / "src-tauri" / "gen" / "android" / "app" / "build.gradle.kts"
text = gradle.read_text()
gradle.write_text(re.sub(r"(compileSdk|targetSdk) = \d+", r"\1 = 36", text))
# Rust looks these up by name through JNI, and R8 renames members that only Kotlin code seems to use.
(root / "src-tauri" / "gen" / "android" / "app" / "proguard-veilway.pro").write_text("-keep class io.github.veilwayproject.app.Native { *; }\n-keep class io.github.veilwayproject.app.Bridge { *; }\n")
# The template runs the CLI as `node tauri ...`, which only works for a CLI installed in the project. The image has it on the PATH.
task = next((root / "src-tauri" / "gen" / "android" / "buildSrc").rglob("BuildTask.kt"))
text = task.read_text().replace('val executable = """node""";', 'val executable = """tauri""";').replace('listOf("tauri", "android", "android-studio-script")', 'listOf("android", "android-studio-script")')
task.write_text(text)
print("overlay applied")
