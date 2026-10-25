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
# The scanner hands the photo to the phone's camera app through the web view, and from Android 11 the app only finds a camera app that it names here.
if "android.media.action.IMAGE_CAPTURE" not in text:
    text = text.replace("</manifest>", '    <queries>\n        <intent><action android:name="android.media.action.IMAGE_CAPTURE" /></intent>\n    </queries>\n</manifest>', 1)
# The quick settings tile and the home screen shortcut, both one switch for the last connection (Toggle.kt). The shortcut goes on the launcher activity, so a long press on the icon offers it and it can be dragged to the home screen.
if "VeilwayTile" not in text:
    text = text.replace("</application>", """        <service
            android:name=".VeilwayTile"
            android:exported="true"
            android:icon="@drawable/ic_veilway_tile"
            android:label="@string/veilway_tile"
            android:permission="android.permission.BIND_QUICK_SETTINGS_TILE">
            <intent-filter>
                <action android:name="android.service.quicksettings.action.QS_TILE" />
            </intent-filter>
            <meta-data android:name="android.service.quicksettings.TOGGLEABLE_TILE" android:value="true" />
        </service>
        <activity
            android:name=".ToggleActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:noHistory="true"
            android:taskAffinity=""
            android:theme="@android:style/Theme.Translucent.NoTitleBar" />
    </application>""", 1)
    text = re.sub(r'(android:name="\.MainActivity"[\s\S]*?</intent-filter>)', lambda m: m.group(1) + '\n            <meta-data android:name="android.app.shortcuts" android:resource="@xml/shortcuts" />', text, count=1)
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
(root / "src-tauri" / "gen" / "android" / "app" / "proguard-veilway.pro").write_text("-keep class io.github.veilwayproject.app.Native { *; }\n-keep class io.github.veilwayproject.app.Bridge { *; }\n# Tauri plugins read their arguments by reflection: a shrunk or renamed argument class arrives as null and the app crashes, as the barcode scanner of v0.2.18 did.\n-keep @app.tauri.annotation.InvokeArg class * { *; }\n-keep @app.tauri.annotation.TauriPlugin class * { *; }\n-keepclassmembers class * { @app.tauri.annotation.Command <methods>; @app.tauri.annotation.PermissionCallback <methods>; @app.tauri.annotation.ActivityCallback <methods>; }\n")
# The template runs the CLI as `node tauri ...`, which only works for a CLI installed in the project. The image has it on the PATH.
task = next((root / "src-tauri" / "gen" / "android" / "buildSrc").rglob("BuildTask.kt"))
text = task.read_text().replace('val executable = """node""";', 'val executable = """tauri""";').replace('listOf("tauri", "android", "android-studio-script")', 'listOf("android", "android-studio-script")')
task.write_text(text)
res = gen / "res"
(res / "xml" / "shortcuts.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<shortcuts xmlns:android="http://schemas.android.com/apk/res/android">
    <shortcut android:shortcutId="toggle" android:enabled="true" android:icon="@mipmap/ic_launcher" android:shortcutShortLabel="@string/veilway_toggle_short" android:shortcutLongLabel="@string/veilway_toggle_long">
        <intent android:action="android.intent.action.VIEW" android:targetPackage="io.github.veilwayproject.app" android:targetClass="io.github.veilwayproject.app.ToggleActivity" />
    </shortcut>
</shortcuts>
""")
for folder, tile, short, long in (("values", "Veilway", "Connect or disconnect", "Connect or disconnect Veilway"), ("values-fa", "وی‌ال‌وی", "وصل یا قطع", "وصل یا قطع کردن وی‌ال‌وی")):
    (res / folder).mkdir(parents=True, exist_ok=True)
    (res / folder / "veilway_strings.xml").write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="veilway_tile">{tile}</string>
    <string name="veilway_toggle_short">{short}</string>
    <string name="veilway_toggle_long">{long}</string>
</resources>
""")
# The tile icon is a white shape on nothing, as the system tints it: a shield with the V of the app icon cut out.
(res / "drawable" / "ic_veilway_tile.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="24dp" android:height="24dp" android:viewportWidth="24" android:viewportHeight="24">
    <path android:fillColor="#FFFFFFFF" android:fillType="evenOdd" android:pathData="M12,2L4,5v6c0,5 3.4,9.7 8,11c4.6,-1.3 8,-6 8,-11V5L12,2zM8,8.2h2.1L12,13.6l1.9,-5.4H16l-3.1,8h-1.8L8,8.2z" />
</vector>
""")
print("overlay applied")
