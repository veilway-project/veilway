# Veilway for Android

Tauri 2 mobile app. The screens are the desktop app's (`../desktop/ui`, loaded unchanged); the engine runs in the app process, and a Kotlin `VpnService` owns the VPN interface. Design and the reason this is its own crate are in the header of `src-tauri/src/lib.rs`.

Build the debug-signed arm64 APK in Docker (needs `~/veilway-ui` cloned, one container at a time, about 3 GB of memory):

```
sh apps/android/scripts/docker-build.sh   # writes apps/android/dist/veilway-debug-arm64.apk
```

CI builds the same APK as the `android` job of `ci.yml`.

## What the user turns on

- The first Connect shows Android's VPN consent dialog. Allow it.
- Always-on and kill switch: Settings, Network, VPN, the gear next to Veilway, then turn on Always-on VPN and Block connections without VPN. Android lets only the user do this. The Settings screen of the app has a button that opens the page. With it, the system starts Veilway at boot and after a crash, and blocks the internet while it is not connected.
- Without always-on, the app reconnects after a reboot by itself if the connection was on when the phone shut down (`BootReceiver`). Some phone makers stop this unless the app is excluded from battery optimization.
- Notifications (Android 13 and later) are optional. Without them the foreground service runs, only its notification is hidden.

## Check on a real phone

`adb logcat -s veilway` shows the engine's log lines. See `src-tauri/src/lib.rs` for the layout and `kotlin/` for the service.
