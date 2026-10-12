<h1 align="center">Veilway</h1>

<p align="center" dir="rtl">
یک هستهٔ VPN بر پایهٔ WireGuard و نوشته‌شده با Rust که قرار است به یک پلتفرم کامل تبدیل شود:<br>
یک موتور، یک پنل وب و کلاینت‌های رسمی.
</p>

<p align="center">
<a href="README.md">English</a> | <b>فارسی</b>
</p>

<p align="center">
<a href="https://github.com/veilway-project/veilway/actions/workflows/ci.yml"><img alt="ci" src="https://github.com/veilway-project/veilway/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/veilway-project/veilway/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/veilway-project/veilway?display_name=tag"></a>
<a href="LICENSE"><img alt="licence" src="https://img.shields.io/badge/licence-Apache--2.0-blue"></a>
</p>

<!-- SCREENSHOT SLOT 1 (hero): desktop client, connected state, dark mode, Persian UI, about 380px wide, centred. Produce it from the real UI. Do not add a mockup. -->

<div dir="rtl">

## Veilway چیست

Veilway یک VPN لایهٔ ۳ است. کلاینت یک کارت شبکهٔ مجازی می‌گیرد، بسته‌های IP به‌طور کامل درون یک تونل WireGuard دست‌نخورده جابه‌جا می‌شوند و سرور تصمیم می‌گیرد هر جریان از کجا خارج شود. رمزنگاری همان رمزنگاری WireGuard است و با [boringtun](https://github.com/cloudflare/boringtun) انجام می‌شود. آنچه Veilway اضافه می‌کند دور تونل قرار دارد: ترنسپورت‌هایی که تونل را از شبکه‌هایی عبور می‌دهند که UDP ساده در آن‌ها بسته است، جداسازی سخت‌گیرانه میان همتاها، و کنترل روی نقطهٔ خروج.

هدف، یک مجموعهٔ یکپارچه است که کاری را انجام دهد که امروز به یک هستهٔ پروکسی، یک پنل جدا و برنامه‌های کلاینت جدا نیاز دارد: هسته‌ای که کتابخانه هم هست، یک پنل وب، کلاینت دسکتاپ و اندروید، و مستندات فارسی و انگلیسی. بیشتر این‌ها هنوز ساخته نشده است. بخش «وضعیت» دقیقاً می‌گوید چه چیزی آماده است.

## برای چه کسانی است

- کسانی که برای خودشان یا یک گروه کوچک سرور VPN راه می‌اندازند، روی شبکه‌ای که UDP را می‌بندد یا کند می‌کند.
- گردانندگانی که می‌خواهند هر همتا فقط از یک پروکسی بالادستی خارج شود و هیچ راهی به همتاهای دیگر یا خود میزبان نداشته باشد.
- برنامه‌نویسانی که یک موتور سرور یا کلاینت WireGuard را به شکل کتابخانهٔ Rust می‌خواهند.

## وضعیت

> **آزمایشی.** Veilway نرم‌افزاری نوپاست و هیچ بازبینی امنیتی بیرونی نداشته است. رمزنگاری تونل از WireGuard است، اما هیچ بخشی از آن در برابر بازرسی عمیق بسته‌ها (DPI) یا کاوش فعال سنجیده نشده و WireGuard ساده روی UDP به‌آسانی قابل شناسایی است. جایی که از کار افتادنش شما را به خطر می‌اندازد به آن تکیه نکنید.

### آنچه امروز کار می‌کند

| بخش | کاری که می‌کند |
|---|---|
| سرور (`veilway run`) | تونل WireGuard را برای چندین همتا در فضای کاربر خاتمه می‌دهد (terminate)، روی UDP و روی WebSocket (هر دیتاگرام WireGuard یک فریم باینری است). بدون دستگاه TUN، بدون مسیریابی هسته، و بدون نیاز به root جز برای گشودن پورت زیر 1024. |
| خروج از SOCKS5 | هر جریان TCP و UDP که همتا می‌فرستد دوباره از یک SOCKS5 بالادستی برقرار می‌شود، سراسری یا جدا برای هر همتا. اگر بالادست UDP نداشته باشد DNS روی TCP می‌رود. |
| جداسازی همتاها | هر همتا از راه پروکسی به اینترنت عمومی می‌رسد و نه هیچ جای دیگر: نه همتاهای دیگر، نه دروازه (gateway)، نه میزبان و نه بازه‌های خصوصی، مگر اینکه `allow_private` روشن باشد. |
| پل (`veilway bridge`) | `client` به برنامهٔ معمولی WireGuard یک نقطهٔ UDP محلی می‌دهد و آن را روی `wss://` می‌برد. `relay` اتصال WebSocket می‌پذیرد و به هر پورت UDP WireGuard می‌فرستد. |
| کلاینت دسکتاپ | فقط ویندوز. یک فایل `.conf` معمولی WireGuard می‌خواند، تونل را درون خود برنامه روی UDP یا WebSocket و با آداپتر Wintun اجرا می‌کند و مسیرها و DNS را طوری تنظیم می‌کند که از تونل بگذرند. |

محدودیت‌های شناخته‌شده: درون تونل فقط IPv4 هست (کلاینت ویندوز IPv6 را به آداپتر می‌فرستد و همان‌جا دور می‌ریزد تا از کنار تونل نگذرد)، ICMP و پروتکل‌های غیر از TCP و UDP از بالادست SOCKS5 رد نمی‌شوند، پیکربندی یک فایل JSON ثابت است و بارگذاری دوباره ندارد، و هنوز پنل، حسابداری کاربران و API کنترل وجود ندارد.

### برنامهٔ پیش رو

برنامهٔ کامل و معیار پایان هر فاز در [PLAN.md](PLAN.md) است.

| فاز | چه چیزی تحویل می‌دهد |
|---|---|
| ۰، انجام شد | ساختار مخزن، مجوز و فایل‌های جامعه، CI، مدل تهدید |
| ۱ | موتور هسته: پیکربندی نسخه‌دار با بارگذاری دوبارهٔ زنده، چند ورودی، جدول جریان و مسیریاب، خروجی‌ها (پشتهٔ فضای کاربر، و TUN با NAT روی لینوکس برای همهٔ پروتکل‌های IP)، کاربران، سهمیه، آمار، API کنترل |
| ۲ | پروتکل بومی: کانال کنترل درون تونل، ترنسپورت‌ها (TLS، UDP مبهم‌سازی‌شده، HTTP از پشت CDN، آزمایش اولیهٔ TLS جعلی)، موتور کلاینت روی ویندوز، مک و لینوکس با IPv6 |
| ۳ | سیستم طراحی مشترک برای پنل و کلاینت‌ها، پوسته‌ها |
| ۴ | پنل وب: کاربران، ورودی‌ها، خروجی‌ها، مسیریابی، اشتراک‌ها، آمار |
| ۵ | کلاینت دسکتاپ روی ویندوز، مک و لینوکس با اشتراک و آمار زنده. این همان آلفای عمومی است |
| ۶ | افزونهٔ اختیاری که باینری رسمی Xray را به شکل یک پردازهٔ جانبی مدیریت‌شده اجرا می‌کند |
| ۷ | کلاینت اندروید |
| ۸ | مستندات کامل به هر دو زبان، نمونه‌های SDK، فازینگ در CI، انتشارهای امضاشده |

## شروع سریع

هنوز نسخه‌ای منتشر نشده، پس باید از کد منبع بسازید. به یک نسخهٔ پایدار زنجیره‌ابزار Rust و یک پروکسی SOCKS5 بالادستی نیاز دارید که سرور به آن دسترسی داشته باشد.

### ۱. ساخت (حدود ۵ دقیقه)

</div>

```
git clone https://github.com/veilway-project/veilway
cd veilway
cargo build --release --workspace
```

<div dir="rtl">

فایل اجرایی در `target/release/veilway` ساخته می‌شود. برای یک باینری ایستای لینوکس، اگر [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) نصب باشد:

</div>

```
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p veilway --bin veilway
```

<div dir="rtl">

### ۲. ساخت کلیدها (حدود ۱ دقیقه)

</div>

```
./target/release/veilway genkey
```

<div dir="rtl">

یک `private_key` و `public_key` متناظرش را چاپ می‌کند. یک بار برای سرور و یک بار برای هر همتا اجرایش کنید.

### ۳. نوشتن پیکربندی (حدود ۲ دقیقه)

</div>

```
cp config.example.json config.json
```

<div dir="rtl">

فایل `config.json` را ویرایش کنید: کلید خصوصی سرور را در `private_key` بگذارید، `upstream` را روی SOCKS5 خودتان تنظیم کنید و کلید عمومی هر همتا را زیر `peers` بنویسید. فایل نمونه یک شنوندهٔ WebSocket هم روی پورت 443 با فایل‌های گواهی باز می‌کند. برای شروع فقط با UDP بلوک `listen_ws` را پاک کنید، یا مسیر فایل‌های واقعی را در `cert` و `key` بگذارید.

### ۴. اجرای سرور

</div>

```
./target/release/veilway run --config config.json
```

<div dir="rtl">

سرور هنگام شروع کلید عمومی خودش را در لاگ می‌نویسد. با `RUST_LOG=debug` جزئیات بیشتری می‌بینید.

### ۵. اتصال یک همتا

با هر برنامهٔ WireGuard، روی UDP:

</div>

```
[Interface]
PrivateKey = <peer private key>
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

<div dir="rtl">

جایی که UDP بسته است، پل را کنار برنامهٔ WireGuard اجرا کنید و به‌جای آن `Endpoint = 127.0.0.1:51820` بگذارید. این کار به بلوک `listen_ws` سرور با گواهی معتبر برای دامنهٔ شما نیاز دارد (گام ۳)، یا به یک `veilway bridge relay` جلوی سرور (بخش «رلهٔ WebSocket» را ببینید). به‌جای `vpn.example.com` نام میزبان خودتان را بگذارید.

</div>

```
veilway bridge client --listen 127.0.0.1:51820 --url wss://vpn.example.com/wg
```

<div dir="rtl">

گزینهٔ `--insecure` بررسی گواهی را رد می‌کند و فقط برای آزمایش یک رله با گواهی خودامضا است.

## پیکربندی سرور

`config.json` یک سند JSON است. `private_key`، `address`، `upstream`، `peers` و دست‌کم یک شنونده الزامی‌اند.

| کلید | معنی |
|---|---|
| `private_key` | کلید سرور به شکل base64. با `veilway genkey` ساخته می‌شود. |
| `address` | زیرشبکهٔ تونل همراه با نشانی دروازه (gateway)، مثلاً `10.7.0.1/24`. |
| `upstream` | `socks5://user:pass@host:1080`. نام کاربری و گذرواژه می‌توانند percent-encoded باشند. |
| `peers[]` | `public_key`، `allowed_ips`، و در صورت نیاز `preshared_key` و یک `upstream` جدا برای همان همتا. |
| `listen_udp` | شنوندهٔ UDP WireGuard. اگر فقط WebSocket می‌خواهید حذفش کنید. |
| `listen_ws` | `{addr, path, cert, key}`. برای `ws://` ساده پشت یک پروکسی معکوس، `cert` و `key` را حذف کنید. |
| `dns` | DNS همهٔ همتاها را به این `ip:53` می‌فرستد. |
| `mtu` | پیش‌فرض `1420`. |
| `udp_idle_secs`، `tcp_idle_secs` | مهلت بیکاری جریان‌های رله‌شده. پیش‌فرض `60` و `7200`. |
| `allow_private` | با `true` همتاها از راه پروکسی به بازه‌های خصوصی هم می‌رسند. پیش‌فرض `false`. |

یک نمونهٔ کامل در [config.example.json](config.example.json) هست.

## رلهٔ WebSocket

با `listen_ws` خود سرور اتصال WebSocket را می‌پذیرد. `veilway bridge relay` نسخهٔ مستقل همین کار است: WebSocket را خاتمه می‌دهد و به هر پورت UDP WireGuard، حتی WireGuard هسته، می‌فرستد. هر اتصال سوکت UDP محلی خودش را دارد، پس جابه‌جایی میان شبکه‌ها و چند کلاینت پشت یک NAT درست کار می‌کند.

با گواهی خودش:

</div>

```
veilway bridge relay --listen 0.0.0.0:443 --path /wg --target 127.0.0.1:51820 \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

<div dir="rtl">

پشت یک پروکسی معکوس که گواهی را خودش دارد و روی همان میزبان یک سایت معمولی هم نشان می‌دهد:

</div>

```
veilway bridge relay --listen 127.0.0.1:8443 --path /wg --target 127.0.0.1:51820
```

<div dir="rtl">

گزینهٔ `--max-conns` (پیش‌فرض 1024) سقف اتصال‌های هم‌زمان رله را تعیین می‌کند.

## کلاینت دسکتاپ

`apps/desktop` یک برنامهٔ Tauri 2 است. امروز فقط روی ویندوز اجرا می‌شود و برای آداپتر Wintun و جدول مسیریابی به دسترسی مدیر نیاز دارد. یک فایل `.conf` WireGuard می‌گیرد که `Endpoint` آن `wss://`، `ws://` یا `host:port` باشد.

</div>

<!-- SCREENSHOT SLOT 2: desktop client, profile list and disconnected state, dark mode, Persian UI, two images side by side. Produce them from the real UI. -->

<div dir="rtl">

`wintun.dll` در مخزن نیست. آن را دریافت کنید و بعد بررسی کنید برنامه کامپایل می‌شود:

</div>

```
apps/desktop/scripts/fetch-wintun.sh
cd apps/desktop/src-tauri && cargo check
```

<div dir="rtl">

خود نصب‌کننده روی ویندوز و از همان پوشه ساخته می‌شود:

</div>

```
npx --yes @tauri-apps/cli@^2 build
```

<!-- SCREENSHOT SLOT 3: web panel dashboard, dark mode, Persian UI, full width. The panel does not exist yet (Phase 4). Leave empty until it does. -->

<div dir="rtl">

## معماری

مسیر داده در حال حاضر:

</div>

```mermaid
flowchart LR
    P["WireGuard peer<br>stock app or Veilway desktop"]
    B["veilway bridge client"]
    R["veilway bridge relay"]
    S["veilway run<br>boringtun + userspace TCP/IP"]
    X["upstream SOCKS5"]
    I(("internet"))
    O["other peers, gateway,<br>host, private ranges"]
    P -- "UDP" --> S
    P -- "wss://host/wg (Veilway desktop)" --> S
    P -- "UDP" --> B
    B -- "wss" --> R
    R -- "UDP" --> S
    S -- "CONNECT / UDP ASSOCIATE" --> X
    X --> I
    S x--x O
```

<div dir="rtl">

سرور دستگاه TUN ندارد. هر بسته را رمزگشایی می‌کند، بررسی می‌کند که نشانی مبدأ به همان همتا تعلق داشته باشد، آن را به یک پشتهٔ TCP/IP در فضای کاربر می‌دهد و برای هر جریان یک اتصال یا association روی SOCKS5 باز می‌کند. سقف جریان‌ها 4096 در کل و 512 برای هر همتا است.

شکل برنامه‌ریزی‌شده. در این نمودار دوم، جز تونل و خروجی SOCKS5 هیچ چیز دیگری هنوز وجود ندارد:

</div>

```mermaid
flowchart TB
    C["clients<br>desktop, Android"]
    W["panel<br>web UI + server"]
    subgraph CORE["veilway core: daemon and library"]
        IN["inbounds<br>WireGuard tunnel behind a transport"]
        RT["flow table + router"]
        EX["exits"]
        IN --> RT
        RT --> EX
    end
    OUT["direct, SOCKS5, NAT on the host,<br>another Veilway or WireGuard node"]
    XR["optional Xray sidecar"]
    C -- "IP packets in a WireGuard tunnel" --> IN
    W -- "control API" --> RT
    EX --> OUT
    EX -.-> XR
```

<div dir="rtl">

## ساختار مخزن

</div>

```
crates/
  veilway             the only binary: run, genkey, bridge client, bridge relay
  veilway-core        server engine: accept loop, isolation rules, per-flow SOCKS5 egress, config
  veilway-wg          multi-peer WireGuard wrapper (handshake routing, cookies, timers, roaming) and the WebSocket relay
  veilway-client      single-peer client engine and the Windows Wintun, route and DNS layer
  veilway-proto       wire formats (empty skeleton)
  veilway-transport   transports behind one trait (empty skeleton)
  veilway-api         control API server and OpenAPI schema (empty skeleton)
  veilway-xray        optional Xray sidecar manager (empty skeleton)
  veilway-ffi         uniffi bindings (empty skeleton)
apps/
  desktop             Tauri 2 desktop client, outside the cargo workspace
vendor/
  ipstack             patched userspace TCP/IP stack
```

<div dir="rtl">

پوشه‌های `panel/`، `packages/` و `apps/android` در فازهای بعدی اضافه می‌شوند.

## مستندات

- [veilway-docs](https://github.com/veilway-project/veilway-docs): مشخصات پروتکل، مرجع پیکربندی و راهنماها، به فارسی و انگلیسی. هم‌زمان با کد تکمیل می‌شود.
- [PLAN.md](PLAN.md): تصمیم‌های طراحی و برنامهٔ فازها (انگلیسی).
- [THREAT_MODEL.md](THREAT_MODEL.md): اینکه Veilway در برابر چه کسانی دفاع می‌کند و چه چیزهایی را پوشش نمی‌دهد (انگلیسی).

## مشارکت

از هر تغییری استقبال می‌شود، حتی تغییرهای کوچک. [CONTRIBUTING.fa.md](CONTRIBUTING.fa.md) ([English](CONTRIBUTING.md)) توضیح می‌دهد چطور بسازید، آزمایش کنید و تغییر بفرستید و سبک کد چیست. دو نکته را از همین اول بدانید: روی این کد `rustfmt`، `cargo fmt` یا prettier اجرا نکنید، و در اولین pull request از شما خواسته می‌شود یک بار [CLA](CLA.md) را امضا کنید.

</div>

```
cargo test --workspace
```

<div dir="rtl">

نام هر کسی که تغییری از او پذیرفته شود در [صفحهٔ مشارکت‌کنندگان](https://github.com/veilway-project/veilway/graphs/contributors) و در یادداشت‌های انتشار می‌آید.

## امنیت

آسیب‌پذیری‌ها را به شکل خصوصی و طبق [SECURITY.md](SECURITY.md) گزارش کنید. لطفاً برای آسیب‌پذیری issue عمومی باز نکنید.

## مجوز و قدردانی

Apache-2.0، فایل‌های [LICENSE](LICENSE) و [NOTICE](NOTICE) را ببینید. حق نشر: The Veilway Authors. مجوز شامل نام پروژه نمی‌شود: فورک‌ها باید نام و نشان خودشان را داشته باشند، [TRADEMARKS.md](TRADEMARKS.md) را ببینید.

Veilway برای پروتکل WireGuard از [boringtun](https://github.com/cloudflare/boringtun)، برای TCP/IP در فضای کاربر از [ipstack](https://github.com/narrowlink/ipstack) (با وصله در `vendor/ipstack`)، برای آداپتر ویندوز از [Wintun](https://www.wintun.net) و برای پوستهٔ دسکتاپ از [Tauri](https://tauri.app) استفاده می‌کند. WireGuard نشان تجاری ثبت‌شدهٔ Jason A. Donenfeld است.

</div>
