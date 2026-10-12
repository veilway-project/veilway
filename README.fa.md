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
| سرور (`veilway run`) | تونل WireGuard را برای چندین همتا در فضای کاربر خاتمه می‌دهد (terminate)، روی UDP و روی WebSocket (هر دیتاگرام WireGuard یک فریم باینری است). با خروجی‌های `netstack` نه دستگاه TUN در کار است، نه مسیریابی هسته، و نه نیازی به root جز برای گشودن پورت زیر 1024. خروجی `l3` (فقط لینوکس) یک دستگاه TUN اضافه می‌کند و به `CAP_NET_ADMIN` نیاز دارد. |
| خروج | هر جریان از خروجی‌ای بیرون می‌رود که قانون‌های مسیریابی برایش انتخاب می‌کنند. یک خروجی یا TCP و UDP را از راه outbound خودش دوباره برقرار می‌کند (یک SOCKS5 بالادستی یا اتصال مستقیم از خود نود)، یا روی میزبان لینوکسی همهٔ پروتکل‌های IP را به هستهٔ سیستم‌عامل می‌سپارد. اگر SOCKS5 بالادستی UDP نداشته باشد DNS روی TCP می‌رود. |
| جداسازی همتاها | هیچ همتایی به دروازه (gateway) یا میزبان نمی‌رسد. اینکه به کاربران دیگر و بازه‌های خصوصی برسد یا نه را قانون‌های مسیریابی تعیین می‌کنند، و پیکربندی نمونه هر دو را رد می‌کند. |
| پل (`veilway bridge`) | `client` به برنامهٔ معمولی WireGuard یک نقطهٔ UDP محلی می‌دهد و آن را روی `wss://` می‌برد. `relay` اتصال WebSocket می‌پذیرد و به هر پورت UDP WireGuard می‌فرستد. |
| کلاینت دسکتاپ | فقط ویندوز. یک فایل `.conf` معمولی WireGuard می‌خواند، تونل را درون خود برنامه روی UDP یا WebSocket و با آداپتر Wintun اجرا می‌کند و مسیرها و DNS را طوری تنظیم می‌کند که از تونل بگذرند. |

محدودیت‌های شناخته‌شده: درون تونل فقط IPv4 هست (کلاینت ویندوز IPv6 را به آداپتر می‌فرستد و همان‌جا دور می‌ریزد تا از کنار تونل نگذرد)، ICMP و پروتکل‌های غیر از TCP و UDP از بالادست SOCKS5 رد نمی‌شوند (پینگ را خود نود پاسخ می‌دهد و فقط خروجی `l3` روی لینوکس همهٔ پروتکل‌های IP را عبور می‌دهد)، و هنوز بارگذاری دوبارهٔ پیکربندی، سهمیه، پنل و API کنترل وجود ندارد.

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

هنوز نسخه‌ای منتشر نشده، پس باید از کد منبع بسازید. به یک نسخهٔ پایدار زنجیره‌ابزار Rust نیاز دارید. پروکسی SOCKS5 بالادستی اختیاری است: خروجی می‌تواند مستقیم از خود سرور هم بیرون برود.

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

فایل `config.json` را ویرایش کنید:

- در `private_key` هر inbound که نگه می‌دارید کلیدی از `veilway genkey` بگذارید. کلیدهای نمونه فقط جانگهدارند.
- در outbound با نام `proxy`، `server` و اطلاعات ورود را روی SOCKS5 خودتان تنظیم کنید. برای خروج بدون پروکسی، `outbound` خروجی `main` را روی `plain` (outbound مستقیم) بگذارید.
- زیر `users`، کلید عمومی هر دستگاه را در `public_key` بنویسید و در `addresses` نشانی‌ای از استخر inbound همان دستگاه بدهید.
- خروجی `node` به لینوکس با `CAP_NET_ADMIN` و برنامه‌های `ip` و `nft` (بسته‌های iproute2 و nftables) نیاز دارد؛ روی هر سیستم دیگری آن را با هرچه نامش را آورده حذف کنید: قانون‌های `staff-intranet` و `staff-ping`، مقدار `"exit": "node"` برای alice و `"node"` در `exits` مربوط به bob.
- ترنسپورت `ws` روی پورت 443 به فایل‌های گواهی در مسیرهای `tls` نیاز دارد، نسبت به پوشهٔ فایل پیکربندی. برای شروع فقط با UDP آن ترنسپورت را پاک کنید.

`veilway run` پیکربندی‌ای را که گروه یا دیگران بتوانند بخوانند نمی‌پذیرد، پس دسترسی را محدود کنید و بعد اعتبارسنجی کنید:

</div>

```
chmod 600 config.json
./target/release/veilway check --config config.json
```

<div dir="rtl">

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

جایی که UDP بسته است، پل را کنار برنامهٔ WireGuard اجرا کنید و به‌جای آن `Endpoint = 127.0.0.1:51820` بگذارید. این کار به یک ترنسپورت `ws` روی سرور با گواهی معتبر برای دامنهٔ شما نیاز دارد (گام ۳)، یا به یک `veilway bridge relay` جلوی سرور (بخش «رلهٔ WebSocket» را ببینید). به‌جای `vpn.example.com` نام میزبان خودتان را بگذارید.

</div>

```
veilway bridge client --listen 127.0.0.1:51820 --url wss://vpn.example.com/wg
```

<div dir="rtl">

گزینهٔ `--insecure` بررسی گواهی را رد می‌کند و فقط برای آزمایش یک رله با گواهی خودامضا است.

## پیکربندی سرور

`config.json` یک سند JSON نسخه‌دار است (`"version": 1`). `veilway check` آن را اعتبارسنجی می‌کند و کلید ناشناس خطاست.

| بخش | معنی |
|---|---|
| `log` | سطح گزارش، و اینکه مقصدها اجازهٔ ظاهر شدن در گزارش‌ها را دارند یا نه (به‌طور پیش‌فرض خاموش). |
| `dns` | resolverهای بالادستی، و اینکه هر پرسش DNS از تونل را خود نود پاسخ بدهد یا نه. |
| `groups` | نام گروه‌هایی که کاربران و قانون‌ها می‌توانند به آن‌ها اشاره کنند. |
| `inbounds` | تونل‌های WireGuard: یک کلید، یک استخر نشانی و یک یا چند ترنسپورت (`udp`، `ws`). |
| `outbounds` | راه‌های برقراری جریان: `direct` یا `socks5`. |
| `exits` | راه‌های خروج نام‌دار، هرکدام با یک backend (`netstack`، `block`). |
| `routing` | خروج پیش‌فرض و فهرستی مرتب از قانون‌ها بر پایهٔ inbound، گروه، مقصد، دامنه و پروتکل. |
| `users` | کاربران با گروه‌ها، خروج‌های مجاز، تاریخ انقضای اختیاری و دستگاه‌ها (کلید عمومی، نشانی‌ها). |

همهٔ کلیدها، پیش‌فرض‌ها و قواعد اعتبارسنجی در [مرجع پیکربندی](https://github.com/veilway-project/veilway-docs/blob/main/src/content/docs/reference/config.md) آمده است. یک نمونهٔ کامل در [config.example.json](config.example.json) هست.

## رلهٔ WebSocket

با یک ترنسپورت `ws` روی inbound، خود سرور اتصال WebSocket را می‌پذیرد. `veilway bridge relay` نسخهٔ مستقل همین کار است: WebSocket را خاتمه می‌دهد و به هر پورت UDP WireGuard، حتی WireGuard هسته، می‌فرستد. هر اتصال سوکت UDP محلی خودش را دارد، پس جابه‌جایی میان شبکه‌ها و چند کلاینت پشت یک NAT درست کار می‌کند.

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

سرور هر بسته را رمزگشایی می‌کند، بررسی می‌کند که نشانی مبدأ به همان دستگاه تعلق داشته باشد و آن را طبق قانون‌ها مسیریابی می‌کند. برای خروجی `netstack` بسته به یک پشتهٔ TCP/IP در فضای کاربر می‌رود که برای هر جریان یک اتصال یا association از راه outbound همان خروجی باز می‌کند و دستگاه TUN در کار نیست. برای خروجی `l3` بسته روی یک دستگاه TUN نوشته می‌شود و هسته آن را فوروارد می‌کند. سقف جریان‌ها 65536 در کل، 1024 برای هر کاربر و 512 برای هر دستگاه است.

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
  veilway-core        server engine: config v1, inbounds, routing rules, flow table, isolation rules, per-flow egress
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
