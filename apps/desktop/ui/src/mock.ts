// Development only: stands in for the Tauri side so the screens can run in a plain browser. main.tsx loads it only when Vite runs in "mock" mode, so a production build never contains it.
// The address picks the scene and the display: ?scene=empty|question|connected|offer|xray&lang=en|fa&scheme=dark|light. "offer" holds pasted links with no Xray add-on, "xray" is connected through it.
import type {BundleReview, Host, LegacyOffer, Running, StatusView, Subscription, XrayState} from "./tauri.ts";

const query = new URLSearchParams(location.search), scene = query.get("scene") ?? "connected";
try { localStorage.setItem("veilway-desktop", JSON.stringify({scheme: query.get("scheme") ?? "system", choice: query.get("profile") ? {subscription: "sub-harbor", profile: query.get("profile")} : null, hidden: []})); } catch { /* private window */ }
const LOGO = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAsUlEQVR42u3awQ2AMAwDwE7AtAzCqHx5lQUQCk2dNMaR+saHUKEJramIatuPblklQy+H8QZPg8wOHgpBh4chooJDIFnhpyCyw7sRpQEjFzqvblpwxOidQgI+IUoDPM8qGmBClAZ4d4sIwCtCgEzAjBdOFOARIYAAAggggAClAfoWEmCBM4FOZNnnYnUlsntDyzS2RhEowH+bu+Xb6xQDDooRE82Qj2LMSjPopvnVQOWsG6NWRf9wqO4DAAAAAElFTkSuQmCC";
// Not a real code: a pattern with the three finder squares, for the screenshots only.
const QR = (() => { const n = 29, cells: string[] = []; for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) { const finder = (x < 8 && y < 8) || (x >= n - 8 && y < 8) || (x < 8 && y >= n - 8), edge = (a: number, b: number) => a === 0 || a === 6 || b === 0 || b === 6 || (a >= 2 && a <= 4 && b >= 2 && b <= 4); const dark = finder ? (x < 8 && y < 8 ? edge(x, y) : x >= n - 8 && y < 8 ? edge(x - (n - 7), y) : edge(x, y - (n - 7))) && x % (n - 7) < 7 && y % (n - 7) < 7 || false : ((x * 7 + y * 13 + x * y) % 5 < 2); if (dark) cells.push(`<rect x="${x + 2}" y="${y + 2}" width="1" height="1"/>`); } return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n + 4} ${n + 4}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><g fill="#000">${cells.join("")}</g></svg>`; })();
const DAY = 86400, now = () => Math.floor(Date.now() / 1000), GB = 1024 ** 3;

let lan = false, alpha = false, hosts: Host[] = [{key: "backup.harbor.example:443", host: "backup.harbor.example:443", kind: "update", state: "waiting", check: "chain", from: null}, {key: "http://203.0.113.9:8080/s#plain", host: "203.0.113.9:8080", kind: "move", state: "waiting", check: "plain", from: "sub.harbor.example:443"}, {key: "objects.storage.example:443#static", host: "objects.storage.example:443", kind: "static", state: "waiting", check: "chain", from: null}, {key: "raw.codehost.example:443#static", host: "raw.codehost.example:443", kind: "static", state: "allowed", check: "chain", from: null}];

function bundleReview(fa: boolean): BundleReview {
	const name = fa ? "هاربر نت" : "Harbor Net";
	return {fingerprint: "7f3a 91c0 4be2 1d55 a08e 6c19 f2b7 3e04", created_at: now() - 3 * DAY, old: false, future: false, release: false, signer: name, apps: [{platform: "linux-x86_64", version: "0.4.0", size: 88 * 1024 ** 2, newer: true, installable: true}, {platform: "macos-aarch64", version: "0.4.0", size: 90 * 1024 ** 2, newer: true, installable: false}, {platform: "windows-x86_64", version: "0.3.1", size: 84 * 1024 ** 2, newer: false, installable: false}], found: [{provider: name, subscription: "sub-harbor", serial: 42, expires_at: now() + 40 * DAY, code: null}, {provider: fa ? "کوای وی‌پی‌ان" : "Quay VPN", subscription: null, serial: null, expires_at: null, code: "same"}], notices: [{providers: [name], severity: "information", text: fa ? "سرور هلسینکی شنبه ساعت ۲ بامداد برای نگهداری یک ساعت خاموش است." : "Helsinki is down for maintenance on Saturday from 2 am for one hour."}], dropped: [{part: 3, code: "notice_no_subscription"}]};
}

function subscription(fa: boolean): Subscription {
	return {
		id: "sub-harbor", provider: fa ? "هاربر نت" : "Harbor Net", standing: "current", expires_at: now() + 23 * DAY, can_refresh: true,
		profiles: [{id: "main", name: fa ? "اتصال اصلی" : "Main", exits: [["fra", "Frankfurt"], ["ams", "Amsterdam"], ["hel", "Helsinki"], ["ist", "Istanbul"]], left_out: false}, {id: "backup", name: fa ? "اتصال پشتیبان" : "Backup", exits: [["fra", "Frankfurt"]], left_out: true}],
		usage: [31.4 * GB, 50 * GB, "monthly"],
		cards: [{kind: "stat", label: fa ? "دستگاه‌ها" : "Devices", value: "2 / 3", unit: null}, {kind: "notice", severity: "information", text: fa ? "سرور هلسینکی شنبه ساعت ۲ بامداد برای نگهداری یک ساعت خاموش است." : "Helsinki is down for maintenance on Saturday from 02:00 for about an hour."}, {kind: "link", label: fa ? "تمدید اشتراک" : "Renew your plan", url: "https://harbor.example/renew"}],
		notices: [], support: [[fa ? "پشتیبانی" : "Support", "https://t.me/harbor_support"]], terms: "https://harbor.example/terms", privacy: "https://harbor.example/privacy", logo: LOGO, accent: "#0e7490", left_out: 0, lan_local: lan, hosts
	};
}

// Pasted links of another app, kept unsigned and connected through the Xray add-on.
const pasted = (): Subscription => ({id: "legacy.7c1e", provider: "", standing: "current", expires_at: 0, can_refresh: false, profiles: [{id: "1", name: "Edge Frankfurt", exits: [], left_out: false, legacy: {protocol: "vless", unsafe_cap: false, refused: null}}, {id: "2", name: "Backup", exits: [], left_out: false, legacy: {protocol: "trojan", unsafe_cap: false, refused: null}}], usage: null, cards: [], notices: [], support: [], terms: null, privacy: null, logo: null, accent: null, left_out: 0, lan_local: lan, hosts: [], legacy: true});
const legacyOffer: LegacyOffer = {kind: "legacy", connections: [{name: "Edge Frankfurt", protocol: "vless", unsafe_cap: false}, {name: "Backup", protocol: "trojan", unsafe_cap: false}], refused: [{name: "Old KCP", code: "profile_refused.stream"}], skipped: 0, cut: false};
const xrayScene = scene === "offer" || scene === "xray";
let xrayInstalled = scene === "xray", legacyHeld = xrayScene, lastLegacy = false;
const xrayState = (): XrayState => ({supported: true, installed: xrayInstalled, release: "v26.3.27", size: 64 * 1024 ** 2, installing: false});
const list = () => [...(legacyHeld ? [pasted()] : []), ...(held ? [subscription(languages[0] === "fa")] : [])];

const opened = now() - 3725, connection = {transport: query.get("transport") ?? "tls", address: "203.0.113.24:443", host: "node.harbor.example", front: null, server_name: "cdn.harbor.example", check: "public-and-pin", since: opened, alpha: query.get("transport") === "faketls"};
let held = scene === "empty" ? 0 : 1, sent = 48 * 1024 ** 2, received = 712 * 1024 ** 2, connected = scene !== "empty" && scene !== "offer", selected: string | null = null;
const status = (): StatusView => {
	sent += 40000 + Math.random() * 90000;
	received += 600000 + Math.random() * 2400000;
	if (xrayScene) return {state: "connected", name: "Edge Frankfurt", exit: null, wait_until: null, say_code: null, say: null, exits: [], usage: null, notices: [], sent_bytes: sent, received_bytes: received, mtu: 1400, out_of_date: false, connection: null, applied: null, xray: {open_tcp: 14, open_udp: 3, failed_flows: 2, carried_flows: 318, bytes_sent: sent, bytes_received: received, unsupported_packets: 6, dropped_udp_flows: 0, restarts: 0, last_restart: null, say_code: null, say: null}};
	return {
		state: scene === "question" ? "connecting" : "connected", name: "Main", exit: "fra", wait_until: null, say_code: null, say: null,
		exits: [{tag: "fra", name: "Frankfurt", country: "de", selected: selected === "fra", configured: true, working: true, load: "low"}, {tag: "ams", name: "Amsterdam", country: "nl", selected: selected === "ams", configured: true, working: true, load: "medium"}, {tag: "hel", name: "Helsinki", country: "fi", selected: selected === "hel", configured: true, working: true, load: "high"}, {tag: "ist", name: "Istanbul", country: "tr", selected: false, configured: true, working: false, load: "unknown"}],
		usage: {used_bytes: 31.4 * GB, quota_bytes: 50 * GB, period: "monthly", expires_at: now() + 23 * DAY, up_bytes: 2.1 * GB, down_bytes: 29.3 * GB},
		notices: [], sent_bytes: sent, received_bytes: received, mtu: 1390, out_of_date: false, connection: scene === "question" ? {...connection, since: null} : connection, applied: null
	};
};

const callbacks = new Map<number, (event: unknown) => void>();
let nextId = 1;
const emit = (event: string, payload: unknown) => listeners.filter(l => l.event === event).forEach(l => callbacks.get(l.handler)?.({event, id: l.id, payload}));
const listeners: {event: string, handler: number, id: number}[] = [];
let languages: string[] = ["en"];

const answers: Record<string, (args: Record<string, unknown>) => unknown> = {
	"plugin:event|listen": args => {
		const id = nextId++;
		listeners.push({event: String(args.event), handler: Number(args.handler), id});
		if (args.event === "question" && scene === "question") setTimeout(() => emit("question", "On some networks the only way through may be one that does not look like web traffic. Someone watching the network can tell that something unusual is going on, though not what. Allow it for this connection?"), 400);
		return id;
	},
	"plugin:event|unlisten": () => null,
	library: args => { languages = (args.languages as string[]) ?? ["en"]; return list(); },
	status: (): Running => ({connected, status: connected ? status() : null, kill_switch_kept: false}),
	log_history: () => ["0.4s client ready", "1.2s connect requested", "2.0s connected through Frankfurt"],
	get_settings: () => ({auto_update: scene === "update", theme: "dark", locale: query.get("lang") === "fa" ? "fa" : "en", kill_switch: true}),
	set_settings: () => null,
	get_autostart: () => false,
	set_autostart: () => null,
	open_link: () => null,
	check_update: () => scene === "update" ? {available: true, version: "0.2.9", notes: "", current: "0.2.8"} : {available: false, version: "0.1.0", notes: "", current: "0.1.0"},
	install_update: () => new Promise(() => { setTimeout(() => emit("update-progress", {downloaded: 9 * 1024 ** 2, total: 21 * 1024 ** 2}), 200); }),
	connect: () => { if (xrayScene && !xrayInstalled) return {xray_offer: xrayState()}; connected = true; return null; },
	xray_state: xrayState,
	xray_install: () => {
		[300, 600, 900].forEach((at, i) => setTimeout(() => emit("xray-install", {phase: "downloading", downloaded: (i + 1) * 4 * 1024 ** 2, state: null, error: null}), at));
		setTimeout(() => { xrayInstalled = true; emit("xray-install", {phase: "done", downloaded: 12 * 1024 ** 2, state: xrayState(), error: null}); }, 1200);
		return null;
	},
	xray_remove: () => { xrayInstalled = false; return xrayState(); },
	disconnect: () => { connected = false; return null; },
	answer: () => null,
	select_exit: args => { selected = (args.tag as string | null) ?? null; return null; },
	import_open: args => {
		const source = args.source as {kind: string, password?: string, text?: string};
		lastLegacy = source.kind === "link" && /^(vless|vmess|trojan|ss):\/\//.test(source.text ?? "");
		if (lastLegacy) return /type=kcp/.test(source.text ?? "") ? Promise.reject("profile_refused.stream") : legacyOffer;
		if (source.kind === "file" && query.has("sealed")) return Promise.reject("needs_password");
		if (source.kind === "sealed" && source.password !== "correct horse battery") return Promise.reject("wrong_password");
		return ({kind: "native", host: "sub.harbor.example", fingerprint: "hb7Q-2mXe-91Lk-Pz4c", pinned: true, plain: false, in_file: false});
	},
	share_link: () => ({link: "veilway://sub/sub.harbor.example/s#v1.0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc.VVVVVVVVVVVVVVVVVVVVVQ", qr: QR}),
	share_file: () => true,
	share_text: () => null,
	import_qr: () => ({kind: "carried", host: null, fingerprint: "hb7Q-2mXe-91Lk-Pz4c", pinned: false, plain: false, in_file: false}),
	import_proceed: () => ({fingerprint: "hb7Q-2mXe-91Lk-Pz4c", replaces: false, endpoint_changed: false, moving: null, left_out: [], preview: subscription(languages[0] === "fa")}),
	import_keep: args => { if (args.keep && lastLegacy) legacyHeld = true; else if (args.keep) held = 1; return list(); },
	import_cancel: () => null,
	refresh: () => [subscription(languages[0] === "fa")],
	remove: args => { if (args.id === "legacy.7c1e") legacyHeld = false; else held = 0; return list(); },
	bundle_pick: () => bundleReview(languages[0] === "fa"),
	bundle_document: () => [subscription(languages[0] === "fa")],
	bundle_notices: () => null,
	bundle_close: () => null,
	bundle_install: () => null,
	answer_hosts: args => { hosts = hosts.map(host => (args.allow as string[]).includes(host.key) ? {...host, state: "allowed"} : (args.decline as string[]).includes(host.key) ? {...host, state: "declined"} : host); return [subscription(languages[0] === "fa")]; },
	set_lan: args => { lan = args.on === true; return [subscription(languages[0] === "fa")]; },
	get_alpha: () => ({alpha}),
	set_alpha: args => { alpha = args.on === true; return {alpha}; }
};

Object.assign(window, {
	__TAURI_INTERNALS__: {
		metadata: {currentWindow: {label: "main"}, currentWebview: {windowLabel: "main", label: "main"}},
		transformCallback: (callback: (event: unknown) => void) => { const id = nextId++; callbacks.set(id, callback); return id; },
		unregisterCallback: (id: number) => callbacks.delete(id),
		invoke: (command: string, args: Record<string, unknown> = {}) => {
			const answer = answers[command];
			return answer ? new Promise(resolve => setTimeout(() => resolve(answer(args)), 30)) : Promise.reject("The mock has no answer for " + command);
		}
	},
	__TAURI_EVENT_PLUGIN_INTERNALS__: {unregisterListener: () => {}}
});
