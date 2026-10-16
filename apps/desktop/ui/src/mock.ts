// Development only: stands in for the Tauri side so the screens can run in a plain browser. main.tsx loads it only when Vite runs in "mock" mode, so a production build never contains it.
// The address picks the scene and the display: ?scene=empty|question|connected&lang=en|fa&scheme=dark|light.
import type {Host, Running, StatusView, Subscription} from "./tauri.ts";

const query = new URLSearchParams(location.search), scene = query.get("scene") ?? "connected";
try { localStorage.setItem("veilway-desktop", JSON.stringify({scheme: query.get("scheme") ?? "system", choice: null, hidden: []})); } catch { /* private window */ }
const LOGO = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAsUlEQVR42u3awQ2AMAwDwE7AtAzCqHx5lQUQCk2dNMaR+saHUKEJramIatuPblklQy+H8QZPg8wOHgpBh4chooJDIFnhpyCyw7sRpQEjFzqvblpwxOidQgI+IUoDPM8qGmBClAZ4d4sIwCtCgEzAjBdOFOARIYAAAggggAClAfoWEmCBM4FOZNnnYnUlsntDyzS2RhEowH+bu+Xb6xQDDooRE82Qj2LMSjPopvnVQOWsG6NWRf9wqO4DAAAAAElFTkSuQmCC";
// Not a real code: a pattern with the three finder squares, for the screenshots only.
const QR = (() => { const n = 29, cells: string[] = []; for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) { const finder = (x < 8 && y < 8) || (x >= n - 8 && y < 8) || (x < 8 && y >= n - 8), edge = (a: number, b: number) => a === 0 || a === 6 || b === 0 || b === 6 || (a >= 2 && a <= 4 && b >= 2 && b <= 4); const dark = finder ? (x < 8 && y < 8 ? edge(x, y) : x >= n - 8 && y < 8 ? edge(x - (n - 7), y) : edge(x, y - (n - 7))) && x % (n - 7) < 7 && y % (n - 7) < 7 || false : ((x * 7 + y * 13 + x * y) % 5 < 2); if (dark) cells.push(`<rect x="${x + 2}" y="${y + 2}" width="1" height="1"/>`); } return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n + 4} ${n + 4}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><g fill="#000">${cells.join("")}</g></svg>`; })();
const DAY = 86400, now = () => Math.floor(Date.now() / 1000), GB = 1024 ** 3;

let lan = false, hosts: Host[] = [{key: "backup.harbor.example:443", host: "backup.harbor.example:443", kind: "update", state: "waiting", check: "chain", from: null}, {key: "http://203.0.113.9:8080/s#plain", host: "203.0.113.9:8080", kind: "move", state: "waiting", check: "plain", from: "sub.harbor.example:443"}, {key: "objects.storage.example:443#static", host: "objects.storage.example:443", kind: "static", state: "waiting", check: "chain", from: null}, {key: "raw.codehost.example:443#static", host: "raw.codehost.example:443", kind: "static", state: "allowed", check: "chain", from: null}];

function subscription(fa: boolean): Subscription {
	return {
		id: "sub-harbor", provider: fa ? "هاربر نت" : "Harbor Net", standing: "current", expires_at: now() + 23 * DAY, can_refresh: true,
		profiles: [{id: "main", name: fa ? "اتصال اصلی" : "Main", exits: [["fra", "Frankfurt"], ["ams", "Amsterdam"], ["hel", "Helsinki"], ["ist", "Istanbul"]]}, {id: "backup", name: fa ? "اتصال پشتیبان" : "Backup", exits: [["fra", "Frankfurt"]]}],
		usage: [31.4 * GB, 50 * GB, "monthly"],
		cards: [{kind: "stat", label: fa ? "دستگاه‌ها" : "Devices", value: "2 / 3", unit: null}, {kind: "notice", severity: "information", text: fa ? "سرور هلسینکی شنبه ساعت ۲ بامداد برای نگهداری یک ساعت خاموش است." : "Helsinki is down for maintenance on Saturday from 02:00 for about an hour."}, {kind: "link", label: fa ? "تمدید اشتراک" : "Renew your plan", url: "https://harbor.example/renew"}],
		notices: [], support: [[fa ? "پشتیبانی" : "Support", "https://t.me/harbor_support"]], logo: LOGO, accent: "#0e7490", left_out: 0, lan_local: lan, hosts
	};
}

const opened = now() - 3725, connection = {transport: query.get("transport") ?? "tls", address: "203.0.113.24:443", host: "node.harbor.example", front: null, server_name: "cdn.harbor.example", check: "public-and-pin", since: opened};
let held = scene === "empty" ? 0 : 1, sent = 48 * 1024 ** 2, received = 712 * 1024 ** 2, connected = scene !== "empty", selected: string | null = null;
const status = (): StatusView => {
	sent += 40000 + Math.random() * 90000;
	received += 600000 + Math.random() * 2400000;
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
	library: args => { languages = (args.languages as string[]) ?? ["en"]; return held ? [subscription(languages[0] === "fa")] : []; },
	status: (): Running => ({connected, status: connected ? status() : null, kill_switch_kept: false}),
	log_history: () => ["0.4s client ready", "1.2s connect requested", "2.0s connected through Frankfurt"],
	get_settings: () => ({auto_update: false, theme: "dark", locale: query.get("lang") === "fa" ? "fa" : "en", kill_switch: true}),
	set_settings: () => null,
	get_autostart: () => false,
	set_autostart: () => null,
	open_link: () => null,
	check_update: () => ({available: false, version: "0.1.0", notes: "", current: "0.1.0"}),
	connect: () => { connected = true; return null; },
	disconnect: () => { connected = false; return null; },
	answer: () => null,
	select_exit: args => { selected = (args.tag as string | null) ?? null; return null; },
	import_open: args => {
		const source = args.source as {kind: string, password?: string};
		if (source.kind === "file" && query.has("sealed")) return Promise.reject("needs_password");
		if (source.kind === "sealed" && source.password !== "correct horse battery") return Promise.reject("wrong_password");
		return ({kind: "native", host: "sub.harbor.example", fingerprint: "hb7Q-2mXe-91Lk-Pz4c", pinned: true, plain: false, in_file: false});
	},
	share_link: () => ({link: "veilway://sub/sub.harbor.example/s#v1.0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc.VVVVVVVVVVVVVVVVVVVVVQ", qr: QR}),
	share_file: () => true,
	share_text: () => null,
	import_qr: () => ({kind: "carried", host: null, fingerprint: "hb7Q-2mXe-91Lk-Pz4c", pinned: false, plain: false, in_file: false}),
	import_proceed: () => ({fingerprint: "hb7Q-2mXe-91Lk-Pz4c", replaces: false, endpoint_changed: false, moving: null, left_out: [], preview: subscription(languages[0] === "fa")}),
	import_keep: args => { if (args.keep) held = 1; return held ? [subscription(languages[0] === "fa")] : []; },
	import_cancel: () => null,
	refresh: () => [subscription(languages[0] === "fa")],
	remove: () => { held = 0; return []; },
	answer_hosts: args => { hosts = hosts.map(host => (args.allow as string[]).includes(host.key) ? {...host, state: "allowed"} : (args.decline as string[]).includes(host.key) ? {...host, state: "declined"} : host); return [subscription(languages[0] === "fa")]; },
	set_lan: args => { lan = args.on === true; return [subscription(languages[0] === "fa")]; }
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
