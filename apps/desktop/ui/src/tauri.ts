import {invoke} from "@tauri-apps/api/core";
import {listen, type UnlistenFn} from "@tauri-apps/api/event";

// The shapes of src-tauri/src/view.rs and helper.rs as the window receives them. Times are Unix seconds.
export type Notice = {severity: string, text: string};
export type Exit = {tag: string, name: string, country: string | null, selected: boolean, configured: boolean, working: boolean, load: string};
export type Usage = {used_bytes: number, quota_bytes: number, period: string, expires_at: number, up_bytes: number, down_bytes: number};
export type Connection = {transport: string, address: string, host: string | null, front: string | null, server_name: string | null, check: string | null, since: number | null, alpha: boolean};
// What the carrier of pasted links counts while it runs. Numbers and a reason code only.
export type XrayStatus = {open_tcp: number, open_udp: number, failed_flows: number, carried_flows: number, bytes_sent: number, bytes_received: number, unsupported_packets: number, dropped_udp_flows: number, restarts: number, last_restart: number | null, say_code: string | null, say: string | null};
export type StatusView = {state: "off" | "connecting" | "connected" | "reconnecting" | "stopped" | "failed", name: string, exit: string | null, wait_until: number | null, say_code: string | null, say: string | null, exits: Exit[], usage: Usage | null, notices: Notice[], sent_bytes: number, received_bytes: number, mtu: number, out_of_date: boolean, connection: Connection | null, applied: unknown, xray?: XrayStatus | null};
export type Card = {kind: "stat", label: string, value: string, unit: string | null} | {kind: "progress", label: string, used: number, total: number} | {kind: "notice", severity: string, text: string} | {kind: "link", label: string, url: string};
// `legacy` is set for a connection of pasted links: its protocol, whether the core caps it at Unsafe (otherwise at Detectable), and the code of the refusal when it cannot connect.
export type Legacy = {protocol: string, unsafe_cap: boolean, refused: string | null};
export type Profile = {id: string, name: string, exits: [string, string][], left_out: boolean, legacy?: Legacy | null};
// A backup update address of a subscription, or the new main address a move asks for. `key` is what an answer names it by (host and port, never a path or the token). An `update` host sees the token, a `static` one never does, and a `move` would become the main one. Over `plain` the network can tell that the device uses this app. `from` is the address a move leaves.
export type Host = {key: string, host: string, kind: "update" | "static" | "move", state: "waiting" | "allowed" | "declined", check: "chain" | "pinned" | "plain", from: string | null};
export type Subscription = {id: string, provider: string, standing: "current" | "out_of_date" | "stale", expires_at: number, can_refresh: boolean, profiles: Profile[], usage: [number, number, string] | null, cards: Card[], notices: Notice[], support: [string, string][], terms: string | null, privacy: string | null, logo: string | null, accent: string | null, left_out: number, lan_local: boolean, hosts: Host[], legacy?: boolean, bundle_notices?: {severity: string, text: string, issued_at: number}[]};
export type Offer = {kind: "native" | "carried", host: string | null, fingerprint: string, pinned: boolean, plain: boolean, in_file: boolean};
// Pasted links of another app, read and checked by the helper. Nothing is fetched for them; keeping them is the only step left.
export type LegacyOffer = {kind: "legacy", connections: {name: string, protocol: string, unsafe_cap: boolean}[], refused: {name: string, code: string}[], skipped: number, cut: boolean};
// The Xray add-on: whether this system can have it, whether the release this app pins is installed, the release and the most its download can be, in bytes, and whether an install is running.
export type XrayState = {supported: boolean, installed: boolean, release: string, size: number, installing: boolean};
// How an install goes, pushed by the helper: the bytes so far every half second, then `done` with the state or `failed` with the code of the step.
export type XrayInstallPush = {phase: "downloading" | "done" | "failed", downloaded: number, state: XrayState | null, error: string | null};
export type XrayOffer = {xray_offer: XrayState};
export const offersXray = (value: unknown): value is XrayOffer => typeof value === "object" && value !== null && "xray_offer" in value;
export type Move = {host: string, check: "chain" | "pinned" | "plain", from: string | null};
export type Review = {fingerprint: string, replaces: boolean, endpoint_changed: boolean, moving: Move | null, left_out: string[], preview: Subscription};
// The question of an endpoint on a private address that the user has not said yes to yet. The answer to it is the same call again with `private` set to these addresses, exactly as shown.
export type PrivateAsk = {ask_private: {host: string, addresses: string[]}};
export const asksPrivate = (value: unknown): value is PrivateAsk => typeof value === "object" && value !== null && "ask_private" in value;
export type Running = {connected: boolean, status: StatusView | null, kill_switch_kept: boolean};
export type Settings = {auto_update: boolean, theme: string, locale: string, kill_switch: boolean};
export type UpdateInfo = {available: boolean, version: string, notes: string, current: string};
export type Options = {local_names: boolean, routes: string[]};
export type Ended = {error: string | null, kept: boolean};
export type Progress = {downloaded: number, total: number | null};
// A bundle as the helper reviewed it (src-tauri/src/bundle.rs). `signer` is the provider's name when `release` is false. `subscription` is set where a newer document can be applied.
export type BundleApp = {platform: string, version: string, size: number, newer: boolean, installable: boolean};
export type BundleFound = {provider: string, subscription: string | null, serial: number | null, expires_at: number | null, code: "same" | "refused" | null};
export type BundleNotice = {providers: string[], severity: string, text: string};
export type BundleReview = {fingerprint: string, created_at: number, old: boolean, future: boolean, release: boolean, signer: string | null, apps: BundleApp[], found: BundleFound[], notices: BundleNotice[], dropped: {part: number, code: string}[]};

type Commands = {
	import_open: [{source: {kind: "link", text: string} | {kind: "file", data: string} | {kind: "sealed", data: string, password: string}}, Offer | LegacyOffer],
	import_qr: [{data: string}, Offer | LegacyOffer],
	import_proceed: [{private?: string[]}, Review | PrivateAsk],
	import_keep: [{keep: boolean}, Subscription[]],
	import_cancel: [{}, null],
	share_link: [{id: string}, {link: string, qr: string}],
	share_text: [{text: string}, null],
	share_file: [{id: string, password: string}, boolean],
	bundle_pick: [{}, BundleReview | null],
	bundle_document: [{id: string}, Subscription[]],
	bundle_install: [{}, null],
	bundle_notices: [{}, null],
	bundle_close: [{}, null],
	library: [{languages: string[]}, Subscription[]],
	refresh: [{id: string, private?: string[]}, Subscription[] | PrivateAsk],
	remove: [{id: string}, Subscription[]],
	answer_hosts: [{id: string, allow: string[], decline: string[]}, Subscription[]],
	set_lan: [{id: string, on: boolean}, Subscription[]],
	get_alpha: [{}, {alpha: boolean}],
	set_alpha: [{on: boolean}, {alpha: boolean}],
	connect: [{subscription: string, profile: string, options: Options}, null | XrayOffer],
	xray_state: [{}, XrayState],
	xray_install: [{}, null],
	xray_remove: [{}, XrayState],
	answer: [{yes: boolean}, null],
	disconnect: [{}, null],
	select_exit: [{tag: string | null}, null],
	status: [{}, Running],
	log_history: [{}, string[]],
	check_update: [{}, UpdateInfo],
	install_update: [{}, null],
	get_settings: [{}, Settings],
	set_settings: [{settings: Settings}, null],
	open_link: [{url: string}, null],
	get_autostart: [{}, boolean],
	set_autostart: [{enabled: boolean}, null],
	open_vpn_settings: [{}, null]
};

type Events = {status: StatusView, question: string, ended: Ended, log: string, "update-progress": Progress, "xray-install": XrayInstallPush};

// Every command answers with its value or rejects with the plain-words text the window shows.
export function call<C extends keyof Commands>(command: C, args: Commands[C][0] = {} as Commands[C][0]): Promise<Commands[C][1]> {
	return invoke<Commands[C][1]>(command, args).catch(error => Promise.reject(typeof error === "string" ? error : error instanceof Error ? error.message : String(error)));
}

export function on<E extends keyof Events>(event: E, handler: (payload: Events[E]) => void): Promise<UnlistenFn> {
	return listen<Events[E]>(event, e => handler(e.payload));
}
