import {invoke} from "@tauri-apps/api/core";
import {listen, type UnlistenFn} from "@tauri-apps/api/event";

// The shapes of src-tauri/src/view.rs and helper.rs as the window receives them. Times are Unix seconds.
export type Notice = {severity: string, text: string};
export type Exit = {tag: string, name: string, country: string | null, selected: boolean, configured: boolean, working: boolean, load: string};
export type Usage = {used_bytes: number, quota_bytes: number, period: string, expires_at: number, up_bytes: number, down_bytes: number};
export type StatusView = {state: "off" | "connecting" | "connected" | "reconnecting" | "stopped" | "failed", name: string, exit: string | null, wait_until: number | null, say_code: string | null, say: string | null, exits: Exit[], usage: Usage | null, notices: Notice[], sent_bytes: number, received_bytes: number, mtu: number, out_of_date: boolean, applied: unknown};
export type Card = {kind: "stat", label: string, value: string, unit: string | null} | {kind: "progress", label: string, used: number, total: number} | {kind: "notice", severity: string, text: string} | {kind: "link", label: string, url: string};
export type Profile = {id: string, name: string, exits: [string, string][]};
export type Subscription = {id: string, provider: string, standing: "current" | "out_of_date" | "stale", expires_at: number, can_refresh: boolean, profiles: Profile[], usage: [number, number, string] | null, cards: Card[], notices: Notice[], support: [string, string][], logo: string | null, accent: string | null, left_out: number, lan_local: boolean};
export type Offer = {kind: "native" | "carried", host: string | null, fingerprint: string, pinned: boolean, in_file: boolean};
export type Review = {fingerprint: string, replaces: boolean, endpoint_changed: boolean, left_out: string[], preview: Subscription};
export type Running = {connected: boolean, status: StatusView | null, kill_switch_kept: boolean};
export type Settings = {auto_update: boolean, theme: string, locale: string, kill_switch: boolean};
export type UpdateInfo = {available: boolean, version: string, notes: string, current: string};
export type Options = {local_names: boolean, routes: string[]};
export type Ended = {error: string | null, kept: boolean};
export type Progress = {downloaded: number, total: number | null};

type Commands = {
	import_open: [{source: {kind: "link", text: string} | {kind: "file", data: string}}, Offer],
	import_qr: [{data: string}, Offer],
	import_proceed: [{}, Review],
	import_keep: [{keep: boolean}, Subscription[]],
	import_cancel: [{}, null],
	library: [{languages: string[]}, Subscription[]],
	refresh: [{id: string}, Subscription[]],
	remove: [{id: string}, Subscription[]],
	set_lan: [{id: string, on: boolean}, Subscription[]],
	connect: [{subscription: string, profile: string, options: Options}, null],
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

type Events = {status: StatusView, question: string, ended: Ended, log: string, "update-progress": Progress};

// Every command answers with its value or rejects with the plain-words text the window shows.
export function call<C extends keyof Commands>(command: C, args: Commands[C][0] = {} as Commands[C][0]): Promise<Commands[C][1]> {
	return invoke<Commands[C][1]>(command, args).catch(error => Promise.reject(typeof error === "string" ? error : error instanceof Error ? error.message : String(error)));
}

export function on<E extends keyof Events>(event: E, handler: (payload: Events[E]) => void): Promise<UnlistenFn> {
	return listen<Events[E]>(event, e => handler(e.payload));
}
