import {THEME_FORMAT} from "../brand.ts";
import {BLACK, WHITE, contrast, luminance, mix, parseHex, toHex} from "./color.ts";
import {BLUR_MAX, COLOR_KEYS, MAX_BYTES, MAX_NAME, RULES, findings, grounds, minTint, type Palette, type Theme, type Tints} from "./tokens.ts";

export type IssueCode = "not-text" | "too-large" | "too-deep" | "not-json" | "not-object" | "unknown-key" | "missing-key" | "bad-type" | "bad-value" | "bad-color" | "scheme-mismatch" | "low-contrast" | "ink-adjusted" | "tint-raised";
export type Issue = {code: IssueCode, path: string};
export type Verdict = {ok: true, theme: Theme, corrections: Issue[]} | {ok: false, errors: Issue[]};

const ROOT_KEYS = ["format", "version", "name", "scheme", "colors", "glass"];
const GLASS_KEYS = ["tint", "blur"];
const MAX_ISSUES = 12;
// A pair this far under its minimum is refused outright; anything closer is repaired by moving the foreground.
const REFUSE_BELOW = 2 / 3;
// Colours are judged first with every pane solid, which is also what the solid setting shows. How thin the glass may then get is a separate question with its own answer.
const SOLID: Tints = {glass: 1, float: 1, thick: 1};

function refuse(code: IssueCode, path: string): Verdict {
	return {ok: false, errors: [{code, path}]};
}

// Keys in a hostile file end up in error messages, so only a short plain slice of them is kept.
function plain(key: string): string {
	return key.slice(0, 32).replace(/[^A-Za-z0-9_.-]/g, "?");
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Takes the text of a theme file from any source and returns either a theme rebuilt from parsed values or the reasons it was refused. Nothing from the input is passed through as a string except the name, which matches a letters-and-digits pattern.
export function validateTheme(input: unknown): Verdict {
	if (typeof input !== "string") return refuse("not-text", "");
	if (input.length > MAX_BYTES || new TextEncoder().encode(input).length > MAX_BYTES) return refuse("too-large", "");
	let depth = 0, inString = false;
	for (let i = 0; i < input.length; i++) {
		const ch = input[i];
		if (inString) {
			if (ch === "\\") i++;
			else if (ch === "\"") inString = false;
		} else if (ch === "\"") inString = true;
		else if (ch === "[") return refuse("too-deep", "");
		else if (ch === "{" && ++depth > 2) return refuse("too-deep", "");
		else if (ch === "}") depth--;
	}
	let raw: unknown;
	try { raw = JSON.parse(input); } catch { return refuse("not-json", ""); }
	if (!isRecord(raw)) return refuse("not-object", "");
	const errors: Issue[] = [];
	const colors = isRecord(raw.colors) ? raw.colors : {}, glass = isRecord(raw.glass) ? raw.glass : {};
	for (const [prefix, object, allowed] of [["", raw, ROOT_KEYS], ["colors.", colors, COLOR_KEYS], ["glass.", glass, GLASS_KEYS]] as const) {
		for (const key of Object.keys(object)) if (!(allowed as readonly string[]).includes(key)) errors.push({code: "unknown-key", path: prefix + plain(key)});
		for (const key of allowed) if (!Object.hasOwn(object, key)) errors.push({code: "missing-key", path: prefix + key});
	}
	if (errors.length > 0) return {ok: false, errors: errors.slice(0, MAX_ISSUES)};
	if (raw.format !== THEME_FORMAT) errors.push({code: "bad-value", path: "format"});
	if (raw.version !== 1) errors.push({code: "bad-value", path: "version"});
	if (typeof raw.name !== "string") errors.push({code: "bad-type", path: "name"});
	else if (raw.name.length > MAX_NAME || !/^[\p{L}\p{N}][\p{L}\p{N} _.-]*$/u.test(raw.name)) errors.push({code: "bad-value", path: "name"});
	if (raw.scheme !== "dark" && raw.scheme !== "light") errors.push({code: "bad-value", path: "scheme"});
	if (!isRecord(raw.colors)) errors.push({code: "bad-type", path: "colors"});
	if (!isRecord(raw.glass)) errors.push({code: "bad-type", path: "glass"});
	for (const [key, max] of [["tint", 1], ["blur", BLUR_MAX]] as const) {
		const value = glass[key];
		if (typeof value !== "number" || !Number.isFinite(value)) errors.push({code: "bad-type", path: "glass." + key});
		else if (value < 0 || value > max) errors.push({code: "bad-value", path: "glass." + key});
	}
	const p = {} as Palette;
	for (const key of COLOR_KEYS) {
		const parsed = parseHex(colors[key]);
		if (parsed) p[key] = parsed;
		else errors.push({code: typeof colors[key] === "string" ? "bad-color" : "bad-type", path: "colors." + key});
	}
	if (errors.length > 0) return {ok: false, errors: errors.slice(0, MAX_ISSUES)};
	if ((luminance(p.text) > luminance(p.surface)) !== (raw.scheme === "dark") || (luminance(p.text) > luminance(p.bg)) !== (raw.scheme === "dark")) return refuse("scheme-mismatch", "scheme");
	const corrections: Issue[] = [], blur = Math.round(glass.blur as number);
	for (const rule of RULES) {
		const path = "colors." + rule.fg;
		const worst = () => Math.min(...rule.on.flatMap(on => grounds(p, SOLID, blur, on, rule.fg)).map(g => contrast(p[rule.fg], g)));
		if (worst() >= rule.min) continue;
		if (worst() < rule.min * REFUSE_BELOW) {
			errors.push({code: "low-contrast", path});
			continue;
		}
		const start = p[rule.fg], pole = luminance(grounds(p, SOLID, blur, rule.on[0]!, rule.fg)[0]!) < 0.18 ? WHITE : BLACK;
		for (let step = 1; step <= 20 && worst() < rule.min; step++) p[rule.fg] = parseHex(toHex(mix(start, pole, step / 20))) ?? start;
		if (worst() < rule.min) errors.push({code: "low-contrast", path});
		else if (!corrections.some(c => c.path === path)) corrections.push({code: "ink-adjusted", path});
	}
	// A repair can move a status colour and with it the wash other text sits on, so the whole set is judged once more.
	for (const f of findings(p, SOLID, blur)) if (f.ratio < f.min && !errors.some(e => e.path === "colors." + f.fg)) errors.push({code: "low-contrast", path: "colors." + f.fg});
	// The backdrop colours, the surface colour and the tint are judged together here: the floor is the thinnest sheet this palette can read through over its own backdrop.
	const floor = minTint(p, blur);
	if (errors.length > 0 || floor === null) return {ok: false, errors: errors.slice(0, MAX_ISSUES)};
	if ((glass.tint as number) < floor) corrections.push({code: "tint-raised", path: "glass.tint"});
	return {ok: true, corrections, theme: {
		format: THEME_FORMAT,
		version: 1,
		name: raw.name as string,
		scheme: raw.scheme as Theme["scheme"],
		colors: Object.fromEntries(COLOR_KEYS.map(k => [k, toHex(p[k]).toUpperCase()])) as Theme["colors"],
		glass: {tint: Math.round(Math.max(floor, glass.tint as number) * 100) / 100, blur}
	}};
}

export function serializeTheme(theme: Theme): string {
	return JSON.stringify({format: theme.format, version: theme.version, name: theme.name, scheme: theme.scheme, colors: Object.fromEntries(COLOR_KEYS.map(k => [k, theme.colors[k]])), glass: {tint: theme.glass.tint, blur: theme.glass.blur}}, null, "\t") + "\n";
}
