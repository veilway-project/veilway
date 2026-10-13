import {THEME_FORMAT} from "../brand.ts";
import {BLACK, WHITE, contrast, mix, parseHex, type Rgb} from "./color.ts";

export const COLOR_KEYS = ["bg", "field1", "field2", "surface", "sunken", "text", "textMuted", "line", "lineStrong", "accent", "onAccent", "accentInk", "info", "protected", "detectable", "unsafe", "chart1", "chart2", "focus"] as const;
export type ColorKey = typeof COLOR_KEYS[number];
export type Scheme = "dark" | "light";
export type Theme = {format: typeof THEME_FORMAT, version: 1, name: string, scheme: Scheme, colors: Record<ColorKey, string>, glass: {tint: number, blur: number}};
export type Palette = Record<ColorKey, Rgb>;

export const MAX_BYTES = 16384;
export const MAX_NAME = 40;
export const BLUR_MAX = 40;
// How strongly the two backdrop glows are painted over the page background. The stylesheet and the contrast rules share it.
export const FIELD_STRENGTH = 0.55;
// How much of a status colour is mixed into the surface behind a badge or banner of that status.
export const WASH_STRENGTH = 0.14;
export const TEXT_MIN = 4.5;
export const MARK_MIN = 3;

export type Ground = "bg" | "field" | "surface" | "sunken" | "accent" | "wash" | "glass";
// Every pair of a foreground token and the grounds it is allowed to sit on. The stylesheets may not use a pair that is missing here.
export const RULES: {fg: ColorKey, on: Ground[], min: number}[] = [
	{fg: "text", on: ["bg", "field", "surface", "sunken", "glass"], min: TEXT_MIN},
	{fg: "textMuted", on: ["bg", "field", "surface", "sunken", "glass"], min: TEXT_MIN},
	{fg: "onAccent", on: ["accent"], min: TEXT_MIN},
	{fg: "accentInk", on: ["bg", "surface", "sunken", "glass"], min: TEXT_MIN},
	{fg: "info", on: ["surface", "wash", "glass"], min: TEXT_MIN},
	{fg: "protected", on: ["surface", "wash", "glass"], min: TEXT_MIN},
	{fg: "detectable", on: ["surface", "wash", "glass"], min: TEXT_MIN},
	{fg: "unsafe", on: ["surface", "wash", "glass"], min: TEXT_MIN},
	{fg: "text", on: ["wash"], min: TEXT_MIN},
	{fg: "lineStrong", on: ["bg", "surface", "sunken"], min: MARK_MIN},
	{fg: "focus", on: ["bg", "surface", "sunken"], min: MARK_MIN},
	{fg: "chart1", on: ["surface"], min: MARK_MIN},
	{fg: "chart2", on: ["surface"], min: MARK_MIN}
];
const STATUS: ColorKey[] = ["info", "protected", "detectable", "unsafe"];

// The colours a ground can take behind a given foreground. Glass is checked over pure black and pure white: whatever scrolls under it, blurred and saturated or not, stays between those two.
export function grounds(p: Palette, tint: number, on: Ground, fg: ColorKey): Rgb[] {
	if (on === "field") return [mix(p.bg, p.field1, FIELD_STRENGTH), mix(p.bg, p.field2, FIELD_STRENGTH)];
	if (on === "wash") return (STATUS.includes(fg) ? [fg] : STATUS).map(k => mix(p.surface, p[k], WASH_STRENGTH));
	if (on === "glass") return [mix(BLACK, p.surface, tint), mix(WHITE, p.surface, tint)];
	return [p[on]];
}

export type Finding = {fg: ColorKey, on: Ground, ratio: number, min: number};

export function audit(p: Palette, tint: number): Finding[] {
	return RULES.flatMap(rule => rule.on.map(on => ({fg: rule.fg, on, min: rule.min, ratio: Math.min(...grounds(p, tint, on, rule.fg).map(g => contrast(p[rule.fg], g)))})));
}

// The lowest glass tint at which every foreground allowed on glass still passes over both extremes, or null when even a solid surface fails.
export function minTint(p: Palette): number | null {
	for (let step = 30; step <= 100; step++) if (audit(p, step / 100).every(f => f.on !== "glass" || f.ratio >= f.min)) return step / 100;
	return null;
}

export function palette(theme: Theme): Palette {
	return Object.fromEntries(COLOR_KEYS.map(k => [k, parseHex(theme.colors[k]) ?? BLACK])) as Palette;
}

export const DARK: Theme = {
	format: THEME_FORMAT,
	version: 1,
	name: "Night glass",
	scheme: "dark",
	colors: {bg: "#14353A", field1: "#1F6E58", field2: "#2C4391", surface: "#0F2327", sunken: "#0A1A1C", text: "#F0F7F4", textMuted: "#C4D6D1", line: "#2C4A4C", lineStrong: "#7A9893", accent: "#22795A", onAccent: "#F1F8F4", accentInk: "#8FE0BC", info: "#B7CBFC", protected: "#8FE0BC", detectable: "#F2CC78", unsafe: "#FFB5A8", chart1: "#3BA87D", chart2: "#6E8CE2", focus: "#C6D5FF"},
	glass: {tint: 0.78, blur: 24}
};

export const LIGHT: Theme = {
	format: THEME_FORMAT,
	version: 1,
	name: "Day glass",
	scheme: "light",
	colors: {bg: "#DCE7E3", field1: "#A6D8C1", field2: "#B4C6F0", surface: "#FBFDFC", sunken: "#EDF3F0", text: "#0E1D1A", textMuted: "#364843", line: "#C3D2CC", lineStrong: "#667D75", accent: "#22795A", onAccent: "#F1F8F4", accentInk: "#125540", info: "#244592", protected: "#125540", detectable: "#6B4400", unsafe: "#96221A", chart1: "#1B8C63", chart2: "#3B66C4", focus: "#244592"},
	glass: {tint: 0.78, blur: 24}
};

export const BUILTIN: Record<Scheme, Theme> = {dark: DARK, light: LIGHT};
