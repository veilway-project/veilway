import {THEME_FORMAT} from "../brand.ts";
import {BLACK, WHITE, contrast, mix, parseHex, saturate, type Rgb} from "./color.ts";

export const COLOR_KEYS = ["bg", "field1", "field2", "surface", "sunken", "text", "textMuted", "line", "lineStrong", "accent", "onAccent", "accentInk", "info", "success", "warning", "danger", "chart1", "chart2", "focus"] as const;
export type ColorKey = typeof COLOR_KEYS[number];
export type Scheme = "dark" | "light";
export type Theme = {format: typeof THEME_FORMAT, version: 1, name: string, scheme: Scheme, colors: Record<ColorKey, string>, glass: {tint: number, blur: number}};
export type Palette = Record<ColorKey, Rgb>;

export const MAX_BYTES = 16384;
export const MAX_NAME = 40;
export const BLUR_MAX = 40;
export const DEFAULT_BLUR = 28;
// How much of a status colour is mixed into the surface behind a badge or banner of that status.
export const WASH_STRENGTH = 0.14;
export const TEXT_MIN = 4.5;
export const MARK_MIN = 3;
// The material as numbers. colors.css hands them to the stylesheet and the contrast rules below use the same values, so what is painted and what is checked cannot drift apart.
export const MATERIAL = {
	// Strongest opacity of the two glows and of the light shafts over the page background. A shaft is the first glow colour mixed with white.
	glow1: 0.8,
	glow2: 0.8,
	shaft: 0.2,
	shaftWhite: 0.6,
	// What the glass does to the picture behind it, and the most light and shade its own surface gradient, edge and grain add on top.
	saturate: 1.5,
	sheen: 0.06,
	shade: 0.05,
	// Opacity of the sunken colour in a well cut into glass, and of the scrim under a dialog.
	well: 0.55,
	scrim: 0.5,
	// Text and thin marks that pass under a floating layer are smeared by the blur: at inkBlur pixels or more they cover at most this share of what the layer sees. With less blur they count for more, and with none in full.
	inkCoverage: 0.5,
	inkBlur: 16,
	// A layer that floats over content is at least this much denser than a sheet that rests on the backdrop.
	floatStep: 0.24,
	thickStep: 0.4
} as const;
// The share of the page background in the colour of shadows and of the scrim under a dialog; the rest is black.
export const SHADOW_INK = 0.35;

// Where a foreground may sit. "field" is the bare backdrop. The three glass grounds differ in what can be behind them: "glass" is a sheet resting on the backdrop, "float" is navigation or a tooltip with live content passing under it, "thick" is a dialog, menu or toast, which can also sit over the dimmed page. "well" is a recess cut into a sheet or a dialog.
export type Ground = "bg" | "field" | "surface" | "sunken" | "accent" | "wash" | "glass" | "float" | "thick" | "well";
export type Pane = "glass" | "float" | "thick";
export type Tints = Record<Pane, number>;
// Every pair of a foreground token and the grounds it is allowed to sit on. The stylesheets may not use a pair that is missing here: status colours and chart marks are not allowed on a bare sheet and get a wash or a well instead.
export const RULES: {fg: ColorKey, on: Ground[], min: number}[] = [
	{fg: "text", on: ["bg", "field", "surface", "sunken", "glass", "float", "thick", "well", "wash"], min: TEXT_MIN},
	{fg: "textMuted", on: ["bg", "field", "surface", "sunken", "glass", "float", "thick", "well"], min: TEXT_MIN},
	{fg: "onAccent", on: ["accent"], min: TEXT_MIN},
	{fg: "accentInk", on: ["bg", "surface", "sunken", "glass", "float", "thick", "well"], min: TEXT_MIN},
	{fg: "info", on: ["surface", "wash", "well", "thick"], min: TEXT_MIN},
	{fg: "success", on: ["surface", "wash", "well", "thick"], min: TEXT_MIN},
	{fg: "warning", on: ["surface", "wash", "well", "thick"], min: TEXT_MIN},
	{fg: "danger", on: ["surface", "wash", "well", "thick"], min: TEXT_MIN},
	// As icons and edges only, never as text: an error mark beside a field, the border of an invalid input.
	{fg: "info", on: ["glass", "float"], min: MARK_MIN},
	{fg: "success", on: ["glass", "float"], min: MARK_MIN},
	{fg: "warning", on: ["glass", "float"], min: MARK_MIN},
	{fg: "danger", on: ["glass", "float"], min: MARK_MIN},
	{fg: "lineStrong", on: ["bg", "surface", "sunken", "glass", "thick"], min: MARK_MIN},
	{fg: "focus", on: ["bg", "field", "surface", "sunken", "glass", "float", "thick"], min: MARK_MIN},
	{fg: "chart1", on: ["surface", "well"], min: MARK_MIN},
	{fg: "chart2", on: ["surface", "well"], min: MARK_MIN}
];
const STATUS: ColorKey[] = ["info", "success", "warning", "danger"];
// Tokens that are painted as text or thin marks, and so reach a floating layer only smeared.
const INKS: ColorKey[] = ["text", "onAccent", "lineStrong", "info", "success", "warning", "danger", "chart1", "chart2"];

// How strong the two glows can be at one point, as shares of their full strength. They are painted in opposite corners of the backdrop and each has faded out before the other passes half; material.css keeps to that.
const GLOWS = [[0, 0], [0.5, 0], [1, 0], [0, 0.5], [0, 1], [0.5, 0.5]] as const;

// Every colour the backdrop can show: the page background under the glows, with and without a light shaft across it. Half steps are in because luminance is not linear along a mix.
export function backdrop(p: Palette): Rgb[] {
	const shaft = mix(p.field1, WHITE, MATERIAL.shaftWhite);
	return GLOWS.map(([one, two]) => mix(mix(p.bg, p.field2, MATERIAL.glow2 * two), p.field1, MATERIAL.glow1 * one)).flatMap(c => [c, mix(c, shaft, MATERIAL.shaft / 2), mix(c, shaft, MATERIAL.shaft)]);
}

// The colours one pane of glass can take: what can be behind it, as it is and saturated, under the scrim of the surface colour, at the lightest and darkest point of the pane's own gradient. Blur only averages what is behind, so it cannot leave this range.
function pane(p: Palette, on: Pane, tint: number, blur: number): Rgb[] {
	const cover = 1 - (1 - MATERIAL.inkCoverage) * Math.min(1, blur / MATERIAL.inkBlur);
	const content = on === "glass" ? [] : [p.surface, p.sunken, p.accent, ...INKS.flatMap(k => [mix(p.surface, p[k], cover), mix(p.bg, p[k], cover)])];
	const behind = [...backdrop(p), ...content], dimmed = on === "thick" ? behind.map(c => mix(c, mix(BLACK, p.bg, SHADOW_INK), MATERIAL.scrim)) : [];
	return [...behind, ...dimmed].flatMap(c => [c, saturate(c, MATERIAL.saturate)]).map(c => mix(c, p.surface, tint)).flatMap(c => [mix(c, WHITE, MATERIAL.sheen), mix(c, BLACK, MATERIAL.shade)]);
}

// The colours a ground can take behind a given foreground.
export function grounds(p: Palette, tints: Tints, blur: number, on: Ground, fg: ColorKey): Rgb[] {
	if (on === "field") return backdrop(p);
	if (on === "wash") return (STATUS.includes(fg) ? [fg] : STATUS).map(k => mix(p.surface, p[k], WASH_STRENGTH));
	if (on === "glass" || on === "float" || on === "thick") return pane(p, on, tints[on], blur);
	if (on === "well") return [...pane(p, "glass", tints.glass, blur), ...pane(p, "thick", tints.thick, blur), p.surface].map(c => mix(c, p.sunken, MATERIAL.well));
	return [p[on]];
}

export type Finding = {fg: ColorKey, on: Ground, ratio: number, min: number};

// The worst contrast of every allowed pair at the given tints. The validator and the floors below call it directly; everything else goes through audit.
export function findings(p: Palette, tints: Tints, blur: number): Finding[] {
	return RULES.flatMap(rule => rule.on.map(on => ({fg: rule.fg, on, min: rule.min, ratio: Math.min(...grounds(p, tints, blur, on, rule.fg).map(g => contrast(p[rule.fg], g)))})));
}

// The lowest tint at which everything allowed on one kind of pane passes while the other two are solid, or null when even a solid surface fails.
function floor(p: Palette, on: Pane, blur: number): number | null {
	const passes = (step: number) => findings(p, {glass: 1, float: 1, thick: 1, [on]: step / 100}, blur).every(f => f.ratio >= f.min);
	if (!passes(100)) return null;
	let low = 0, high = 100;
	while (low < high) {
		const middle = Math.floor((low + high) / 2);
		if (passes(middle)) high = middle;
		else low = middle + 1;
	}
	return low / 100;
}

// The lowest tint a theme with this palette may ask for: the thinnest sheet through which all text on it still reads over the theme's own backdrop.
export function minTint(p: Palette, blur = DEFAULT_BLUR): number | null {
	return floor(p, "glass", blur);
}

// The tint of each kind of pane for a theme's tint and blur. Floating and thick panes are a fixed step denser than a sheet and never thinner than their own worst case needs, which depends on the blur.
export function glassTints(p: Palette, tint: number, blur = DEFAULT_BLUR): Tints {
	return {glass: tint, float: Math.max(Math.min(1, Math.round((tint + MATERIAL.floatStep) * 100) / 100), floor(p, "float", blur) ?? 1), thick: Math.max(Math.min(1, Math.round((tint + MATERIAL.thickStep) * 100) / 100), floor(p, "thick", blur) ?? 1)};
}

export function audit(p: Palette, tint: number, blur = DEFAULT_BLUR): Finding[] {
	return findings(p, glassTints(p, tint, blur), blur);
}

export function palette(theme: Theme): Palette {
	return Object.fromEntries(COLOR_KEYS.map(k => [k, parseHex(theme.colors[k]) ?? BLACK])) as Palette;
}

export const DARK: Theme = {
	format: THEME_FORMAT,
	version: 1,
	name: "Night glass",
	scheme: "dark",
	colors: {bg: "#091C22", field1: "#1A6652", field2: "#283B88", surface: "#11282E", sunken: "#06161A", text: "#F0F7F4", textMuted: "#D3E2DD", line: "#274447", lineStrong: "#A2BBB6", accent: "#22795A", onAccent: "#F1F8F4", accentInk: "#9AE6C5", info: "#B7CBFC", success: "#9AE6C5", warning: "#F2CC78", danger: "#FFA086", chart1: "#3BA87D", chart2: "#6E8CE2", focus: "#C6D5FF"},
	glass: {tint: 0.36, blur: 28}
};

export const LIGHT: Theme = {
	format: THEME_FORMAT,
	version: 1,
	name: "Day glass",
	scheme: "light",
	colors: {bg: "#CADDD6", field1: "#6FC4A4", field2: "#67B6C4", surface: "#FBFDFC", sunken: "#EDF3F0", text: "#0E1D1A", textMuted: "#2D3E39", line: "#C3D2CC", lineStrong: "#50665F", accent: "#22795A", onAccent: "#F1F8F4", accentInk: "#0F4E3A", info: "#244592", success: "#0F4E3A", warning: "#6B4400", danger: "#96221A", chart1: "#1B8C63", chart2: "#3B66C4", focus: "#244592"},
	glass: {tint: 0.36, blur: 28}
};

export const BUILTIN: Record<Scheme, Theme> = {dark: DARK, light: LIGHT};
