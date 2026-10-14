import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {THEME_FORMAT} from "../src/brand.ts";
import {BLUR_MAX, BUILTIN, COLOR_KEYS, MAX_BYTES, MAX_NAME, audit, glassTints, minTint, palette, serializeTheme, themeVars, validateTheme, type Theme} from "../src/theme/index.ts";

const read = (name: string) => readFileSync(new URL(name, import.meta.url), "utf8");
const dark = () => JSON.parse(serializeTheme(BUILTIN.dark)) as {[key: string]: any};
const codes = (input: unknown) => {
	const verdict = validateTheme(input);
	return verdict.ok ? [] : verdict.errors.map(e => e.code + " " + e.path);
};

test("the built-in themes are valid as they stand and survive export and import", () => {
	for (const theme of Object.values(BUILTIN)) {
		const verdict = validateTheme(serializeTheme(theme));
		assert.ok(verdict.ok, JSON.stringify(verdict));
		assert.deepEqual(verdict.corrections, []);
		assert.deepEqual(verdict.theme, theme);
	}
});

test("the hand-written hostile theme file is rejected", () => {
	const verdict = validateTheme(read("hostile.veilway-theme"));
	assert.equal(verdict.ok, false);
	assert.ok(!verdict.ok && verdict.errors.length > 0);
	assert.equal(({} as {polluted?: boolean}).polluted, undefined);
});

// One attack at a time on an otherwise valid theme, so no attack hides behind another one's refusal.
const attacks: [string, (t: {[key: string]: any}) => void, string][] = [
	["CSS injection after a colour", t => { t.colors.bg = "#101010; background-image: url(https://collect.example.net/a.png)"; }, "bad-color colors.bg"],
	["a rule break out of the declaration", t => { t.colors.success = "#84DBB4}*{display:none"; }, "bad-color colors.success"],
	["url( as a colour", t => { t.colors.field1 = "url(https://collect.example.net/b.png)"; }, "bad-color colors.field1"],
	["expression( as a colour", t => { t.colors.field2 = "expression(alert(1))"; }, "bad-color colors.field2"],
	["var() as a colour", t => { t.colors.sunken = "var(--c-text)"; }, "bad-color colors.sunken"],
	["a colour function", t => { t.colors.text = "rgb(240 247 244)"; }, "bad-color colors.text"],
	["a colour name", t => { t.colors.accent = "red"; }, "bad-color colors.accent"],
	["a short hex", t => { t.colors.line = "#222"; }, "bad-color colors.line"],
	["a hex with alpha", t => { t.colors.lineStrong = "#22222222"; }, "bad-color colors.lineStrong"],
	["a comment opener after a colour", t => { t.colors.chart1 = "#5CC79B/*"; }, "bad-color colors.chart1"],
	["a NUL after a colour", t => { t.colors.warning = "#F0C465\u0000"; }, "bad-color colors.warning"],
	["a leading space", t => { t.colors.danger = " #FFA596"; }, "bad-color colors.danger"],
	["a trailing newline", t => { t.colors.danger = "#FFA596\n"; }, "bad-color colors.danger"],
	["a number as a colour", t => { t.colors.onAccent = 16777215; }, "bad-type colors.onAccent"],
	["null as a colour", t => { t.colors.focus = null; }, "bad-type colors.focus"],
	["an object as a colour", t => { t.colors.info = {hex: "#A9C1FB"}; }, "too-deep "],
	["an array as a colour", t => { t.colors.accentInk = ["#84DBB4"]; }, "too-deep "],
	["an unknown colour key", t => { t.colors.extra = "#FFFFFF"; }, "unknown-key colors.extra"],
	["a font key", t => { t.font = "url(https://collect.example.net/font.woff2)"; }, "unknown-key font"],
	["a css key", t => { t.css = "body{background:url(https://collect.example.net/beacon.gif)}"; }, "unknown-key css"],
	["an image in glass", t => { t.glass.image = "data:image/svg+xml,<svg onload=alert(1)>"; }, "unknown-key glass.image"],
	["a missing colour", t => { delete t.colors.focus; }, "missing-key colors.focus"],
	["markup in the name", t => { t.name = "Free</style><script>alert(1)</script>"; }, "bad-value name"],
	["a bidi override in the name", t => { t.name = "safe‮emeht"; }, "bad-value name"],
	["a name that is too long", t => { t.name = "a".repeat(MAX_NAME + 1); }, "bad-value name"],
	["a name that is not text", t => { t.name = 7; }, "bad-type name"],
	["the version as text", t => { t.version = "1"; }, "bad-value version"],
	["another format", t => { t.format = "other-theme"; }, "bad-value format"],
	["a third scheme", t => { t.scheme = "sepia"; }, "bad-value scheme"],
	["the tint as text", t => { t.glass.tint = "0.5"; }, "bad-type glass.tint"],
	["a tint above one", t => { t.glass.tint = 1.5; }, "bad-value glass.tint"],
	["a negative blur", t => { t.glass.blur = -4; }, "bad-value glass.blur"],
	["a blur beyond the cap", t => { t.glass.blur = BLUR_MAX + 1; }, "bad-value glass.blur"],
	["colors as text", t => { t.colors = "#FFFFFF"; }, "missing-key colors.bg"],
	["near-invisible text", t => { t.colors.text = "#1C3C40"; }, "low-contrast colors.text"],
	["near-invisible secondary text", t => { t.colors.textMuted = "#1F4044"; }, "low-contrast colors.textMuted"],
	["an unreadable primary button", t => { t.colors.onAccent = "#2A8062"; }, "low-contrast colors.onAccent"],
	["light colours declared as dark", t => { Object.assign(t.colors, BUILTIN.light.colors); }, "scheme-mismatch scheme"]
];
for (const [name, mutate, expected] of attacks) test("refused: " + name, () => {
	const theme = dark();
	mutate(theme);
	assert.ok(codes(JSON.stringify(theme)).includes(expected), codes(JSON.stringify(theme)).join(", ") || "accepted");
});

test("refused: input that is not a theme document at all", () => {
	assert.deepEqual(codes(undefined), ["not-text "]);
	assert.deepEqual(codes(dark()), ["not-text "]);
	assert.deepEqual(codes(""), ["not-json "]);
	assert.deepEqual(codes("{\"format\":"), ["not-json "]);
	assert.deepEqual(codes("null"), ["not-object "]);
	assert.deepEqual(codes("\"#FFFFFF\""), ["not-object "]);
	assert.deepEqual(codes("[]"), ["too-deep "]);
	assert.deepEqual(codes("﻿" + serializeTheme(BUILTIN.dark)), ["not-json "]);
});

test("refused: oversized files, counted in bytes", () => {
	assert.deepEqual(codes(serializeTheme(BUILTIN.dark) + " ".repeat(MAX_BYTES)), ["too-large "]);
	const persian = JSON.stringify({...dark(), note: "س".repeat(MAX_BYTES / 2)});
	assert.ok(persian.length < MAX_BYTES);
	assert.deepEqual(codes(persian), ["too-large "]);
	assert.deepEqual(codes("a".repeat(50_000_000)), ["too-large "]);
});

test("refused: deep nesting, without recursing into it", () => {
	assert.deepEqual(codes("[".repeat(8000) + "]".repeat(8000)), ["too-deep "]);
	assert.deepEqual(codes("{\"a\":".repeat(2000) + "1" + "}".repeat(2000)), ["too-deep "]);
	assert.deepEqual(codes(JSON.stringify({...dark(), glass: {tint: {value: {deeper: 0.5}}, blur: 24}})), ["too-deep "]);
});

test("refused: numbers JSON can write but a theme cannot use", () => {
	assert.ok(codes(serializeTheme(BUILTIN.dark).replace("\"blur\": 28", "\"blur\": 1e999")).includes("bad-type glass.blur"));
	assert.ok(codes(serializeTheme(BUILTIN.dark).replace("\"tint\": 0.36", "\"tint\": -0")).length === 0);
});

test("a __proto__ key is refused and pollutes nothing", () => {
	const text = serializeTheme(BUILTIN.dark).replace("{", "{\"__proto__\": {\"polluted\": true},");
	assert.ok(codes(text).includes("unknown-key __proto__"));
	assert.equal(({} as {polluted?: boolean}).polluted, undefined);
});

test("slightly weak text is repaired and reported, not passed through", () => {
	const theme = dark();
	theme.colors.textMuted = "#C4D6D1";
	const verdict = validateTheme(JSON.stringify(theme));
	assert.ok(verdict.ok, JSON.stringify(verdict));
	assert.ok(verdict.corrections.some(c => c.code === "ink-adjusted" && c.path === "colors.textMuted"));
	assert.notEqual(verdict.theme.colors.textMuted, "#C4D6D1");
	for (const f of audit(palette(verdict.theme), verdict.theme.glass.tint, verdict.theme.glass.blur)) assert.ok(f.ratio >= f.min, f.fg + " on " + f.on + " " + f.ratio.toFixed(2));
});

test("a tint too thin to read through is raised to the lowest readable one", () => {
	for (const scheme of ["dark", "light"] as const) {
		const theme = JSON.parse(serializeTheme(BUILTIN[scheme])) as Theme;
		theme.glass.tint = 0.05;
		const verdict = validateTheme(JSON.stringify(theme));
		assert.ok(verdict.ok, JSON.stringify(verdict));
		assert.deepEqual(verdict.corrections, [{code: "tint-raised", path: "glass.tint"}]);
		assert.equal(verdict.theme.glass.tint, minTint(palette(BUILTIN[scheme]), BUILTIN[scheme].glass.blur));
		for (const f of audit(palette(verdict.theme), verdict.theme.glass.tint, verdict.theme.glass.blur)) assert.ok(f.ratio >= f.min, f.fg + " on " + f.on);
	}
});

// The backdrop colours and the tint are judged together: the same tint that is fine over a dim backdrop is too thin over a brighter one.
test("a brighter backdrop needs denser glass, and gets it", () => {
	const theme = dark();
	theme.colors.field1 = "#124A3B";
	theme.colors.field2 = "#1C2B66";
	const floor = minTint(palette(theme as unknown as Theme), theme.glass.blur)!;
	theme.glass.tint = floor;
	assert.deepEqual(validateTheme(JSON.stringify(theme)), {ok: true, corrections: [], theme});
	theme.colors.field1 = BUILTIN.dark.colors.field1;
	theme.colors.field2 = BUILTIN.dark.colors.field2;
	const verdict = validateTheme(JSON.stringify(theme));
	assert.ok(verdict.ok, JSON.stringify(verdict));
	assert.deepEqual(verdict.corrections, [{code: "tint-raised", path: "glass.tint"}]);
	assert.ok(verdict.theme.glass.tint > floor, verdict.theme.glass.tint + " is not above " + floor);
	for (const f of audit(palette(verdict.theme), verdict.theme.glass.tint, verdict.theme.glass.blur)) assert.ok(f.ratio >= f.min, f.fg + " on " + f.on + " " + f.ratio.toFixed(2));
});

test("refused: a backdrop so bright that text set straight on it cannot be read", () => {
	const theme = dark();
	theme.colors.field1 = "#9FF0D2";
	assert.ok(codes(JSON.stringify(theme)).some(code => code.startsWith("low-contrast colors.text")), codes(JSON.stringify(theme)).join(", ") || "accepted");
	const pale = JSON.parse(serializeTheme(BUILTIN.light)) as Theme;
	pale.colors.field2 = "#16224F";
	assert.ok(codes(JSON.stringify(pale)).some(code => code.startsWith("low-contrast colors.text")), codes(JSON.stringify(pale)).join(", ") || "accepted");
});

test("a theme without blur loads, and its floating layers turn denser", () => {
	for (const scheme of ["dark", "light"] as const) {
		const theme = JSON.parse(serializeTheme(BUILTIN[scheme])) as Theme;
		theme.glass.blur = 0;
		const verdict = validateTheme(JSON.stringify(theme));
		assert.ok(verdict.ok, JSON.stringify(verdict));
		const tints = glassTints(palette(verdict.theme), verdict.theme.glass.tint, 0);
		assert.ok(tints.float >= glassTints(palette(BUILTIN[scheme]), BUILTIN[scheme].glass.tint, BUILTIN[scheme].glass.blur).float + 0.1, "float is " + tints.float);
		assert.equal(themeVars(verdict.theme)["--glass-tint-float"], String(tints.float));
	}
});

// Files written for the first material, which kept every pane at tint 0.78 and had dimmer glows behind it. The format has not changed, so they load; where the new, brighter backdrop leaves secondary text short, the text is repaired and the file says so.
test("theme files from before the thinner glass still load", () => {
	const before = {dark: {bg: "#14353A", field1: "#1F6E58", field2: "#2C4391", surface: "#0F2327", sunken: "#0A1A1C", text: "#F0F7F4", textMuted: "#C4D6D1", line: "#2C4A4C", lineStrong: "#7A9893", accent: "#22795A", onAccent: "#F1F8F4", accentInk: "#8FE0BC", info: "#B7CBFC", success: "#8FE0BC", warning: "#F2CC78", danger: "#FFB5A8", chart1: "#3BA87D", chart2: "#6E8CE2", focus: "#C6D5FF"}, light: {bg: "#DCE7E3", field1: "#A6D8C1", field2: "#B4C6F0", surface: "#FBFDFC", sunken: "#EDF3F0", text: "#0E1D1A", textMuted: "#364843", line: "#C3D2CC", lineStrong: "#667D75", accent: "#22795A", onAccent: "#F1F8F4", accentInk: "#125540", info: "#244592", success: "#125540", warning: "#6B4400", danger: "#96221A", chart1: "#1B8C63", chart2: "#3B66C4", focus: "#244592"}};
	for (const scheme of ["dark", "light"] as const) {
		const verdict = validateTheme(JSON.stringify({...dark(), name: "Older file", scheme, colors: before[scheme], glass: {tint: 0.78, blur: 24}}));
		assert.ok(verdict.ok, JSON.stringify(verdict));
		assert.deepEqual(verdict.theme.glass, {tint: 0.78, blur: 24});
		assert.ok(verdict.corrections.every(c => c.code === "ink-adjusted"), JSON.stringify(verdict.corrections));
		for (const f of audit(palette(verdict.theme), verdict.theme.glass.tint, verdict.theme.glass.blur)) assert.ok(f.ratio >= f.min, f.fg + " on " + f.on + " " + f.ratio.toFixed(2));
	}
});

test("only parsed values reach CSS", () => {
	const verdict = validateTheme(serializeTheme(BUILTIN.light).replaceAll("#0F4E3A", "#0f4e3b"));
	assert.ok(verdict.ok);
	for (const [name, value] of Object.entries(themeVars(verdict.theme))) {
		assert.match(name, /^--[a-z0-9-]+$/);
		assert.match(value, /^(#[0-9a-f]{6}|\d+(\.\d+)?|\d+px)$/);
	}
	assert.throws(() => themeVars({...BUILTIN.dark, colors: {...BUILTIN.dark.colors, bg: "red;}"}}));
	assert.equal(themeVars({...BUILTIN.dark, glass: {tint: "1;x" as unknown as number, blur: "9px;x" as unknown as number}})["--glass-blur"], "0px");
});

test("the JSON Schema and the validator describe the same file", () => {
	const schema = JSON.parse(read("../schema/veilway-theme.schema.json"));
	assert.equal(schema.additionalProperties, false);
	assert.equal(schema.properties.colors.additionalProperties, false);
	assert.equal(schema.properties.glass.additionalProperties, false);
	assert.deepEqual(schema.properties.colors.required, [...COLOR_KEYS]);
	assert.deepEqual(Object.keys(schema.properties.colors.properties), [...COLOR_KEYS]);
	assert.deepEqual(schema.required, Object.keys(dark()));
	assert.deepEqual(Object.keys(schema.properties), Object.keys(dark()));
	assert.deepEqual(Object.keys(schema.properties.glass.properties), Object.keys(dark().glass));
	assert.equal(schema.properties.format.const, THEME_FORMAT);
	assert.equal(schema.properties.name.maxLength, MAX_NAME);
	assert.equal(schema.properties.glass.properties.blur.maximum, BLUR_MAX);
	assert.equal(schema.$defs.color.pattern, "^#[0-9a-fA-F]{6}$");
	assert.ok(schema.description.includes(String(MAX_BYTES)));
});
