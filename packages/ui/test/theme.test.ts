import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {THEME_FORMAT} from "../src/brand.ts";
import {BLUR_MAX, BUILTIN, COLOR_KEYS, MAX_BYTES, MAX_NAME, audit, minTint, palette, serializeTheme, themeVars, validateTheme, type Theme} from "../src/theme/index.ts";

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
	["a rule break out of the declaration", t => { t.colors.protected = "#84DBB4}*{display:none"; }, "bad-color colors.protected"],
	["url( as a colour", t => { t.colors.field1 = "url(https://collect.example.net/b.png)"; }, "bad-color colors.field1"],
	["expression( as a colour", t => { t.colors.field2 = "expression(alert(1))"; }, "bad-color colors.field2"],
	["var() as a colour", t => { t.colors.sunken = "var(--c-text)"; }, "bad-color colors.sunken"],
	["a colour function", t => { t.colors.text = "rgb(240 247 244)"; }, "bad-color colors.text"],
	["a colour name", t => { t.colors.accent = "red"; }, "bad-color colors.accent"],
	["a short hex", t => { t.colors.line = "#222"; }, "bad-color colors.line"],
	["a hex with alpha", t => { t.colors.lineStrong = "#22222222"; }, "bad-color colors.lineStrong"],
	["a comment opener after a colour", t => { t.colors.chart1 = "#5CC79B/*"; }, "bad-color colors.chart1"],
	["a NUL after a colour", t => { t.colors.detectable = "#F0C465\u0000"; }, "bad-color colors.detectable"],
	["a leading space", t => { t.colors.unsafe = " #FFA596"; }, "bad-color colors.unsafe"],
	["a trailing newline", t => { t.colors.unsafe = "#FFA596\n"; }, "bad-color colors.unsafe"],
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
	assert.ok(codes(serializeTheme(BUILTIN.dark).replace("\"blur\": 24", "\"blur\": 1e999")).includes("bad-type glass.blur"));
	assert.ok(codes(serializeTheme(BUILTIN.dark).replace("\"tint\": 0.78", "\"tint\": -0")).length === 0);
});

test("a __proto__ key is refused and pollutes nothing", () => {
	const text = serializeTheme(BUILTIN.dark).replace("{", "{\"__proto__\": {\"polluted\": true},");
	assert.ok(codes(text).includes("unknown-key __proto__"));
	assert.equal(({} as {polluted?: boolean}).polluted, undefined);
});

test("slightly weak text is repaired and reported, not passed through", () => {
	const theme = dark();
	theme.colors.textMuted = "#A3B8B3";
	const verdict = validateTheme(JSON.stringify(theme));
	assert.ok(verdict.ok, JSON.stringify(verdict));
	assert.ok(verdict.corrections.some(c => c.code === "ink-adjusted" && c.path === "colors.textMuted"));
	assert.notEqual(verdict.theme.colors.textMuted, "#A3B8B3");
	for (const f of audit(palette(verdict.theme), verdict.theme.glass.tint)) assert.ok(f.ratio >= f.min, f.fg + " on " + f.on + " " + f.ratio.toFixed(2));
});

test("a tint too thin to read through is raised to the lowest readable one", () => {
	for (const scheme of ["dark", "light"] as const) {
		const theme = JSON.parse(serializeTheme(BUILTIN[scheme])) as Theme;
		theme.glass.tint = 0.05;
		const verdict = validateTheme(JSON.stringify(theme));
		assert.ok(verdict.ok, JSON.stringify(verdict));
		assert.deepEqual(verdict.corrections, [{code: "tint-raised", path: "glass.tint"}]);
		assert.equal(verdict.theme.glass.tint, minTint(palette(BUILTIN[scheme])));
		for (const f of audit(palette(verdict.theme), verdict.theme.glass.tint)) assert.ok(f.ratio >= f.min, f.fg + " on " + f.on);
	}
});

test("only parsed values reach CSS", () => {
	const verdict = validateTheme(serializeTheme(BUILTIN.light).replaceAll("#125540", "#12554a"));
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
