import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {BUILTIN, RULES, audit, builtinCss, minTint, palette} from "../src/theme/index.ts";

for (const theme of Object.values(BUILTIN)) test("every text and surface pair of the " + theme.scheme + " scheme meets its contrast minimum", t => {
	const p = palette(theme), floor = minTint(p);
	assert.ok(floor !== null && floor <= theme.glass.tint, "the shipped tint " + theme.glass.tint + " is under the lowest readable tint " + floor);
	// Glass pairs are judged at the lowest tint a theme may use, over pure black and pure white. Solid pairs do not depend on the tint.
	const findings = audit(p, floor);
	assert.equal(findings.length, RULES.reduce((n, rule) => n + rule.on.length, 0));
	for (const f of findings) {
		t.diagnostic(f.fg.padEnd(11) + " on " + f.on.padEnd(8) + f.ratio.toFixed(2).padStart(6) + "  (min " + f.min + (f.on === "glass" ? ", tint " + floor : "") + ")");
		assert.ok(f.ratio >= f.min, theme.scheme + ": " + f.fg + " on " + f.on + " is " + f.ratio.toFixed(2) + ", needs " + f.min);
	}
	assert.ok(audit(p, floor - 0.02).some(f => f.ratio < f.min), "the floor is not the lowest readable tint");
});

test("colors.css is what the token source generates", () => {
	assert.equal(readFileSync(new URL("../src/styles/colors.css", import.meta.url), "utf8"), builtinCss(), "run npm run tokens");
});
