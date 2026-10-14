import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {BUILTIN, MATERIAL, RULES, audit, backdrop, builtinCss, findings, glassTints, luminance, minTint, palette, themeVars} from "../src/theme/index.ts";

for (const theme of Object.values(BUILTIN)) test("every text and surface pair of the " + theme.scheme + " scheme meets its contrast minimum", t => {
	const p = palette(theme), floor = minTint(p, theme.glass.blur), tints = glassTints(p, theme.glass.tint, theme.glass.blur), lums = backdrop(p).map(luminance);
	assert.ok(floor !== null && floor <= theme.glass.tint, "the shipped tint " + theme.glass.tint + " is under the lowest readable tint " + floor);
	t.diagnostic("backdrop luminance " + Math.min(...lums).toFixed(3) + " to " + Math.max(...lums).toFixed(3) + ", tints sheet " + tints.glass + " chrome " + tints.float + " popover and dialog " + tints.thick + ", thinnest sheet allowed " + floor);
	// Glass pairs are judged at the tints the theme ships with, over every colour the theme can put behind each kind of pane. Solid pairs do not depend on the tint.
	const shipped = audit(p, theme.glass.tint, theme.glass.blur);
	assert.equal(shipped.length, RULES.reduce((n, rule) => n + rule.on.length, 0));
	for (const f of shipped) {
		t.diagnostic(f.fg.padEnd(11) + " on " + f.on.padEnd(8) + f.ratio.toFixed(2).padStart(6) + "  (min " + f.min + ")");
		assert.ok(f.ratio >= f.min, theme.scheme + ": " + f.fg + " on " + f.on + " is " + f.ratio.toFixed(2) + ", needs " + f.min);
	}
	// The same holds at the thinnest sheet the validator lets a theme with this palette ask for, and stops holding just under it.
	for (const f of audit(p, floor, theme.glass.blur)) assert.ok(f.ratio >= f.min, theme.scheme + " at the floor: " + f.fg + " on " + f.on + " is " + f.ratio.toFixed(2));
	if (floor > 0.02) assert.ok(audit(p, floor - 0.02, theme.glass.blur).some(f => f.ratio < f.min), "the floor is not the lowest readable tint");
	// And with every pane solid, which is what the solid setting and reduced transparency show.
	for (const f of findings(p, {glass: 1, float: 1, thick: 1}, theme.glass.blur)) assert.ok(f.ratio >= f.min, theme.scheme + " solid: " + f.fg + " on " + f.on + " is " + f.ratio.toFixed(2));
});

test("the built-in glass is glass: a sheet lets more than half of the backdrop through", () => {
	for (const theme of Object.values(BUILTIN)) assert.ok(theme.glass.tint <= 0.45, theme.scheme + " ships tint " + theme.glass.tint);
});

test("a layer that floats over content is never thinner than a sheet, and less blur makes it denser", () => {
	for (const theme of Object.values(BUILTIN)) {
		const p = palette(theme), wide = glassTints(p, theme.glass.tint, theme.glass.blur), none = glassTints(p, theme.glass.tint, 0);
		assert.ok(wide.glass < wide.float && wide.float <= wide.thick, JSON.stringify(wide));
		assert.ok(wide.float >= theme.glass.tint + MATERIAL.floatStep - 0.001 && wide.thick >= Math.min(1, theme.glass.tint + MATERIAL.thickStep) - 0.001);
		// Without blur, text that passes under navigation is not smeared at all and counts in full, so navigation has to be much denser.
		assert.ok(none.float >= wide.float + 0.1, "float at blur 0 is " + none.float + ", with blur " + wide.float);
		for (const f of audit(p, theme.glass.tint, 0)) assert.ok(f.ratio >= f.min, theme.scheme + " with no blur: " + f.fg + " on " + f.on + " is " + f.ratio.toFixed(2));
		assert.equal(themeVars(theme)["--glass-tint-float"], String(wide.float));
		assert.equal(themeVars(theme)["--glass-tint-thick"], String(wide.thick));
	}
});

test("colors.css is what the token source generates", () => {
	assert.equal(readFileSync(new URL("../src/styles/colors.css", import.meta.url), "utf8"), builtinCss(), "run npm run tokens");
});

test("the stylesheet paints the material with the numbers the rules check", () => {
	const css = readFileSync(new URL("../src/styles/material.css", import.meta.url), "utf8") + readFileSync(new URL("../src/styles/surfaces.css", import.meta.url), "utf8"), generated = builtinCss();
	for (const name of ["--glow-1", "--glow-2", "--shaft", "--shaft-white", "--sheen", "--shade", "--well", "--scrim", "--glass-saturate", "--glass-tint-float", "--glass-tint-thick"]) {
		assert.ok(generated.includes("\t" + name + ": "), name + " is not generated");
		assert.ok(css.includes("var(" + name + ")"), name + " is not used by the stylesheet");
	}
	// No hand-written opacity for a glow, a shaft or the scrim: each one is the generated variable or a fraction of it.
	assert.equal(css.match(/var\(--c-field-[12]\) \d/g), null);
	assert.equal(css.match(/var\(--shaft-ink\) \d/g), null);
});
