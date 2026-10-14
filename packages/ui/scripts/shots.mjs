// Screenshots of the gallery for the visual gate: every page in dark and light, English and Persian, at desktop width and at 390px, plus a few states that need interaction. Run it in the Playwright container (see README.md). Playwright is not a dependency of this package; PW_HOME names a folder that has it installed.
import {mkdirSync} from "node:fs";
import {createRequire} from "node:module";

const {chromium} = createRequire((process.env.PW_HOME ?? process.cwd()) + "/")("playwright");
const base = process.env.BASE ?? "http://127.0.0.1:4173/", out = process.env.OUT ?? "shots", only = process.env.ONLY;
const problems = [];
mkdirSync(out, {recursive: true});
const browser = await chromium.launch();
const open = async (query, width, height, extra = {}) => {
	// One device pixel per CSS pixel throughout: the software renderer in the container leaves part of a backdrop blur undone at higher densities (a five-line page shows it), which a real GPU does not.
	const context = await browser.newContext({viewport: {width, height}, deviceScaleFactor: 1, ...extra}), page = await context.newPage();
	page.on("console", message => { if (message.type() === "error" || message.type() === "warning") problems.push(query + " console " + message.type() + ": " + message.text()); });
	page.on("pageerror", error => problems.push(query + " page error: " + error.message));
	page.on("request", request => { if (!request.url().startsWith(base) && !request.url().startsWith("data:") && !request.url().startsWith("blob:")) problems.push(query + " request left the origin: " + request.url()); });
	await page.goto(base + "?still=1&" + query, {waitUntil: "networkidle"});
	await page.evaluate(() => document.fonts.ready);
	return page;
};
for (const scheme of ["dark", "light"]) for (const lang of ["en", "fa"]) for (const [size, width, height] of [["desktop", 1440, 900], ["mobile", 390, 844]]) for (const name of ["use", "foundations", "components", "data", "themes"]) {
	if (only && !(scheme + "-" + lang + "-" + size + "-" + name).includes(only)) continue;
	const page = await open("page=" + name + "&scheme=" + scheme + "&lang=" + lang, width, height), tall = Math.min(8000, await page.evaluate(() => document.documentElement.scrollHeight));
	const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
	if (overflow > 0) problems.push(scheme + " " + lang + " " + size + " " + name + ": the page scrolls sideways by " + overflow + "px");
	// The backdrop is pinned to the viewport, so the whole page is shot through a viewport as tall as the page, not stitched.
	await page.setViewportSize({width, height: tall});
	await page.screenshot({path: out + "/" + [scheme, lang, size, name].join("-") + ".png"});
	await page.context().close();
}
if (!only) for (const lang of ["en", "fa"]) {
	const page = await open("page=components&scheme=dark&lang=" + lang, 1440, 900);
	for (let i = 0; i < 9; i++) await page.keyboard.press("Tab");
	await page.screenshot({path: out + "/state-" + lang + "-focus-ring.png"});
	await page.getByRole("combobox").first().click();
	await page.screenshot({path: out + "/state-" + lang + "-select-open.png"});
	await page.keyboard.press("Escape");
	await page.getByRole("button", {name: lang === "en" ? "Show subscription link" : "نمایش پیوند اشتراک"}).click();
	await page.waitForTimeout(400);
	await page.screenshot({path: out + "/state-" + lang + "-dialog.png"});
	await page.keyboard.press("Escape");
	await page.getByRole("button", {name: lang === "en" ? "Show an error toast" : "نمایش اعلان خطا"}).click();
	await page.waitForTimeout(400);
	await page.screenshot({path: out + "/state-" + lang + "-toast.png"});
	await page.getByRole("tab", {name: lang === "en" ? "Loading" : "در حال بارگذاری"}).click();
	await page.getByRole("tab", {name: lang === "en" ? "Loading" : "در حال بارگذاری"}).scrollIntoViewIfNeeded();
	await page.screenshot({path: out + "/state-" + lang + "-loading.png"});
	await page.context().close();
	for (const scheme of ["dark", "light"]) for (const link of ["off", "connecting"]) {
		const client = await open("page=use&scheme=" + scheme + "&lang=" + lang + "&link=" + link, 1440, 900);
		await client.locator(".g-window").screenshot({path: out + "/state-" + lang + "-" + scheme + "-client-" + link + ".png"});
		await client.context().close();
	}
	for (const scheme of ["dark", "light"]) {
		const client = await open("page=use&scheme=" + scheme + "&lang=" + lang, 1440, 900);
		await client.locator(".g-window").screenshot({path: out + "/state-" + lang + "-" + scheme + "-client-on.png"});
		// Content under the navigation bar: the layer that has text passing beneath it.
		await client.locator(".g-scroll").evaluate(el => el.scrollTo(0, 150));
		await client.locator(".g-window").screenshot({path: out + "/state-" + lang + "-" + scheme + "-client-scrolled.png"});
		await client.context().close();
	}
	const data = await open("page=data&scheme=light&lang=" + lang, 1440, 900);
	await data.locator(".vw-chart-frame svg").first().hover({position: {x: 420, y: 120}});
	await data.screenshot({path: out + "/state-" + lang + "-chart-hover.png"});
	await data.context().close();
	const themes = await open("page=themes&scheme=dark&lang=" + lang, 1440, 900);
	await themes.getByRole("button", {name: lang === "en" ? "Load a hostile file" : "بارگذاری یک فایل مخرب"}).click();
	await themes.screenshot({path: out + "/state-" + lang + "-hostile-refused.png"});
	await themes.context().close();
}
if (!only) for (const [name, query, extra] of [["solid-setting", "page=use&scheme=dark&lang=en&material=solid", {}], ["reduced-transparency", "page=use&scheme=light&lang=fa", {reducedMotion: "reduce"}], ["latin-digits-gregorian", "page=use&scheme=light&lang=fa&digits=latin&calendar=gregorian", {}]]) {
	const page = await open(query, 1440, 900, extra);
	if (name === "reduced-transparency") await page.emulateMedia({reducedMotion: "reduce", colorScheme: "light"}).then(() => page.context().newCDPSession(page)).then(session => session.send("Emulation.setEmulatedMedia", {features: [{name: "prefers-reduced-transparency", value: "reduce"}, {name: "prefers-reduced-motion", value: "reduce"}]}));
	await page.screenshot({path: out + "/state-" + name + ".png"});
	await page.context().close();
}
await browser.close();
for (const problem of problems) console.error(problem);
console.log(problems.length === 0 ? "no console errors, no page errors, no request left the origin, no sideways scroll" : problems.length + " problems");
process.exit(problems.length === 0 ? 0 : 1);
