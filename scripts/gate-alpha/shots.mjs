// Screenshots of the panel through the web server in front: login, users and traffic, English and Persian, dark. Run by scripts/gate-alpha.sh in the Playwright image. Fails on a console error, a page error or a request that leaves the origin.
import {createRequire} from "node:module";
import {createHmac} from "node:crypto";
import {readFileSync, writeFileSync} from "node:fs";
const {chromium} = createRequire(process.env.PW_HOME + "/")("playwright");
const {PANEL_HOST: host, PANEL_PREFIX: prefix, STATE: stateDir, OUT: out} = process.env;
const file = stateDir + "/state.json", state = JSON.parse(readFileSync(file, "utf8")), base = `https://${host}${prefix}/`;
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const secret = Buffer.from([...state.totp_secret.replace(/=+$/, "")].reduce((bits, c) => bits + alphabet.indexOf(c).toString(2).padStart(5, "0"), "").match(/.{8}/g).map(b => parseInt(b, 2)));
const code = async () => {
	let step = Math.max(Math.floor(Date.now() / 30000), (state.last_step ?? 0) + 1);
	while (step > Math.floor(Date.now() / 30000) + 1) { await new Promise(r => setTimeout(r, 2000)); step = Math.max(Math.floor(Date.now() / 30000), step); }
	state.last_step = step;
	writeFileSync(file, JSON.stringify(state, null, 1));
	const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
	const tag = createHmac("sha1", secret).update(counter).digest(), at = tag[19] & 15;
	return String((tag.readUInt32BE(at) & 0x7fffffff) % 1000000).padStart(6, "0");
};
const problems = [];
const browser = await chromium.launch(), context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1280, height: 860}, colorScheme: "dark"}), page = await context.newPage();
// The app asks who is logged in before the login page, and the browser logs the 401 it gets.
page.on("console", m => { if (["error", "warning"].includes(m.type()) && !m.text().includes("401")) problems.push("console " + m.type() + ": " + m.text()); });
page.on("pageerror", e => problems.push("page error: " + e.message));
page.on("request", r => { if (!r.url().startsWith(`https://${host}/`)) problems.push("request left the origin: " + r.url()); });
const shot = async name => { await page.waitForTimeout(800); await page.screenshot({path: `${out}/${name}.png`, fullPage: true}); console.log("shot " + name); };
for (const lang of ["en", "fa"]) {
	await page.goto(`${base}?lang=${lang}&scheme=dark`);
	await page.waitForSelector("input[type=password]");
	await shot(`login-${lang}`);
}
await page.goto(`${base}?lang=en&scheme=dark`);
await page.fill("input[autocomplete=username]", state.username);
await page.fill("input[type=password]", state.password);
await page.fill("input[autocomplete=one-time-code]", await code());
await page.click("button[type=submit]");
await page.waitForSelector("nav, [role=navigation]");
for (const lang of ["en", "fa"]) {
	for (const view of ["users", "traffic"]) {
		await page.goto(`${base}?lang=${lang}&scheme=dark#/${view}`);
		await page.waitForSelector(view === "users" ? "text=alice" : "main, .p-page");
		await shot(`${view}-${lang}`);
	}
}
await browser.close();
if (problems.length) { console.log(problems.join("\n")); process.exit(1); }
