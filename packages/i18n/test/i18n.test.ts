import assert from "node:assert/strict";
import {test} from "node:test";
import {IntlMessageFormat} from "intl-messageformat";
import {LOCALES, PACKS, createI18n, direction, intlTag} from "../src/index.ts";

test("every pack has the same keys and every message parses", () => {
	for (const locale of LOCALES) {
		assert.deepEqual(Object.keys(PACKS[locale]).sort(), Object.keys(PACKS.en).sort());
		for (const [key, message] of Object.entries(PACKS[locale])) {
			assert.doesNotThrow(() => new IntlMessageFormat(message, locale), key);
			assert.ok(!message.includes("—"), key);
		}
	}
});

test("direction follows the locale", () => {
	assert.equal(direction("en"), "ltr");
	assert.equal(direction("fa"), "rtl");
	assert.equal(createI18n({locale: "fa"}).dir, "rtl");
});

test("plurals follow ICU rules in both languages", () => {
	const english = createI18n({locale: "en"}), persian = createI18n({locale: "fa"});
	assert.equal(english.t("count.users", {count: 1}), "1 user");
	assert.equal(english.t("count.users", {count: 1284}), "1,284 users");
	assert.equal(english.t("count.daysLeft", {count: 0}), "Expires today");
	assert.equal(persian.t("count.users", {count: 12}), "۱۲ کاربر");
	assert.equal(persian.t("count.daysLeft", {count: 0}), "امروز تمام می‌شود");
});

test("Persian digits are a choice", () => {
	assert.equal(createI18n({locale: "fa"}).number(1284), "۱٬۲۸۴");
	assert.equal(createI18n({locale: "fa", persianDigits: false}).number(1284), "1,284");
	assert.equal(createI18n({locale: "fa", persianDigits: false}).t("count.devices", {count: 3}), "3 دستگاه");
	assert.equal(createI18n({locale: "en", persianDigits: true}).number(1284), "1,284");
});

test("Jalali dates are a choice", () => {
	const day = new Date(Date.UTC(2026, 2, 21, 12));
	assert.equal(intlTag({locale: "fa"}), "fa-IR-u-ca-persian-nu-arabext");
	assert.match(createI18n({locale: "fa"}).date(day, {year: "numeric", month: "long", day: "numeric", timeZone: "UTC"}), /۱ فروردین ۱۴۰۵/);
	assert.match(createI18n({locale: "fa", jalali: false}).date(day, {year: "numeric", month: "long", day: "numeric", timeZone: "UTC"}), /۲۰۲۶/);
	assert.equal(createI18n({locale: "en"}).date(day, {year: "numeric", month: "long", day: "numeric", timeZone: "UTC"}), "March 21, 2026");
});

test("byte amounts scale in steps of 1024 and keep value and unit apart", () => {
	const english = createI18n({locale: "en"}), persian = createI18n({locale: "fa"});
	assert.deepEqual(english.bytes(0), {value: "0", unit: "B", text: "0 B"});
	assert.equal(english.bytes(1536).text, "1.5 KB");
	assert.equal(english.bytes(50 * 1024 ** 3).text, "50 GB");
	assert.equal(english.bytes(5 * 1024 ** 5).text, "5,120 TB");
	assert.equal(english.rate(3.2 * 1024 ** 2).text, "3.2 MB/s");
	assert.equal(persian.bytes(12.4 * 1024 ** 3).text, "۱۲٫۴ گیگابایت");
	assert.equal(persian.rate(1024).unit, "کیلوبایت/ثانیه");
});

test("extra messages are merged and a missing key comes back as the key", () => {
	const i18n = createI18n({locale: "fa", extra: {en: {"demo.title": "Users"}, fa: {"demo.title": "کاربران"}}});
	assert.equal(i18n.t("demo.title"), "کاربران");
	assert.equal(i18n.t("demo.none" as "demo.title"), "demo.none");
});
