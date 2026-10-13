import {IntlMessageFormat} from "intl-messageformat";
import {en, type MessageKey} from "./locales/en.ts";
import {fa} from "./locales/fa.ts";

export type {MessageKey};
export type Locale = "en" | "fa";
export type Direction = "ltr" | "rtl";
// Persian digits and the Jalali calendar only apply to Persian, where both are on unless turned off.
export type FormatOptions = {locale: Locale, persianDigits?: boolean, jalali?: boolean};
export type Values = Record<string, string | number | Date>;
export type Amount = {value: string, unit: string, text: string};
export type I18n<K extends string = never> = {
	locale: Locale,
	dir: Direction,
	tag: string,
	t: (key: MessageKey | K, values?: Values) => string,
	number: (value: number, options?: Intl.NumberFormatOptions) => string,
	percent: (ratio: number) => string,
	bytes: (bytes: number) => Amount,
	rate: (bytesPerSecond: number) => Amount,
	date: (date: Date, options?: Intl.DateTimeFormatOptions) => string,
	time: (date: Date, seconds?: boolean) => string
};

export const LOCALES: Locale[] = ["en", "fa"];
export const PACKS: Record<Locale, Record<MessageKey, string>> = {en, fa};
const UNITS = ["unit.b", "unit.kb", "unit.mb", "unit.gb", "unit.tb"] as const;

export function direction(locale: Locale): Direction {
	return locale === "fa" ? "rtl" : "ltr";
}

// The BCP 47 tag that carries the digit and calendar choice into every Intl formatter.
export function intlTag(options: FormatOptions): string {
	return options.locale === "fa" ? "fa-IR-u-ca-" + (options.jalali === false ? "gregory" : "persian") + "-nu-" + (options.persianDigits === false ? "latn" : "arabext") : "en-u-ca-gregory-nu-latn";
}

export function createI18n<K extends string = never>(options: FormatOptions & {extra?: Record<Locale, Record<K, string>>}): I18n<K> {
	const tag = intlTag(options), cache = new Map<string, IntlMessageFormat>();
	const messages: Record<string, string> = {...PACKS[options.locale], ...options.extra?.[options.locale]};
	const number = (value: number, format?: Intl.NumberFormatOptions) => new Intl.NumberFormat(tag, format).format(value);
	const t = (key: MessageKey | K, values?: Values) => {
		const message = messages[key];
		if (message === undefined) return key;
		if (!cache.has(key)) cache.set(key, new IntlMessageFormat(message, tag));
		return String(cache.get(key)!.format(values));
	};
	const bytes = (amount: number): Amount => {
		const step = Math.min(UNITS.length - 1, Math.max(0, Math.floor(Math.log(Math.max(1, Math.abs(amount))) / Math.log(1024))));
		const scaled = amount / 1024 ** step, value = number(scaled, {maximumFractionDigits: step === 0 || scaled >= 100 ? 0 : 1}), unit = t(UNITS[step]!);
		return {value, unit, text: t("unit.amount", {value, unit})};
	};
	return {
		locale: options.locale,
		dir: direction(options.locale),
		tag,
		t,
		number,
		bytes,
		percent: ratio => number(ratio, {style: "percent", maximumFractionDigits: 0}),
		rate: amount => {
			const base = bytes(amount), unit = t("unit.perSecond", {unit: base.unit});
			return {value: base.value, unit, text: t("unit.amount", {value: base.value, unit})};
		},
		date: (date, format) => new Intl.DateTimeFormat(tag, format ?? {year: "numeric", month: "long", day: "numeric"}).format(date),
		time: (date, seconds) => new Intl.DateTimeFormat(tag, {hour: "2-digit", minute: "2-digit", second: seconds ? "2-digit" : undefined, hourCycle: "h23"}).format(date)
	};
}
