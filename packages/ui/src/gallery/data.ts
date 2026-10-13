import type {ProviderItem, Rating, TrafficPoint} from "../index.ts";

// Sample content for the gallery. Names are placeholders, addresses come from the documentation ranges, and nothing here is read from a real node.
const GB = 1024 ** 3;
export type SampleUser = {name: string, group: string, used: number, quota: number | null, daysLeft: number, devices: number, online: boolean};
export const USERS: SampleUser[] = [
	{name: "family-plan-01", group: "family", used: 31.4 * GB, quota: 50 * GB, daysLeft: 12, devices: 4, online: true},
	{name: "office-router", group: "team", used: 188 * GB, quota: 200 * GB, daysLeft: 3, devices: 1, online: true},
	{name: "field-laptop", group: "team", used: 4.2 * GB, quota: 30 * GB, daysLeft: 27, devices: 2, online: false},
	{name: "student-04", group: "trial", used: 5 * GB, quota: 5 * GB, daysLeft: 0, devices: 1, online: false},
	{name: "press-desk", group: "team", used: 96.8 * GB, quota: null, daysLeft: 61, devices: 6, online: true}
];

export type SampleExit = {id: string, place: "fra" | "ams" | "hel" | "ist" | "dxb", latency: number, rating: Rating, host: string};
export const EXITS: SampleExit[] = [
	{id: "de-fra", place: "fra", latency: 48, rating: "protected", host: "fra.vpn.example.net"},
	{id: "nl-ams", place: "ams", latency: 52, rating: "detectable", host: "ams.vpn.example.net"},
	{id: "fi-hel", place: "hel", latency: 71, rating: "detectable", host: "hel.vpn.example.net"},
	{id: "tr-ist", place: "ist", latency: 34, rating: "detectable", host: "198.51.100.24"},
	{id: "ae-dxb", place: "dxb", latency: 29, rating: "unsafe", host: "203.0.113.42"}
];

export const SAMPLE_LINK = "https://sub.example.net/s/4Qm8dX2vT7kLp0Zc";
export const SAMPLE_KEY = "kF3m0Il1O0rnQ8vZt5WcYb2uXe7pLs9dGhJaNq4RwT6=";
export const TREND = [18, 22, 19, 27, 31, 26, 34, 41, 38, 46, 44, 52];
export const START = Date.UTC(2026, 2, 21, 8, 30, 0);

// A repeatable traffic curve: the same seed draws the same minute, so screenshots can be compared.
export function traffic(count: number, offset = 0): TrafficPoint[] {
	return Array.from({length: count}, (_, i) => {
		const n = i + offset, wave = Math.sin(n / 7) * 0.5 + Math.sin(n / 2.3) * 0.2 + 1, jitter = ((n * 9301 + 49297) % 233280) / 233280;
		return {time: new Date(START + n * 1000), down: (2.6 + wave * 2.4 + jitter * 0.9) * 1024 ** 2, up: (0.5 + wave * 0.45 + jitter * 0.3) * 1024 ** 2};
	});
}

export const PROVIDER_CARDS: ProviderItem[] = [
	{type: "stat", label: "Plan", value: "Family", unit: "5 devices"},
	{type: "stat", label: "Renews in", value: "12", unit: "days"},
	{type: "progress", label: "Referral credit", used: 3, total: 5},
	{type: "notice", severity: "warning", text: "Frankfurt goes down for maintenance on Friday from 02:00 to 03:00 UTC."},
	{type: "link", label: "Renew plan", url: "https://account.example.net/renew"},
	{type: "link", label: "Dropped: not https", url: "http://account.example.net/"}
];
export const PROVIDER_CARDS_FA: ProviderItem[] = [
	{type: "stat", label: "طرح", value: "خانواده", unit: "۵ دستگاه"},
	{type: "stat", label: "تمدید تا", value: "۱۲", unit: "روز دیگر"},
	{type: "progress", label: "اعتبار معرفی دوستان", used: 3, total: 5},
	{type: "notice", severity: "warning", text: "سرور فرانکفورت جمعه از ساعت ۰۲:۰۰ تا ۰۳:۰۰ به وقت جهانی برای تعمیرات خاموش است."},
	{type: "link", label: "تمدید طرح", url: "https://account.example.net/renew"},
	{type: "link", label: "حذف می‌شود: https نیست", url: "http://account.example.net/"}
];
