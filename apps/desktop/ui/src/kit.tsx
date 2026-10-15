import {useI18n} from "@veilway/ui";
import {useEffect, useState} from "react";
import type {DesktopKey} from "./locales/en.ts";

export const useD = () => useI18n<DesktopKey>();

// What only this window remembers. The theme also goes to the app's settings file, so the native title bar matches.
export type Prefs = {locale: "en" | "fa", scheme: "system" | "dark" | "light", killSwitch: boolean, choice: {subscription: string, profile: string} | null, hidden: string[]};
const PREFS = "veilway-desktop";

export function loadPrefs(): Prefs {
	const stored = (() => { try { return JSON.parse(localStorage.getItem(PREFS) ?? "{}") as Partial<Prefs>; } catch { return {}; } })();
	return {locale: stored.locale === "fa" ? "fa" : "en", scheme: stored.scheme === "dark" || stored.scheme === "light" ? stored.scheme : "system", killSwitch: stored.killSwitch !== false, choice: stored.choice ?? null, hidden: Array.isArray(stored.hidden) ? stored.hidden : []};
}

export function savePrefs(prefs: Prefs) {
	try { localStorage.setItem(PREFS, JSON.stringify(prefs)); } catch { /* the choice lasts until the window closes */ }
}

// The design system shows a provider logo only from a blob: URL. The Rust side has already decoded and size-checked the picture before handing over this data: URL.
export function useLogo(data: string | null): string | undefined {
	const [url, setUrl] = useState<string>();
	useEffect(() => {
		const found = data?.match(/^data:(image\/(?:png|jpeg));base64,([A-Za-z0-9+/=]+)$/);
		if (!found) return setUrl(undefined);
		const made = URL.createObjectURL(new Blob([Uint8Array.from(atob(found[2]!), c => c.charCodeAt(0))], {type: found[1]}));
		setUrl(made);
		return () => URL.revokeObjectURL(made);
	}, [data]);
	return url;
}

export const fromUnix = (seconds: number) => new Date(seconds * 1000);

// Reads a picked or pasted file as base64 without the data: prefix.
export function base64(file: Blob): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(String(reader.result).replace(/^data:[^,]*,/, ""));
		reader.onerror = () => reject(reader.error);
		reader.readAsDataURL(file);
	});
}
