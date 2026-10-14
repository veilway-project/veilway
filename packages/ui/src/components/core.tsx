import {createI18n, type I18n, type Locale} from "@veilway/i18n";
import {Direction} from "radix-ui";
import {createContext, useContext, useEffect, useMemo, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode} from "react";
import {applyTheme} from "../theme/apply.ts";
import type {Scheme, Theme} from "../theme/tokens.ts";

// scheme "system", material "auto" and motion "auto" follow the OS. A theme, when set, decides the scheme.
export type UiSettings = {locale: Locale, scheme: Scheme | "system", material: "auto" | "glass" | "solid", motion: "auto" | "reduced", persianDigits: boolean, jalali: boolean, theme: Theme | null};
export const DEFAULT_SETTINGS: UiSettings = {locale: "en", scheme: "system", material: "auto", motion: "auto", persianDigits: true, jalali: true, theme: null};

const I18nContext = createContext<I18n<string> | null>(null);

// Owns the document: language, direction, colour scheme, material and motion are attributes on <html>, so dialogs and menus that render outside the app root get them too.
export function UiProvider<K extends string = never>({settings, extra, children}: {settings: UiSettings, extra?: Record<Locale, Record<K, string>>, children: ReactNode}) {
	const i18n = useMemo(() => createI18n({locale: settings.locale, persianDigits: settings.persianDigits, jalali: settings.jalali, extra}), [settings.locale, settings.persianDigits, settings.jalali, extra]);
	useEffect(() => {
		const root = document.documentElement;
		root.classList.add("vw-root");
		root.lang = settings.locale;
		root.dir = i18n.dir;
		for (const [name, value] of [["scheme", settings.scheme === "system" ? null : settings.scheme], ["material", settings.material === "auto" ? null : settings.material], ["motion", settings.motion === "auto" ? null : settings.motion]] as const) {
			if (value) root.dataset[name] = value;
			else delete root.dataset[name];
		}
		applyTheme(root, settings.theme);
	}, [settings, i18n.dir]);
	return <I18nContext.Provider value={i18n as unknown as I18n<string>}><Direction.Provider dir={i18n.dir}>{children}</Direction.Provider></I18nContext.Provider>;
}

export function useI18n<K extends string = never>(): I18n<K> {
	const i18n = useContext(I18nContext);
	if (!i18n) throw new Error("useI18n needs a UiProvider above it");
	return i18n as unknown as I18n<K>;
}

const ICONS = {
	overview: "M3 3h6v8H3zM11 3h6v4h-6zM11 9h6v8h-6zM3 13h6v4H3z",
	foundations: "M4 4h12v12H4zM4 9h12M9 9v7",
	components: "M10 2.5l7 4-7 4-7-4zM3 10.5l7 4 7-4M3 14l7 4 7-4",
	chart: "M3 17V3M3 17h14M7 13V9M11 13V6M15 13v-3",
	theme: "M10 3l5 6a6 6 0 1 1-10 0z",
	users: "M7.5 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM2 17c0-3 2.5-5 5.5-5s5.5 2 5.5 5M13.5 9.2a2.6 2.6 0 0 0 0-5.2M15 12.4c1.8.6 3 2.2 3 4.6",
	globe: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM3 10h14M10 3c2 2 3 4.4 3 7s-1 5-3 7c-2-2-3-4.4-3-7s1-5 3-7z",
	activity: "M2 10h3.5l2.5-6 4 12 2.5-6H18",
	settings: "M3 6h8M15 6h2M3 14h2M9 14h8M13 4v4M7 12v4",
	eye: "M1.5 10S4.5 4 10 4s8.5 6 8.5 6-3 6-8.5 6S1.5 10 1.5 10zM10 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z",
	eyeOff: "M3 3l14 14M8.2 4.3A8 8 0 0 1 10 4c5.5 0 8.5 6 8.5 6a14 14 0 0 1-2.4 3.1M12.6 15.5A8 8 0 0 1 10 16c-5.5 0-8.5-6-8.5-6a14 14 0 0 1 3.6-4.2M8.2 8.3a2.5 2.5 0 0 0 3.5 3.5",
	check: "M4 10.5l4 4 8-9",
	close: "M5 5l10 10M15 5L5 15",
	chevronDown: "M5 7.5l5 5 5-5",
	chevronForward: "M7.5 5l5 5-5 5",
	copy: "M7 7h9v9H7zM13 7V4H4v9h3",
	warning: "M10 3l8 14H2zM10 8v4M10 14.5v.01",
	info: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM10 9v5M10 6.5v.01",
	error: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM7.5 7.5l5 5M12.5 7.5l-5 5",
	plus: "M10 4v12M4 10h12",
	external: "M8 4H4v12h12v-4M11 3h6v6M17 3l-8 8",
	refresh: "M16 10a6 6 0 1 1-2-4.5M16 3v3.5h-3.5",
	power: "M10 3v7M6 5.5a6 6 0 1 0 8 0",
	download: "M10 3v10M6 9.5l4 4 4-4M4 17h12",
	upload: "M10 14V4M6 7.5l4-4 4 4M4 17h12",
	inbox: "M3 11l2.5-7h9L17 11v5H3zM3 11h4l1 2h4l1-2h4",
	lock: "M5 9h10v8H5zM7 9V6.5a3 3 0 0 1 6 0V9",
	device: "M4 4h12v9H4zM2 16h16"
};
export type IconName = keyof typeof ICONS;
// Icons whose meaning depends on the reading direction. They are mirrored in right-to-left layouts.
const DIRECTIONAL: IconName[] = ["chevronForward", "external"];

// The whole icon set is built in. Provider content picks from these names and cannot bring its own.
export function Icon({name, label}: {name: IconName, label?: string}) {
	return <svg className="vw-icon" viewBox="0 0 20 20" data-flip={DIRECTIONAL.includes(name) ? "" : undefined} role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : true}><path d={ICONS[name]}/></svg>;
}

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {variant?: "primary" | "secondary" | "quiet" | "danger", size?: "md" | "sm", icon?: IconName};

export function Button({variant = "secondary", size = "md", icon, className, children, type = "button", ...rest}: ButtonProps) {
	return <button {...rest} type={type} className={"vw-button" + (className ? " " + className : "")} data-variant={variant} data-size={size}>{icon && <Icon name={icon}/>}<span>{children}</span></button>;
}

// A round button that holds one icon. The label is required because nothing else names it.
export function IconButton({icon, label, className, type = "button", ...rest}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children"> & {icon: IconName, label: string}) {
	return <button {...rest} type={type} className={"vw-icon-button" + (className ? " " + className : "")} aria-label={label} title={label}><Icon name={icon}/></button>;
}

export type GlassLayer = "sheet" | "chrome" | "popover" | "dialog";

// A pane of glass. layer says what can be behind it, which decides how dense it is: a sheet rests on the backdrop, chrome has content scrolling under it, a popover or dialog can open over anything. depth only sets how far a sheet lifts; 3 is the older way of asking for a popover.
export function Glass({depth = 2, layer, className, children, ...rest}: HTMLAttributes<HTMLDivElement> & {depth?: 1 | 2 | 3, layer?: GlassLayer}) {
	return <div {...rest} className={"vw-glass" + (className ? " " + className : "")} data-depth={depth} data-layer={layer ?? (depth === 3 ? "popover" : "sheet")}>{children}</div>;
}

// The page behind the glass. fixed pins its light to the viewport, for the root of an app. lit false turns the light down: a client passes its connection state here, so the whole window shows it.
export function Backdrop({lit = true, fixed, className, children, ...rest}: HTMLAttributes<HTMLDivElement> & {lit?: boolean, fixed?: boolean}) {
	return <div {...rest} className={"vw-backdrop" + (className ? " " + className : "")} data-lit={lit ? undefined : "off"} data-fixed={fixed ? "" : undefined}>{children}</div>;
}
