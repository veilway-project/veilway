import {useEffect, useState} from "react";
import {BUILTIN, Backdrop, Button, DEFAULT_SETTINGS, Dialog, Nav, PRODUCT, RadioGroup, Segmented, Shell, Switch, ToastProvider, UiProvider, type UiSettings} from "../index.ts";
import {Components} from "./Components.tsx";
import {COPY} from "./copy.ts";
import {DataPage} from "./DataPage.tsx";
import {Foundations} from "./Foundations.tsx";
import {InUse} from "./InUse.tsx";
import {useG} from "./shared.tsx";
import {Themes} from "./Themes.tsx";

const PAGES = ["use", "foundations", "components", "data", "themes"] as const;
type Page = typeof PAGES[number];
const PAGE_ICON = {use: "overview", foundations: "foundations", components: "components", data: "chart", themes: "theme"} as const;

// The address carries the view (page, scheme, lang, material, motion, digits, calendar, still), so a screenshot script or a bug report can name exactly what it shows.
export function Gallery() {
	const query = new URLSearchParams(location.search), pick = <T extends string>(name: string, allowed: readonly T[], fallback: T) => allowed.includes(query.get(name) as T) ? query.get(name) as T : fallback;
	const [page, setPage] = useState<Page>(() => pick("page", PAGES, "use")), [still] = useState(() => query.has("still"));
	const [settings, setSettings] = useState<UiSettings>(() => ({...DEFAULT_SETTINGS, locale: pick("lang", ["en", "fa"], "en"), scheme: pick("scheme", ["dark", "light", "system"], "dark"), material: pick("material", ["auto", "glass", "solid"], "auto"), motion: pick("motion", ["auto", "reduced"], "auto"), persianDigits: query.get("digits") !== "latin", jalali: query.get("calendar") !== "gregorian"}));
	useEffect(() => {
		const next = new URLSearchParams({page, lang: settings.locale, scheme: settings.scheme});
		for (const [name, value, standard] of [["material", settings.material, "auto"], ["motion", settings.motion, "auto"], ["digits", settings.persianDigits ? "persian" : "latin", "persian"], ["calendar", settings.jalali ? "jalali" : "gregorian", "jalali"]] as const) if (value !== standard) next.set(name, value);
		if (still) next.set("still", "1");
		history.replaceState(null, "", "?" + next);
	}, [page, settings, still]);
	return <UiProvider settings={settings} extra={COPY}><ToastProvider><Frame page={page} onPage={setPage} settings={settings} onSettings={setSettings} still={still}/></ToastProvider></UiProvider>;
}

function Frame({page, onPage, settings, onSettings, still}: {page: Page, onPage: (page: Page) => void, settings: UiSettings, onSettings: (settings: UiSettings) => void, still: boolean}) {
	const {t, date} = useG(), [display, setDisplay] = useState(false);
	const scheme = settings.theme?.scheme ?? (settings.scheme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : settings.scheme), active = settings.theme ?? BUILTIN[scheme];
	return <Backdrop fixed className="g-page">
		<Shell nav={<Nav value={page} onChange={id => onPage(id as Page)} items={PAGES.map(id => ({id, label: t(`g.nav.${id}`), icon: PAGE_ICON[id]}))} header={<div className="g-brand">
			<svg viewBox="0 0 1024 1024" aria-hidden="true"><defs><linearGradient id="g-tile" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#22795A"/><stop offset="1" stopColor="#145540"/></linearGradient><clipPath id="g-band"><rect x="0" y="262" width="1024" height="500"/></clipPath><mask id="g-behind" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024"><rect width="1024" height="1024" fill="#fff"/><path d="M242.2 200L543.7 828" stroke="#000" strokeWidth="152"/></mask></defs><rect x="64" y="64" width="896" height="896" rx="150" fill="url(#g-tile)"/><g clipPath="url(#g-band)" fill="none" stroke="#F1F8F4"><g mask="url(#g-behind)"><path d="M734.1 200L432.6 828" strokeWidth="34"/><path d="M781.8 200L480.3 828" strokeWidth="34" strokeOpacity="0.6"/><path d="M829.5 200L528 828" strokeWidth="34" strokeOpacity="0.32"/></g><path d="M242.2 200L543.7 828" strokeWidth="120"/></g></svg>
			<div><strong>{PRODUCT}</strong><span className="vw-muted vw-small">{t("g.brand")}</span></div>
		</div>}/>}>
			<header className="g-top">
				<div><h1 className="vw-h1">{t(`g.nav.${page}`)}</h1><p className="vw-muted">{t(`g.lead.${page}`)}</p></div>
				<div className="g-cluster">
					<Segmented label={t("g.set.scheme")} value={scheme} onChange={next => onSettings({...settings, theme: null, scheme: next as "dark" | "light"})} options={[{value: "dark", label: t("g.set.dark")}, {value: "light", label: t("g.set.light")}]}/>
					<Segmented label={t("g.set.language")} value={settings.locale} onChange={next => onSettings({...settings, locale: next as "en" | "fa"})} options={[{value: "en", label: "English"}, {value: "fa", label: "فارسی"}]}/>
					<Button icon="settings" onClick={() => setDisplay(true)}>{t("g.set.display")}</Button>
				</div>
			</header>
			{page === "use" && <InUse still={still}/>}
			{page === "foundations" && <Foundations theme={active}/>}
			{page === "components" && <Components/>}
			{page === "data" && <DataPage still={still}/>}
			{page === "themes" && <Themes key={scheme} active={active} onApply={theme => onSettings({...settings, theme})}/>}
			<footer className="vw-muted vw-small g-foot">{t("g.foot", {date: date(new Date(Date.UTC(2026, 2, 21, 12)), {year: "numeric", month: "long", day: "numeric", timeZone: "UTC"})})}</footer>
		</Shell>
		<Dialog open={display} onOpenChange={setDisplay} title={t("g.set.display")} description={t("g.set.displayNote")}>
			<div className="g-stack">
				<RadioGroup label={t("g.set.material")} value={settings.material} onChange={next => onSettings({...settings, material: next as UiSettings["material"]})} options={[{value: "auto", label: t("g.set.system"), detail: t("g.set.materialAuto")}, {value: "glass", label: t("g.set.glass")}, {value: "solid", label: t("g.set.solid"), detail: t("g.set.solidNote")}]}/>
				<Switch label={t("g.set.reducedMotion")} hint={t("g.set.reducedMotionNote")} checked={settings.motion === "reduced"} onChange={on => onSettings({...settings, motion: on ? "reduced" : "auto"})}/>
				<Switch label={t("g.set.persianDigits")} hint={t("g.set.persianOnly")} checked={settings.persianDigits} onChange={persianDigits => onSettings({...settings, persianDigits})}/>
				<Switch label={t("g.set.jalali")} hint={t("g.set.persianOnly")} checked={settings.jalali} onChange={jalali => onSettings({...settings, jalali})}/>
			</div>
		</Dialog>
	</Backdrop>;
}
