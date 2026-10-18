import {Backdrop, Banner, Button, ConfirmDialog, DEFAULT_SETTINGS, Dialog, Nav, PRODUCT, Shell, StateBlock, ToastProvider, UiProvider, useToast, type TrafficPoint} from "@veilway/ui";
import {useEffect, useMemo, useRef, useState} from "react";
import {Bundle} from "./bundle.tsx";
import {Home} from "./home.tsx";
import {Importer} from "./importer.tsx";
import {failureText, loadPrefs, savePrefs, useD, type Prefs} from "./kit.tsx";
import {Library} from "./library.tsx";
import {en, type DesktopKey} from "./locales/en.ts";
import {fa} from "./locales/fa.ts";
import {SettingsPage} from "./settings.tsx";
import {asksPrivate, call, offersXray, on, type BundleReview, type Ended, type Progress, type Running, type Settings, type Subscription, type UpdateInfo, type XrayInstallPush, type XrayState} from "./tauri.ts";
import {UsagePage} from "./usage.tsx";

const PACKS = {en, fa};
const IDLE: Running = {connected: false, status: null, kill_switch_kept: false};
// The engine asks in English; each known question has its own words here. Anything else is shown as the engine wrote it.
const QUESTIONS: [string, string][] = [["private", "private address"], ["unsafe", "does not check who"], ["stale", "expired more than 30 days"], ["cover", "looks like ordinary web traffic"], ["nocover", "does not look like web traffic"], ["plain", "plain tunnel"], ["exposed", "using a tunnel"]];

// Used only until the helper's settings arrive, and when they cannot be read.
const FALLBACK: Settings = {auto_update: true, theme: "dark", locale: "en", kill_switch: true};
// The add-on has not run on a real Mac yet, which its offer says there.
const MAC = /Macintosh|Mac OS X/.test(navigator.userAgent);

export function App() {
	const [prefs, setPrefs] = useState<Prefs>(loadPrefs), [saved, setSaved] = useState<Settings | null>(null);
	useEffect(() => { call("get_settings").then(setSaved, () => setSaved(FALLBACK)); }, []);
	const locale: "en" | "fa" = saved?.locale === "fa" ? "fa" : "en";
	const settings = useMemo(() => ({...DEFAULT_SETTINGS, locale, scheme: prefs.scheme}), [locale, prefs.scheme]);
	const change = (next: Partial<Prefs>) => setPrefs(old => { const merged = {...old, ...next}; savePrefs(merged); return merged; });
	return <UiProvider settings={settings} extra={PACKS}><ToastProvider>{saved && <Root prefs={prefs} onPrefs={change} settings={saved} onSettings={setSaved}/>}</ToastProvider></UiProvider>;
}

function Brand() {
	const {t} = useD();
	return <div className="d-brand">
		<svg viewBox="0 0 1024 1024" aria-hidden="true"><defs><linearGradient id="d-tile" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#22795A"/><stop offset="1" stopColor="#145540"/></linearGradient><clipPath id="d-band"><rect x="0" y="262" width="1024" height="500"/></clipPath><mask id="d-behind" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024"><rect width="1024" height="1024" fill="#fff"/><path d="M242.2 200L543.7 828" stroke="#000" strokeWidth="152"/></mask></defs><rect x="64" y="64" width="896" height="896" rx="150" fill="url(#d-tile)"/><g clipPath="url(#d-band)" fill="none" stroke="#F1F8F4"><g mask="url(#d-behind)"><path d="M734.1 200L432.6 828" strokeWidth="34"/><path d="M781.8 200L480.3 828" strokeWidth="34" strokeOpacity="0.6"/><path d="M829.5 200L528 828" strokeWidth="34" strokeOpacity="0.32"/></g><path d="M242.2 200L543.7 828" strokeWidth="120"/></g></svg>
		<div><strong>{PRODUCT}</strong><span className="vw-muted vw-small">{t("app.subtitle")}</span></div>
	</div>;
}

function Root({prefs, onPrefs, settings, onSettings}: {prefs: Prefs, onPrefs: (next: Partial<Prefs>) => void, settings: Settings, onSettings: (next: Settings) => void}) {
	const {t, locale, percent, bytes} = useD(), toast = useToast();
	const [tab, setTab] = useState("home"), [adding, setAdding] = useState(false), [library, setLibrary] = useState<Subscription[] | null>(null), [libraryError, setLibraryError] = useState<string | null>(null), [privateAsk, setPrivateAsk] = useState<{id: string, addresses: string[]} | null>(null), [bundle, setBundle] = useState<BundleReview | null>(null);
	const [running, setRunning] = useState<Running>(IDLE), [busy, setBusy] = useState(false), [ended, setEnded] = useState<Ended | null>(null), [question, setQuestion] = useState<string | null>(null), [points, setPoints] = useState<TrafficPoint[]>([]), [logs, setLogs] = useState<string[]>([]);
	const [update, setUpdate] = useState<UpdateInfo | null>(null), [progress, setProgress] = useState<Progress | null>(null), [xrayOffer, setXrayOffer] = useState<XrayState | null>(null), [installing, setInstalling] = useState(false), [downloaded, setDownloaded] = useState(0);
	const last = useRef<{at: number, sent: number, received: number} | null>(null), installed = useRef<(push: XrayInstallPush) => void>(() => {});
	const loadLibrary = () => { setLibraryError(null); call("library", {languages: locale === "fa" ? ["fa", "en"] : ["en"]}).then(setLibrary, setLibraryError); };
	useEffect(loadLibrary, [locale]);
	useEffect(() => { document.title = t("app.title"); }, [t]);
	useEffect(() => {
		call("status").then(setRunning, () => setRunning(IDLE));
		call("log_history").then(setLogs, () => setLogs([]));
		const offs = [on("status", status => setRunning(old => ({...old, connected: true, status}))), on("question", setQuestion), on("ended", done => {
			setRunning({...IDLE, kill_switch_kept: done.kept});
			setQuestion(null);
			setEnded(done.error || done.kept ? done : null);
			setPoints([]);
		}), on("log", line => setLogs(list => [...list.slice(-199), line])), on("update-progress", setProgress), on("xray-install", push => installed.current(push))];
		return () => offs.forEach(off => off.then(stop => stop()));
	}, []);
	// At start, every six hours, and when the tunnel comes up or goes down, since a check made while the kill switch held could not reach the release.
	useEffect(() => {
		if (!settings.auto_update) return;
		const check = () => call("check_update").then(info => setUpdate(info.available ? info : null), () => {});
		check();
		const timer = setInterval(check, 6 * 3600 * 1000);
		return () => clearInterval(timer);
	}, [settings.auto_update, running.connected]);
	// Byte counters come with the status; the speed is their change over the second between two polls.
	useEffect(() => {
		if (!running.connected) { last.current = null; return; }
		const timer = setInterval(() => call("status").then(next => {
			setRunning(next);
			const found = next.status, at = Date.now(), before = last.current;
			if (!found) return;
			last.current = {at, sent: found.sent_bytes, received: found.received_bytes};
			if (before && at > before.at) setPoints(list => [...list.slice(-59), {time: new Date(at), down: Math.max(0, (found.received_bytes - before.received) * 1000 / (at - before.at)), up: Math.max(0, (found.sent_bytes - before.sent) * 1000 / (at - before.at))}]);
		}, () => {}), 1000);
		return () => clearInterval(timer);
	}, [running.connected]);
	// Pasted links have no provider: the window names them.
	const named = useMemo(() => library?.map(subscription => subscription.legacy ? {...subscription, provider: t("xray.pasted")} : subscription) ?? null, [library, t]);
	const choices = (named ?? []).flatMap(subscription => subscription.profiles.map(profile => ({subscription, profile})));
	const chosen = choices.find(c => c.subscription.id === prefs.choice?.subscription && c.profile.id === prefs.choice?.profile) ?? choices[0];
	const connect = () => {
		if (!chosen) return;
		setBusy(true);
		setEnded(null);
		call("connect", {subscription: chosen.subscription.id, profile: chosen.profile.id, options: {local_names: false, routes: []}}).then(found => { if (offersXray(found)) return setXrayOffer(found.xray_offer); setRunning(old => ({...old, connected: true})); }, error => toast({tone: "danger", title: t("home.connectFailed"), body: failureText(error, t)})).finally(() => setBusy(false));
	};
	// The add-on is installed only after the yes to its offer. The helper answers at once and tells how it goes with pushes, so Disconnect and the questions are not held up; the connection is made again once it is in.
	const installXray = () => { setInstalling(true); setDownloaded(0); call("xray_install").catch(error => { setInstalling(false); toast({tone: "danger", title: t("xray.installFailed"), body: failureText(error, t)}); }); };
	installed.current = push => {
		setDownloaded(push.downloaded);
		if (push.phase === "downloading") return;
		setInstalling(false);
		if (push.phase === "failed") return toast({tone: "danger", title: t("xray.installFailed"), body: failureText(push.error ?? "", t)});
		setXrayOffer(null);
		connect();
	};
	const disconnect = () => {
		setBusy(true);
		call("disconnect").then(() => { setRunning(IDLE); setEnded(null); setPoints([]); }, error => toast({tone: "danger", title: t("home.ended"), body: error})).finally(() => setBusy(false));
	};
	const refresh = (id: string, agreed?: string[]) => call("refresh", agreed ? {id, private: agreed} : {id}).then(found => { if (asksPrivate(found)) return setPrivateAsk({id, addresses: found.ask_private.addresses}); setLibrary(found); toast({tone: "success", title: t("library.refreshed")}); }, error => toast({tone: "danger", title: t("library.refreshFailed"), body: failureText(error, t)}));
	const answer = (yes: boolean) => {
		setQuestion(null);
		call("answer", {yes}).catch(error => toast({tone: "danger", title: t("question.failed"), body: error}));
	};
	// The desktop restarts into the new version and never returns here; Android returns once the system's installer has the file, and the user may still cancel there.
	const install = () => { setProgress({downloaded: 0, total: null}); call("install_update").then(() => setProgress(null), error => { setProgress(null); toast({tone: "danger", title: t("update.failed"), body: error}); }); };
	const saveSettings = (next: Settings) => { onSettings(next); call("set_settings", {settings: next}).catch(error => toast({tone: "danger", title: t("settings.saveFailed"), body: error})); };
	const kind = question === null ? null : QUESTIONS.find(([, words]) => question.includes(words))?.[0] ?? "other";
	const updateBanner = update && <Banner tone="info" title={t("update.title", {version: update.version})} action={!progress && <Button size="sm" variant="primary" onClick={install}>{t("update.install")}</Button>}>
		{progress ? <span className="d-progress"><span>{t("update.installing")}</span>{progress.total ? <><span className="vw-meter" role="progressbar" aria-valuemin={0} aria-valuemax={progress.total} aria-valuenow={progress.downloaded}><span style={{inlineSize: Math.min(100, progress.downloaded / progress.total * 100) + "%"}}/></span><strong className="vw-num vw-small">{percent(progress.downloaded / progress.total)}</strong></> : null}</span> : update.notes.slice(0, 200)}
	</Banner>;
	const content = bundle ? <Bundle review={bundle} onClose={() => setBundle(null)} onLibrary={setLibrary}/> : named === null ? (libraryError ? <StateBlock kind="error" title={t("library.loadFailed")} action={<Button onClick={loadLibrary}>{t("action.retry")}</Button>}>{t("library.loadFailedBody")}</StateBlock> : <StateBlock kind="loading" title={t("common.loading")}/>)
		: adding || (named.length === 0 && tab === "home") ? <Importer first={named.length === 0} onAccept={(id, terms) => onPrefs({accepted: {...prefs.accepted, [id]: terms}})} onCancel={() => setAdding(false)} onBundle={setBundle} onDone={found => { setLibrary(found); setAdding(false); setTab("home"); toast({tone: "success", title: t("import.added")}); }}/>
		: tab === "usage" ? <UsagePage running={running} points={points}/>
		: tab === "subscriptions" ? <Library library={named} inUse={running.connected ? chosen?.subscription.id ?? null : null} onAdd={() => setAdding(true)} onRefresh={refresh} onChange={setLibrary}/>
		: tab === "settings" ? <SettingsPage prefs={prefs} onPrefs={onPrefs} settings={settings} onSettings={saveSettings} logs={logs} onUpdate={setUpdate}/>
		: <Home running={running} busy={busy} ended={ended} points={points} choices={choices} chosen={chosen} prefs={prefs} onPrefs={onPrefs} onConnect={connect} onDisconnect={disconnect} onRefresh={refresh}/>;
	const lit = running.status?.state === "connected";
	return <Backdrop fixed lit={lit} className="d-app">
		<Shell nav={<Nav header={<Brand/>} value={adding ? "subscriptions" : tab} onChange={id => { setAdding(false); setTab(id); }} items={[{id: "home", label: t("nav.home"), icon: "power"}, {id: "usage", label: t("nav.usage"), icon: "chart"}, {id: "subscriptions", label: t("nav.subscriptions"), icon: "inbox"}, {id: "settings", label: t("nav.settings"), icon: "settings"}]}/>} banner={updateBanner}>{content}</Shell>
		<Dialog open={kind !== null} onOpenChange={open => { if (!open && question !== null) answer(false); }} title={t(`question.${kind ?? "other"}.title` as DesktopKey)} description={kind === "other" ? question ?? "" : t(`question.${kind ?? "other"}.body` as DesktopKey)} footer={<><Button onClick={() => answer(false)}>{t("question.no")}</Button><Button variant={kind === "unsafe" || kind === "stale" ? "danger" : "primary"} onClick={() => answer(true)}>{t(`question.${kind ?? "other"}.yes` as DesktopKey)}</Button></>}/>
		<Dialog open={xrayOffer !== null} onOpenChange={open => { if (!open && !installing) setXrayOffer(null); }} title={t("xray.offer.title")} description={t("xray.offer.body", {release: `\u2066${xrayOffer?.release ?? ""}\u2069`, size: bytes(xrayOffer?.size ?? 0).text})} footer={<><Button disabled={installing} onClick={() => setXrayOffer(null)}>{t("common.cancel")}</Button><Button variant="primary" disabled={installing} onClick={installXray}>{t(installing ? "xray.offer.installing" : "xray.offer.yes")}</Button></>}>
			{MAC && <p className="vw-muted vw-small">{t("xray.offer.untested")}</p>}
			{installing && <p className="vw-muted vw-small" role="status">{t("xray.offer.progress", {size: bytes(downloaded).text})}</p>}
		</Dialog>
		<ConfirmDialog open={privateAsk !== null} onOpenChange={open => { if (!open) setPrivateAsk(null); }} title={t("private.title")} body={t("private.body", {addresses: `\u2066${privateAsk?.addresses.join(", ") ?? ""}\u2069`})} confirmLabel={t("private.yes")} onConfirm={() => { if (privateAsk) refresh(privateAsk.id, privateAsk.addresses); }}/>
	</Backdrop>;
}
