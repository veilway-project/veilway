import {Banner, Button, ConfirmDialog, Glass, Segmented, StateBlock, Switch, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {ANDROID, failureText, useD, type Prefs} from "./kit.tsx";
import {call, type Settings, type UpdateInfo, type XrayState} from "./tauri.ts";

export function SettingsPage({prefs, onPrefs, settings, onSettings, logs, onUpdate}: {prefs: Prefs, onPrefs: (next: Partial<Prefs>) => void, settings: Settings, onSettings: (next: Settings) => void, logs: string[], onUpdate: (info: UpdateInfo | null) => void}) {
	const {t} = useD(), toast = useToast(), [showLog, setShowLog] = useState(false), [checking, setChecking] = useState(false), [checked, setChecked] = useState<UpdateInfo | null>(null), [checkError, setCheckError] = useState<string | null>(null);
	const [autostart, setAutostart] = useState<boolean | null>(null), [alpha, setAlpha] = useState<boolean | null>(null), [asking, setAsking] = useState(false), [xray, setXray] = useState<XrayState | null>(null), [removing, setRemoving] = useState(false);
	useEffect(() => { if (!ANDROID) { call("get_autostart").then(setAutostart, () => {}); call("xray_state").then(setXray, () => {}); } }, []);
	useEffect(() => { call("get_alpha").then(found => setAlpha(found.alpha), () => {}); }, []);
	const saveAlpha = (on: boolean) => call("set_alpha", {on}).then(found => setAlpha(found.alpha), error => toast({tone: "danger", title: t("settings.alphaFailed"), body: error}));
	const removeXray = () => call("xray_remove").then(found => { setXray(found); toast({tone: "success", title: t("settings.xrayRemoved")}); }, error => toast({tone: "danger", title: t("settings.xrayRemoveFailed"), body: failureText(error, t)}));
	const setStart = (enabled: boolean) => call("set_autostart", {enabled}).then(() => setAutostart(enabled), error => toast({tone: "danger", title: t("settings.autostartFailed"), body: error}));
	const check = () => { setChecking(true); setCheckError(null); call("check_update").then(info => { setChecked(info); onUpdate(info.available ? info : null); }, setCheckError).finally(() => setChecking(false)); };
	if (showLog) return <div className="d-page">
		<div className="d-head"><Button variant="quiet" icon="chevronForward" className="d-back" onClick={() => setShowLog(false)}>{t("common.back")}</Button>{logs.length > 0 && <Button icon="copy" onClick={() => navigator.clipboard.writeText(logs.join("\n")).then(() => toast({tone: "success", title: t("logs.copied")}), () => toast({tone: "danger", title: t("logs.copyFailed")}))}>{t("logs.copy")}</Button>}</div>
		<h1 className="vw-h1">{t("logs.title")}</h1>
		<Glass className="d-panel">{logs.length === 0 ? <StateBlock kind="empty" title={t("logs.empty")}>{t("logs.emptyBody")}</StateBlock> : <pre className="d-log vw-code" dir="ltr" tabIndex={0}>{logs.join("\n")}</pre>}</Glass>
	</div>;
	return <div className="d-page">
		<h1 className="vw-h1">{t("settings.title")}</h1>
		<Glass className="d-panel">
			{ANDROID ? <div className="d-setting"><span className="vw-label">{t("settings.alwaysOn")}</span><span className="vw-muted vw-small">{t("settings.alwaysOnHint")}</span><Button icon="settings" onClick={() => call("open_vpn_settings").catch(error => toast({tone: "danger", title: t("settings.alwaysOn"), body: error}))}>{t("settings.alwaysOnOpen")}</Button></div>
			: <Switch label={t("settings.killSwitch")} hint={t("settings.killSwitchHint")} checked={settings.kill_switch} onChange={kill_switch => onSettings({...settings, kill_switch})}/>}
			<div className="d-setting"><span className="vw-label">{t("settings.language")}</span><Segmented label={t("settings.language")} value={settings.locale === "fa" ? "fa" : "en"} onChange={locale => onSettings({...settings, locale: locale === "fa" ? "fa" : "en"})} options={[{value: "en", label: "English"}, {value: "fa", label: "فارسی"}]}/></div>
			<div className="d-setting"><span className="vw-label">{t("settings.theme")}</span><Segmented label={t("settings.theme")} value={prefs.scheme} onChange={value => { const scheme = value === "dark" || value === "light" ? value : "system"; onPrefs({scheme}); onSettings({...settings, theme: scheme === "light" ? "light" : "dark"}); }} options={[{value: "system", label: t("settings.theme.system")}, {value: "dark", label: t("settings.theme.dark")}, {value: "light", label: t("settings.theme.light")}]}/></div>
			<Switch label={t("settings.alpha")} hint={t("settings.alphaHint")} checked={alpha ?? false} disabled={alpha === null} onChange={on => { if (on) setAsking(true); else saveAlpha(false); }}/>
		</Glass>
		<ConfirmDialog open={asking} onOpenChange={setAsking} title={t("alpha.title")} body={t("alpha.warning")} confirmLabel={t("alpha.confirm")} onConfirm={() => { saveAlpha(true); }}/>
		{!ANDROID && <Glass className="d-panel">
			<Switch label={t("settings.autostart")} checked={autostart ?? false} disabled={autostart === null} onChange={setStart}/>
			<Switch label={t("settings.autoUpdate")} checked={settings.auto_update} onChange={auto_update => onSettings({...settings, auto_update})}/>
			<div className="d-head"><span className="vw-muted">{checked ? t("settings.version", {version: checked.current}) : null}</span><Button icon="refresh" disabled={checking} onClick={check}>{t("settings.check")}</Button></div>
			{checked && !checked.available && <Banner tone="success" title={t("settings.upToDate")}/>}
			{checkError && <Banner tone="danger" title={t("settings.checkFailed")}>{checkError}</Banner>}
		</Glass>}
		{!ANDROID && xray?.supported && <Glass className="d-panel"><div className="d-setting"><span className="vw-label">{t("settings.xray")}</span><span className="vw-muted vw-small">{xray.installed ? t("settings.xrayInstalled", {release: `\u2066${xray.release}\u2069`}) : t("settings.xrayMissing")}</span>{xray.installed && <Button onClick={() => setRemoving(true)}>{t("settings.xrayRemove")}</Button>}</div></Glass>}
		<ConfirmDialog open={removing} onOpenChange={setRemoving} danger title={t("settings.xrayRemoveTitle")} body={t("settings.xrayRemoveBody")} confirmLabel={t("settings.xrayRemove")} onConfirm={removeXray}/>
		<Glass className="d-panel"><div className="d-setting"><span className="vw-label">{t("settings.privacy")}</span><span className="vw-muted vw-small">{t("settings.privacyHint")}</span><Button icon="external" onClick={() => call("open_link", {url: `https://veilway-project.github.io/veilway-docs/${settings.locale === "fa" ? "fa/" : ""}legal/app-privacy/`}).catch(error => toast({tone: "danger", title: t("settings.privacy"), body: error}))}>{t("terms.privacy")}</Button></div></Glass>
		<Button variant="quiet" icon="activity" className="d-start" onClick={() => setShowLog(true)}>{t("settings.log")}</Button>
	</div>;
}
