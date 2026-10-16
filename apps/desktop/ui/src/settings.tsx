import {Banner, Button, Glass, Segmented, StateBlock, Switch, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {ANDROID, useD, type Prefs} from "./kit.tsx";
import {call, type Settings, type UpdateInfo} from "./tauri.ts";

export function SettingsPage({prefs, onPrefs, settings, onSettings, logs, onUpdate}: {prefs: Prefs, onPrefs: (next: Partial<Prefs>) => void, settings: Settings, onSettings: (next: Settings) => void, logs: string[], onUpdate: (info: UpdateInfo | null) => void}) {
	const {t} = useD(), toast = useToast(), [showLog, setShowLog] = useState(false), [checking, setChecking] = useState(false), [checked, setChecked] = useState<UpdateInfo | null>(null), [checkError, setCheckError] = useState<string | null>(null);
	const [autostart, setAutostart] = useState<boolean | null>(null);
	useEffect(() => { if (!ANDROID) call("get_autostart").then(setAutostart, () => {}); }, []);
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
		</Glass>
		{!ANDROID && <Glass className="d-panel">
			<Switch label={t("settings.autostart")} checked={autostart ?? false} disabled={autostart === null} onChange={setStart}/>
			<Switch label={t("settings.autoUpdate")} checked={settings.auto_update} onChange={auto_update => onSettings({...settings, auto_update})}/>
			<div className="d-head"><span className="vw-muted">{checked ? t("settings.version", {version: checked.current}) : null}</span><Button icon="refresh" disabled={checking} onClick={check}>{t("settings.check")}</Button></div>
			{checked && !checked.available && <Banner tone="success" title={t("settings.upToDate")}/>}
			{checkError && <Banner tone="danger" title={t("settings.checkFailed")}>{checkError}</Banner>}
		</Glass>}
		<Glass className="d-panel"><div className="d-setting"><span className="vw-label">{t("settings.privacy")}</span><span className="vw-muted vw-small">{t("settings.privacyHint")}</span><Button icon="external" onClick={() => call("open_link", {url: "https://veilway-project.github.io/veilway-docs/privacy/"}).catch(error => toast({tone: "danger", title: t("settings.privacy"), body: error}))}>{t("terms.privacy")}</Button></div></Glass>
		<Button variant="quiet" icon="activity" className="d-start" onClick={() => setShowLog(true)}>{t("settings.log")}</Button>
	</div>;
}
