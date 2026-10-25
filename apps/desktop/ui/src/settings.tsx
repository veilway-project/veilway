import {Banner, Button, ConfirmDialog, Glass, NumberField, Segmented, SecretField, SelectField, StateBlock, Switch, TextField, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {ANDROID, failureText, useD, type Prefs} from "./kit.tsx";
import {call, type ProxySettings, type Settings, type UpdateInfo, type XrayState} from "./tauri.ts";

export function SettingsPage({prefs, onPrefs, settings, onSettings, logs, onUpdate}: {prefs: Prefs, onPrefs: (next: Partial<Prefs>) => void, settings: Settings, onSettings: (next: Settings) => void, logs: string[], onUpdate: (info: UpdateInfo | null) => void}) {
	const {t} = useD(), toast = useToast(), [showLog, setShowLog] = useState(false), [checking, setChecking] = useState(false), [checked, setChecked] = useState<UpdateInfo | null>(null), [checkError, setCheckError] = useState<string | null>(null);
	const [autostart, setAutostart] = useState<boolean | null>(null), [alpha, setAlpha] = useState<boolean | null>(null), [asking, setAsking] = useState(false), [xray, setXray] = useState<XrayState | null>(null), [removing, setRemoving] = useState(false);
	const [mirrorText, setMirrorText] = useState((settings.mirrors ?? []).join(" ")), mirrorList = mirrorText.split(/\s+/).filter(Boolean), mirrorsOk = mirrorList.length <= 4 && mirrorList.every(mirror => mirror.startsWith("https://") && mirror.length <= 256);
	const proxy = settings.proxy, [port, setPort] = useState<number | "">(proxy.port), [askingLan, setAskingLan] = useState(false), [askingLogin, setAskingLogin] = useState(false);
	const setProxy = (next: Partial<ProxySettings>) => onSettings({...settings, proxy: {...proxy, ...next}});
	const portOk = typeof port === "number" && Number.isInteger(port) && port >= 1024 && port <= 65535, loginOn = ANDROID || proxy.login || proxy.lan;
	const copy = (text: string) => navigator.clipboard.writeText(text).then(() => toast({tone: "success", title: t("settings.proxyCopied")}), () => toast({tone: "danger", title: t("settings.proxyCopyFailed")}));
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
		<Glass className="d-panel">
			<Switch label={t("settings.proxy")} hint={t("settings.proxyHint")} checked={proxy.on} onChange={on => setProxy({on})}/>
			{proxy.on && <>
				<div className="d-setting"><span className="vw-label">{t("settings.proxyMode")}</span><Segmented label={t("settings.proxyMode")} value={proxy.only ? "only" : "vpn"} onChange={mode => setProxy({only: mode === "only"})} options={[{value: "only", label: t("settings.proxyMode.only")}, {value: "vpn", label: t("settings.proxyMode.vpn")}]}/><span className="vw-muted vw-small">{t(proxy.only ? "settings.proxyModeOnlyHint" : "settings.proxyModeVpnHint")}</span>{!ANDROID && <span className="vw-muted vw-small">{t("settings.proxyLegacy")}</span>}</div>
				<SelectField label={t("settings.proxyKind")} value={proxy.kind} onChange={kind => setProxy({kind: kind === "socks5" || kind === "http" ? kind : "mixed"})} options={[{value: "mixed", label: t("settings.proxyKind.mixed")}, {value: "socks5", label: t("settings.proxyKind.socks5")}, {value: "http", label: t("settings.proxyKind.http")}]}/>
				<NumberField label={t("settings.proxyPort")} unit="" value={port} onChange={setPort} error={portOk ? undefined : t("settings.proxyPortBad")} onBlur={() => { if (portOk && port !== proxy.port) setProxy({port}); }}/>
				<Switch label={t("settings.proxyLan")} hint={t("settings.proxyLanHint")} checked={proxy.lan} onChange={on => { if (on) setAskingLan(true); else setProxy({lan: false}); }}/>
				{!ANDROID && <Switch label={t("settings.proxyLogin")} hint={t("settings.proxyLoginHint")} checked={loginOn} disabled={proxy.lan} onChange={on => { if (on) setProxy({login: true}); else setAskingLogin(true); }}/>}
				{loginOn && proxy.user && <div className="d-setting">
					<TextField label={t("settings.proxyUser")} technical readOnly value={proxy.user} onChange={() => {}}/>
					<Button icon="copy" onClick={() => copy(proxy.user)}>{t("settings.proxyCopy")}</Button>
					<SecretField label={t("settings.proxyPassword")} readOnly value={proxy.password} onChange={() => {}}/>
					<Button icon="copy" onClick={() => copy(proxy.password)}>{t("settings.proxyCopy")}</Button>
					<span className="vw-muted vw-small">{t("settings.proxyLoginNote")}</span>
				</div>}
			</>}
		</Glass>
		<ConfirmDialog open={askingLan} onOpenChange={setAskingLan} danger title={t("settings.proxyLanTitle")} body={t("settings.proxyLanBody")} confirmLabel={t("settings.proxyLanConfirm")} onConfirm={() => setProxy({lan: true})}/>
		<ConfirmDialog open={askingLogin} onOpenChange={setAskingLogin} danger title={t("settings.proxyLoginTitle")} body={t("settings.proxyLoginBody")} confirmLabel={t("settings.proxyLoginOff")} onConfirm={() => setProxy({login: false})}/>
		<ConfirmDialog open={asking} onOpenChange={setAsking} title={t("alpha.title")} body={t("alpha.warning")} confirmLabel={t("alpha.confirm")} onConfirm={() => { saveAlpha(true); }}/>
		{!ANDROID && <Glass className="d-panel">
			<Switch label={t("settings.autostart")} checked={autostart ?? false} disabled={autostart === null} onChange={setStart}/>
			<Switch label={t("settings.autoUpdate")} checked={settings.auto_update} onChange={auto_update => onSettings({...settings, auto_update})}/>
			<div className="d-head"><span className="vw-muted">{checked ? t("settings.version", {version: checked.current}) : null}</span><Button icon="refresh" disabled={checking} onClick={check}>{t("settings.check")}</Button></div>
			{checked && !checked.available && <Banner tone="success" title={t("settings.upToDate")}/>}
			{checkError && <Banner tone="danger" title={t("settings.checkFailed")}>{checkError}</Banner>}
		</Glass>}
		{!ANDROID && xray?.supported && <Glass className="d-panel"><div className="d-setting"><span className="vw-label">{t("settings.xray")}</span><span className="vw-muted vw-small">{xray.installed ? t("settings.xrayInstalled", {release: `\u2066${xray.release}\u2069`}) : t("settings.xrayMissing")}</span>{xray.installed && <Button onClick={() => setRemoving(true)}>{t("settings.xrayRemove")}</Button>}</div><TextField label={t("settings.xrayMirrors")} hint={t("settings.xrayMirrorsHint")} placeholder="https://mirror.example.com" technical optional value={mirrorText} onChange={setMirrorText} error={mirrorsOk ? undefined : t("settings.xrayMirrorsBad")} onBlur={() => { if (mirrorsOk && mirrorList.join(" ") !== (settings.mirrors ?? []).join(" ")) onSettings({...settings, mirrors: mirrorList}); }}/></Glass>}
		<ConfirmDialog open={removing} onOpenChange={setRemoving} danger title={t("settings.xrayRemoveTitle")} body={t("settings.xrayRemoveBody")} confirmLabel={t("settings.xrayRemove")} onConfirm={removeXray}/>
		<Glass className="d-panel"><div className="d-setting"><span className="vw-label">{t("settings.privacy")}</span><span className="vw-muted vw-small">{t("settings.privacyHint")}</span><Button icon="external" onClick={() => call("open_link", {url: `https://veilway-project.github.io/veilway-docs/${settings.locale === "fa" ? "fa/" : ""}legal/app-privacy/`}).catch(error => toast({tone: "danger", title: t("settings.privacy"), body: error}))}>{t("terms.privacy")}</Button></div></Glass>
		<Button variant="quiet" icon="activity" className="d-start" onClick={() => setShowLog(true)}>{t("settings.log")}</Button>
	</div>;
}
