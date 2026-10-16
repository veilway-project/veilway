import {Banner, Button, Dialog, Segmented, SecretField, TextField, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {ANDROID, failureText, useD} from "./kit.tsx";
import {call, type Subscription} from "./tauri.ts";

const PASSWORD_MIN = 10;

// Shares the subscription's link and nothing else: the device's own keys never leave it. The link is held here only while the dialog is open.
export function ShareDialog({subscription, onClose}: {subscription: Subscription, onClose: () => void}) {
	const {t} = useD(), toast = useToast(), [way, setWay] = useState("text"), [shared, setShared] = useState<{link: string, qr: string} | null>(null), [password, setPassword] = useState(""), [again, setAgain] = useState(""), [tried, setTried] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
	useEffect(() => { if (way !== "file" && !shared) call("share_link", {id: subscription.id}).then(setShared, setError); }, [way, shared, subscription.id]);
	const problem = [...password].length < PASSWORD_MIN ? t("share.passwordShort", {count: PASSWORD_MIN}) : password !== again ? t("share.passwordMismatch") : undefined;
	const save = () => {
		setTried(true);
		if (problem) return;
		setBusy(true);
		setError(null);
		call("share_file", {id: subscription.id, password}).then(saved => { if (saved) { toast({tone: "success", title: t("share.saved")}); onClose(); } }, setError).finally(() => setBusy(false));
	};
	const copy = (link: string) => navigator.clipboard.writeText(link).then(() => toast({tone: "success", title: t("share.copied")}), () => toast({tone: "danger", title: t("share.copyFailed")}));
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("share.title", {provider: subscription.provider})} description={t("share.why")}>
		<Segmented label={t("share.way")} value={way} onChange={next => { setWay(next); setError(null); }} options={[{value: "text", label: t("share.text")}, {value: "qr", label: t("share.qr")}, {value: "file", label: t("share.file")}]}/>
		{way === "text" && <div className="d-share">
			<TextField label={t("share.link")} technical readOnly value={shared?.link ?? ""} onChange={() => {}}/>
			<div className="d-actions d-start"><Button variant="primary" icon="copy" disabled={!shared} onClick={() => shared && copy(shared.link)}>{t("share.copy")}</Button>{ANDROID && <Button disabled={!shared} onClick={() => shared && call("share_text", {text: shared.link}).catch(setError)}>{t("share.send")}</Button>}</div>
		</div>}
		{way === "qr" && <div className="d-share">{shared ? <img className="d-qr" src={`data:image/svg+xml;base64,${btoa(shared.qr)}`} alt={t("share.qrAlt")}/> : !error && <p className="vw-muted">{t("common.loading")}</p>}</div>}
		{way === "file" && <form className="d-share" onSubmit={event => { event.preventDefault(); save(); }}>
			<p className="vw-muted">{t("share.fileBody")}</p>
			<SecretField label={t("share.password")} value={password} onChange={setPassword}/>
			<SecretField label={t("share.passwordAgain")} value={again} onChange={setAgain} error={tried ? problem : undefined}/>
			<Banner tone="info" title={t("share.channel")}/>
			<div className="d-actions d-start"><Button type="submit" variant="primary" disabled={busy}>{t(busy ? "share.saving" : "share.saveFile")}</Button></div>
		</form>}
		{error && <Banner tone="danger" title={t("share.failed")}>{failureText(error, t)}</Banner>}
	</Dialog>;
}
