import {Banner, Button, ConfirmDialog, Glass, List, ListRow} from "@veilway/ui";
import {useState} from "react";
import {type DesktopKey} from "./locales/en.ts";
import {ANDROID, failureText, fromUnix, useD} from "./kit.tsx";
import {call, type BundleApp, type BundleFound, type BundleNotice, type BundleReview, type Subscription} from "./tauri.ts";

const MEGABYTE = 1024 * 1024;

// A bundle from a file, item by item: each app part, newer document and notice has its own yes. Nothing is applied before it, and closing the review deletes the bundle's copy. The helper sends codes and part numbers; the words are the locale packs'.
export function Bundle({review, onClose, onLibrary}: {review: BundleReview, onClose: () => void, onLibrary: (library: Subscription[]) => void}) {
	const {t, date, number} = useD(), [busy, setBusy] = useState<string | null>(null), [done, setDone] = useState<string[]>([]), [error, setError] = useState<string | null>(null), [asking, setAsking] = useState<BundleApp | null>(null);
	const run = <T,>(key: string, work: Promise<T>, then: (value: T) => void) => { setBusy(key); setError(null); work.then(value => { setDone(list => [...list, key]); then(value); }, error => setError(failureText(error, t))).finally(() => setBusy(null)); };
	const close = () => call("bundle_close").catch(() => {}).finally(onClose);
	const install = () => run("app", call("bundle_install"), () => {});
	const failure = error && <Banner tone="danger" title={t("bundle.failed")}>{error}</Banner>;
	const appDetail = (app: BundleApp) => app.installable ? t("bundle.app.ready", {version: app.version, megabytes: number(Math.ceil(app.size / MEGABYTE))}) : app.newer ? t("bundle.app.other", {version: app.version}) : t("bundle.app.old", {version: app.version});
	const foundDetail = (found: BundleFound) => found.code === null ? t("bundle.found.newer", {serial: number(found.serial ?? 0), date: date(fromUnix(found.expires_at ?? 0))}) : found.code === "same" ? t("bundle.found.same") : t("bundle.found.refused");
	const droppedText = (part: number, code: string) => t(`bundle.dropped.${code}` as DesktopKey, {part: number(part + 1)});
	const noticeLine = (notice: BundleNotice) => t("bundle.notice.from", {providers: notice.providers.join(", ")});
	const appDone = done.includes("app");
	return <div className="d-page">
		<div className="d-intro"><h1 className="vw-h1">{t("bundle.title")}</h1><p className="vw-muted">{t("bundle.body")}</p></div>
		<Glass className="d-panel">
			<p className="vw-muted vw-small">{t("bundle.signed")} <span className="vw-code" dir="ltr">{review.fingerprint}</span></p>
			<p>{review.release ? t("bundle.release") : t("bundle.provider", {provider: review.signer ?? ""})}</p>
			<p className="vw-muted vw-small">{t("bundle.created", {date: date(fromUnix(review.created_at))})}</p>
			{review.old && <Banner tone="warning" title={t("bundle.old")}/>}
			{review.future && <Banner tone="warning" title={t("bundle.future")}/>}
			{failure}
			{review.apps.length > 0 && <>
				<h2 className="vw-h3">{t("bundle.section.app")}</h2>
				<List label={t("bundle.section.app")}>{review.apps.map(app => <ListRow key={app.platform} title={app.platform} detail={appDetail(app)} trailing={app.installable && !appDone ? <Button size="sm" variant="primary" disabled={busy !== null} onClick={() => setAsking(app)}>{t("bundle.app.install")}</Button> : undefined}/>)}</List>
			</>}
			{review.found.length > 0 && <>
				<h2 className="vw-h3">{t("bundle.section.subscriptions")}</h2>
				<List label={t("bundle.section.subscriptions")}>{review.found.map((found, index) => {
					const key = "doc:" + (found.subscription ?? index);
					const applied = done.includes(key);
					return <ListRow key={key} title={found.provider} detail={applied ? t("bundle.found.done") : foundDetail(found)} trailing={found.subscription && found.code === null && !applied ? <Button size="sm" disabled={busy !== null} onClick={() => run(key, call("bundle_document", {id: found.subscription ?? ""}), onLibrary)}>{t("bundle.found.update")}</Button> : undefined}/>;
				})}</List>
			</>}
			{review.notices.length > 0 && <>
				<h2 className="vw-h3">{t("bundle.section.notices")}</h2>
				{review.notices.map((notice, index) => <div key={index} className="d-terms"><p className="vw-muted vw-small">{noticeLine(notice)}</p><p>{notice.text}</p></div>)}
				<div className="d-actions d-start"><Button size="sm" disabled={busy !== null || done.includes("notices")} onClick={() => run("notices", call("bundle_notices"), () => {})}>{t(done.includes("notices") ? "bundle.notice.done" : "bundle.notice.keep")}</Button></div>
			</>}
			{review.dropped.length > 0 && <>
				<h2 className="vw-h3">{t("bundle.section.dropped")}</h2>
				<List label={t("bundle.section.dropped")}>{review.dropped.map(item => <ListRow key={item.part} title={droppedText(item.part, item.code)}/>)}</List>
			</>}
			{review.apps.length === 0 && review.found.length === 0 && review.notices.length === 0 && <p className="vw-muted">{t("bundle.empty")}</p>}
			<div className="d-actions"><Button variant="primary" onClick={close}>{t("bundle.close")}</Button></div>
		</Glass>
		<ConfirmDialog open={asking !== null} onOpenChange={open => { if (!open) setAsking(null); }} title={t("bundle.install.title")} body={asking ? t(ANDROID ? "bundle.install.androidBody" : "bundle.install.body", {version: asking.version}) : ""} confirmLabel={t("bundle.install.yes")} onConfirm={() => { setAsking(null); install(); }}/>
	</div>;
}
