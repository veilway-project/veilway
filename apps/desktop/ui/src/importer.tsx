import {Banner, Button, Glass, List, ListRow, SecretField, TextField, UnsafeNote} from "@veilway/ui";
import {useEffect, useRef, useState, type ChangeEvent, type FormEvent} from "react";
import {agreement, ANDROID, base64, CAMERA, failureText, LegacyNote, protocolName, useD} from "./kit.tsx";
import {ScanDialog} from "./scan.tsx";
import {asksPrivate, call, type BundleReview, type LegacyOffer, type Offer, type PrivateAsk, type Review, type Subscription} from "./tauri.ts";

// Three steps, each a plain choice: what to add, whether to reach out for it (or read it), and whether to keep what came back. Nothing leaves the device before the second step's yes.
export function Importer({first, onCancel, onDone, onAccept, onBundle}: {first: boolean, onCancel: () => void, onDone: (library: Subscription[]) => void, onAccept: (id: string, terms: string) => void, onBundle: (review: BundleReview) => void}) {
	const {t, locale, number} = useD(), [text, setText] = useState(""), [offer, setOffer] = useState<Offer | LegacyOffer | null>(null), [review, setReview] = useState<Review | null>(null), [asked, setAsked] = useState<PrivateAsk["ask_private"] | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [sealed, setSealed] = useState<string | null>(null), [password, setPassword] = useState(""), [scanning, setScanning] = useState(false);
	const fileInput = useRef<HTMLInputElement>(null), qrInput = useRef<HTMLInputElement>(null), cameraInput = useRef<HTMLInputElement>(null);
	const run = <T,>(work: Promise<T>, then: (value: T) => void) => { setBusy(true); setError(null); work.then(then, setError).finally(() => setBusy(false)); };
	const bundle = () => run(call("bundle_pick"), found => { if (found) onBundle(found); });
	const qr = (picture: Blob) => run(base64(picture).catch(() => Promise.reject(t("import.readFailed"))).then(data => call("import_qr", {data})), setOffer);
	const proceed = (agreed?: string[]) => run(call("import_proceed", agreed ? {private: agreed} : {}), found => { if (asksPrivate(found)) { setAsked(found.ask_private); } else { setAsked(null); setReview(found); } });
	const cancel = () => { if (offer || review) call("import_cancel").catch(() => {}); setSealed(null); setPassword(""); setOffer(null); setReview(null); setAsked(null); setError(null); if (!first) onCancel(); };
	useEffect(() => {
		if (offer || review) return;
		const paste = (event: ClipboardEvent) => { const picture = Array.from(event.clipboardData?.files ?? []).find(f => f.type.startsWith("image/")); if (picture) { event.preventDefault(); qr(picture); } };
		addEventListener("paste", paste);
		return () => removeEventListener("paste", paste);
	}, [offer, review]);
	const submit = (event: FormEvent) => { event.preventDefault(); if (!text.trim()) return setError(t("import.needLink")); run(call("import_open", {source: {kind: "link", text: text.trim()}}), setOffer); };
	const picked = (event: ChangeEvent<HTMLInputElement>, kind: "file" | "qr" | "camera") => {
		const file = event.target.files?.[0];
		event.target.value = "";
		if (!file) return;
		if (kind === "qr") return qr(file);
		// Android: the phone's camera app takes the photo. It is brought down to 2000 pixels first, which keeps a code readable and the decode quick on a phone.
		if (kind === "camera") return void createImageBitmap(file).then(bitmap => { const scale = Math.min(1, 2000 / Math.max(bitmap.width, bitmap.height)), canvas = document.createElement("canvas"); [canvas.width, canvas.height] = [Math.round(bitmap.width * scale), Math.round(bitmap.height * scale)]; canvas.getContext("2d")!.drawImage(bitmap, 0, 0, canvas.width, canvas.height); return new Promise<Blob>((done, fail) => canvas.toBlob(blob => blob ? done(blob) : fail(), "image/jpeg", 0.9)); }).then(qr, () => qr(file));
		// A sealed file is told by its first bytes, and the password is asked for here. The file stays in this window only until it is opened or backed out of.
		run(base64(file).catch(() => Promise.reject(t("import.readFailed"))).then(data => call("import_open", {source: {kind: "file", data}}).catch(code => code === "needs_password" ? (setSealed(data), null) : Promise.reject(code))), found => { if (found) setOffer(found); });
	};
	const failure = error && <Banner tone="danger" title={t("import.failed")}>{failureText(error, t)}</Banner>;
	const key = (fingerprint: string) => <p className="d-key"><span className="vw-muted vw-small">{t("import.key")}</span><span className="vw-code" dir="ltr">{fingerprint}</span></p>;
	if (review) {
		const preview = review.preview, terms = agreement(preview);
		return <div className="d-page">
			<Glass className="d-panel">
				<h1 className="vw-h2">{t("import.review.title", {provider: preview.provider})}</h1>
				<p className="vw-muted">{t("import.review.body")}</p>
				{key(review.fingerprint)}
				{review.endpoint_changed && <Banner tone="warning" title={t("import.review.endpointTitle")}>{t("import.review.endpoint")}</Banner>}
				{review.replaces && <Banner tone="info" title={t("import.review.replaces")}/>}
				{review.moving && <Banner tone="warning" title={t("import.review.moveTitle")}>{t(review.moving.check === "plain" ? "import.review.movePlain" : review.moving.check === "pinned" ? "import.review.movePinned" : "import.review.move", {from: review.moving.from ?? "", host: review.moving.host})}</Banner>}
				<List label={t("import.review.connections")}>{preview.profiles.map(profile => <ListRow key={profile.id} title={profile.name} detail={[t("import.review.exits", {count: profile.exits.length}), profile.left_out ? t("profile.leftOut") : null].filter(Boolean).join(locale === "fa" ? "، " : ", ")}/>)}</List>
				{review.left_out.length > 0 && <p className="vw-muted vw-small">{t("import.review.leftOut", {count: review.left_out.length})}</p>}
				{terms && <div className="d-terms"><p>{t("import.review.terms", {provider: preview.provider})}</p><div className="d-actions d-start">{([["terms.terms", preview.terms], ["terms.privacy", preview.privacy]] as const).map(([label, url]) => url && <Button key={label} size="sm" icon="external" onClick={() => call("open_link", {url}).catch(setError)}>{t(label)}</Button>)}</div></div>}
				{failure}
				<div className="d-actions"><Button onClick={() => run(call("import_keep", {keep: false}), () => { setReview(null); setOffer(null); if (!first) onCancel(); })} disabled={busy}>{t("import.discard")}</Button><Button variant="primary" disabled={busy} onClick={() => run(call("import_keep", {keep: true}), found => { if (terms) onAccept(preview.id, terms); onDone(found); })}>{t(terms ? "import.acceptKeep" : "import.keep")}</Button></div>
			</Glass>
		</div>;
	}
	if (offer && asked) {
		const addresses = `\u2066${asked.addresses.join(", ")}\u2069`;
		return <div className="d-page">
			<Glass className="d-panel">
				<h1 className="vw-h2">{t("private.title")}</h1>
				<p>{t("private.body", {addresses})}</p>
				{failure}
				<div className="d-actions"><Button onClick={cancel} disabled={busy}>{t("common.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => proceed(asked.addresses)}>{t("private.yes")}</Button></div>
			</Glass>
		</div>;
	}
	if (sealed !== null && !offer) return <div className="d-page">
		<Glass className="d-panel">
			<h1 className="vw-h2">{t("sealed.title")}</h1>
			<p>{t("sealed.body")}</p>
			<form className="d-form" onSubmit={event => { event.preventDefault(); if (!password) return; run(call("import_open", {source: {kind: "sealed", data: sealed, password}}), found => { setSealed(null); setPassword(""); setOffer(found); }); }}>
				<SecretField label={t("sealed.password")} value={password} onChange={setPassword} autoFocus/>
				{failure}
				<div className="d-actions"><Button type="button" onClick={cancel} disabled={busy}>{t("common.cancel")}</Button><Button type="submit" variant="primary" disabled={busy || !password}>{t(busy ? "sealed.opening" : "sealed.open")}</Button></div>
			</form>
		</Glass>
	</div>;
	// Links of another app: read and checked already, nothing to fetch, so keeping them is the one step. What the table refused is listed with its reason; it is kept too, marked, and cannot connect.
	if (offer?.kind === "legacy") return <div className="d-page">
		<Glass className="d-panel">
			<h1 className="vw-h2">{t("import.legacy.title")}</h1>
			<p>{t("import.legacy.body")}</p>
			<List label={t("import.review.connections")}>{offer.connections.map((connection, i) => <ListRow key={i} title={connection.name} detail={[protocolName(connection.protocol), t("xray.tcpUdp"), t("xray.unsigned")].join(locale === "fa" ? "، " : ", ")} trailing={connection.unsafe_cap ? <UnsafeNote/> : undefined}/>)}</List>
			{offer.refused.length > 0 && <Banner tone="warning" title={t("import.legacy.refused", {count: offer.refused.length})}><span className="d-refused">{offer.refused.map((refused, i) => <span key={i}><strong>{refused.name}</strong> {failureText(refused.code, t)}</span>)}</span></Banner>}
			{offer.skipped > 0 && <p className="vw-muted vw-small">{t("import.legacy.skipped", {count: offer.skipped})}</p>}
			{offer.cut && <p className="vw-muted vw-small">{t("import.legacy.cut", {count: number(256)})}</p>}
			<LegacyNote/>
			{failure}
			<div className="d-actions"><Button onClick={cancel} disabled={busy}>{t("common.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => run(call("import_keep", {keep: true}), onDone)}>{t("import.legacy.keep")}</Button></div>
		</Glass>
	</div>;
	if (offer) {
		const native = offer.kind === "native", host = offer.host ?? "";
		return <div className="d-page">
			<Glass className="d-panel">
				<h1 className="vw-h2">{native ? t("import.native.title", {host}) : t("import.carried.title")}</h1>
				<p>{native ? t("import.native.body", {host}) : t(offer.in_file ? "import.carried.bodyFile" : "import.carried.body")}</p>
				{key(offer.fingerprint)}
				{native && offer.pinned && <p className="vw-muted vw-small">{t("import.pinned")}</p>}
				{native && offer.plain && <Banner tone="warning" title={t("import.plain")}/>}
				{failure}
				<div className="d-actions"><Button onClick={cancel} disabled={busy}>{t("common.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => proceed()}>{native ? t("import.native.yes", {host}) : t("import.carried.yes")}</Button></div>
			</Glass>
		</div>;
	}
	return <div className="d-page">
		<div className="d-intro"><h1 className="vw-h1">{t(first ? "empty.title" : "import.title")}</h1><p className="vw-muted">{t("import.body")}</p></div>
		<Glass className="d-panel">
			<form className="d-form" onSubmit={submit}>
				<TextField label={t("import.link")} technical value={text} onChange={setText} placeholder="veilway://" autoComplete="off"/>
				<Button type="submit" variant="primary" disabled={busy}>{t("import.continue")}</Button>
			</form>
			<div className="d-actions d-start">
				<Button icon="upload" disabled={busy} onClick={() => fileInput.current?.click()}>{t("import.file")}</Button>
				<Button icon="upload" disabled={busy} onClick={() => qrInput.current?.click()}>{t("import.qr")}</Button>
				{CAMERA && <Button disabled={busy} onClick={() => ANDROID ? cameraInput.current?.click() : setScanning(true)}>{t("import.scan")}</Button>}
				<Button icon="upload" disabled={busy} onClick={bundle}>{t("bundle.open")}</Button>
			</div>
			{ANDROID && <p className="vw-muted vw-small">{t("scan.privacyApp")}</p>}
			{!matchMedia("(pointer: coarse)").matches && <p className="vw-muted vw-small">{t("import.pasteHint")}</p>}
			<input ref={fileInput} type="file" hidden onChange={event => picked(event, "file")}/>
			<input ref={cameraInput} type="file" accept="image/*" capture="environment" hidden onChange={event => picked(event, "camera")}/>
			<input ref={qrInput} type="file" accept="image/png,image/jpeg,image/gif,image/bmp,image/webp" hidden onChange={event => picked(event, "qr")}/>
			{failure}
			{scanning && <ScanDialog onClose={() => setScanning(false)} onFound={found => { setScanning(false); setOffer(found); }}/>}
			{!first && <Button variant="quiet" className="d-start" onClick={cancel}>{t("common.cancel")}</Button>}
		</Glass>
	</div>;
}
