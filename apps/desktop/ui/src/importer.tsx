import {Banner, Button, Glass, List, ListRow, TextField} from "@veilway/ui";
import {useEffect, useRef, useState, type ChangeEvent, type FormEvent} from "react";
import {base64, useD} from "./kit.tsx";
import {asksPrivate, call, type Offer, type PrivateAsk, type Review, type Subscription} from "./tauri.ts";

// Three steps, each a plain choice: what to add, whether to reach out for it (or read it), and whether to keep what came back. Nothing leaves the device before the second step's yes.
export function Importer({first, onCancel, onDone}: {first: boolean, onCancel: () => void, onDone: (library: Subscription[]) => void}) {
	const {t} = useD(),[text, setText] = useState(""), [offer, setOffer] = useState<Offer | null>(null), [review, setReview] = useState<Review | null>(null), [asked, setAsked] = useState<PrivateAsk["ask_private"] | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
	const fileInput = useRef<HTMLInputElement>(null), qrInput = useRef<HTMLInputElement>(null);
	const run = <T,>(work: Promise<T>, then: (value: T) => void) => { setBusy(true); setError(null); work.then(then, setError).finally(() => setBusy(false)); };
	const qr = (picture: Blob) => run(base64(picture).catch(() => Promise.reject(t("import.readFailed"))).then(data => call("import_qr", {data})), setOffer);
	const proceed = (agreed?: string[]) => run(call("import_proceed", agreed ? {private: agreed} : {}), found => { if (asksPrivate(found)) { setAsked(found.ask_private); } else { setAsked(null); setReview(found); } });
	const cancel = () => { if (offer || review) call("import_cancel").catch(() => {}); setOffer(null); setReview(null); setAsked(null); setError(null); if (!first) onCancel(); };
	useEffect(() => {
		if (offer || review) return;
		const paste = (event: ClipboardEvent) => { const picture = Array.from(event.clipboardData?.files ?? []).find(f => f.type.startsWith("image/")); if (picture) { event.preventDefault(); qr(picture); } };
		addEventListener("paste", paste);
		return () => removeEventListener("paste", paste);
	}, [offer, review]);
	const submit = (event: FormEvent) => { event.preventDefault(); if (!text.trim()) return setError(t("import.needLink")); run(call("import_open", {source: {kind: "link", text: text.trim()}}), setOffer); };
	const picked = (event: ChangeEvent<HTMLInputElement>, kind: "file" | "qr") => {
		const file = event.target.files?.[0];
		event.target.value = "";
		if (!file) return;
		if (kind === "qr") return qr(file);
		run(base64(file).catch(() => Promise.reject(t("import.readFailed"))).then(data => call("import_open", {source: {kind: "file", data}})), setOffer);
	};
	const failure = error && <Banner tone="danger" title={t("import.failed")}>{error}</Banner>;
	const key = (fingerprint: string) => <p className="d-key"><span className="vw-muted vw-small">{t("import.key")}</span><span className="vw-code" dir="ltr">{fingerprint}</span></p>;
	if (review) {
		const preview = review.preview;
		return <div className="d-page">
			<Glass className="d-panel">
				<h1 className="vw-h2">{t("import.review.title", {provider: preview.provider})}</h1>
				<p className="vw-muted">{t("import.review.body")}</p>
				{key(review.fingerprint)}
				{review.endpoint_changed && <Banner tone="warning" title={t("import.review.endpointTitle")}>{t("import.review.endpoint")}</Banner>}
				{review.replaces && <Banner tone="info" title={t("import.review.replaces")}/>}
				<List label={t("import.review.connections")}>{preview.profiles.map(profile => <ListRow key={profile.id} title={profile.name} detail={t("import.review.exits", {count: profile.exits.length})}/>)}</List>
				{review.left_out.length > 0 && <p className="vw-muted vw-small">{t("import.review.leftOut", {count: review.left_out.length})}</p>}
				{failure}
				<div className="d-actions"><Button onClick={() => run(call("import_keep", {keep: false}), () => { setReview(null); setOffer(null); if (!first) onCancel(); })} disabled={busy}>{t("import.discard")}</Button><Button variant="primary" disabled={busy} onClick={() => run(call("import_keep", {keep: true}), onDone)}>{t("import.keep")}</Button></div>
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
	if (offer) {
		const native = offer.kind === "native", host = offer.host ?? "";
		return <div className="d-page">
			<Glass className="d-panel">
				<h1 className="vw-h2">{native ? t("import.native.title", {host}) : t("import.carried.title")}</h1>
				<p>{native ? t("import.native.body", {host}) : t(offer.in_file ? "import.carried.bodyFile" : "import.carried.body")}</p>
				{key(offer.fingerprint)}
				{native && offer.pinned && <p className="vw-muted vw-small">{t("import.pinned")}</p>}
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
			</div>
			{!matchMedia("(pointer: coarse)").matches && <p className="vw-muted vw-small">{t("import.pasteHint")}</p>}
			<input ref={fileInput} type="file" hidden onChange={event => picked(event, "file")}/>
			<input ref={qrInput} type="file" accept="image/png,image/jpeg,image/gif,image/bmp,image/webp" hidden onChange={event => picked(event, "qr")}/>
			{failure}
			{!first && <Button variant="quiet" className="d-start" onClick={cancel}>{t("common.cancel")}</Button>}
		</Glass>
	</div>;
}
