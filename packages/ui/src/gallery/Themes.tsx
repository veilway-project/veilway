import {useMemo, useRef, useState, type CSSProperties} from "react";
import hostile from "../../test/hostile.veilway-theme?raw";
import {BLUR_MAX, BUILTIN, Banner, Button, COLOR_KEYS, Glass, MAX_BYTES, MAX_NAME, RatingBadge, Segmented, Slider, THEME_EXTENSION, TextField, UsageBar, minTint, palette, parseHex, serializeTheme, themeVars, validateTheme, type Issue, type Theme} from "../index.ts";
import {Panel, useG} from "./shared.tsx";

const GB = 1024 ** 3;

// The editor never trusts its own draft: every change is written out as a theme file and read back through the same validator an imported file goes through. What you see in the preview is what the validator returned.
export function Themes({active, onApply}: {active: Theme, onApply: (theme: Theme | null) => void}) {
	const {t, number} = useG(), file = useRef<HTMLInputElement>(null), [draft, setDraft] = useState<Theme>(active), [refused, setRefused] = useState<Issue[] | null>(null), [good, setGood] = useState<Theme>(active);
	const verdict = useMemo(() => validateTheme(serializeTheme(draft)), [draft]), shown = verdict.ok ? verdict.theme : good, floor = minTint(palette(shown)) ?? 1;
	// The preview keeps showing the last theme that passed while the draft is unreadable.
	const update = (next: Theme) => {
		const result = validateTheme(serializeTheme(next));
		setDraft(next);
		if (result.ok) setGood(result.theme);
	};
	const load = (text: string) => {
		const result = validateTheme(text);
		setRefused(result.ok ? null : result.errors);
		if (result.ok) update(result.theme);
	};
	return <>
		<Panel title={t("g.theme.title")} note={t("g.theme.note", {extension: THEME_EXTENSION})}>
			<div className="g-cluster">
				<Button icon="upload" onClick={() => file.current?.click()}>{t("g.theme.import")}</Button>
				<input ref={file} hidden tabIndex={-1} type="file" accept={THEME_EXTENSION + ",application/json"} onChange={event => {
					const picked = event.target.files?.[0];
					event.target.value = "";
					// The size is checked before a single byte is read.
					if (picked && picked.size > MAX_BYTES) setRefused([{code: "too-large", path: ""}]);
					else if (picked) picked.text().then(load, () => setRefused([{code: "not-text", path: ""}]));
				}}/>
				<Button icon="download" disabled={!verdict.ok} onClick={() => {
					const link = document.createElement("a"), url = URL.createObjectURL(new Blob([serializeTheme(shown)], {type: "application/json"}));
					link.href = url;
					link.download = (shown.name.replace(/[^\p{L}\p{N}_-]+/gu, "-") || "theme") + THEME_EXTENSION;
					link.click();
					URL.revokeObjectURL(url);
				}}>{t("g.theme.export")}</Button>
				<Button variant="primary" disabled={!verdict.ok} onClick={() => onApply(shown)}>{t("g.theme.apply")}</Button>
				<Button variant="quiet" onClick={() => { onApply(null); update(BUILTIN[draft.scheme]); setRefused(null); }}>{t("g.theme.reset")}</Button>
				<Button variant="quiet" icon="warning" onClick={() => load(hostile)}>{t("g.theme.hostile")}</Button>
			</div>
			{refused && <Banner tone="danger" title={t("g.theme.refused")}><ul className="g-issues">{refused.map((issue, i) => <li key={i}>{t(`theme.error.${issue.code}`, {path: issue.path})}</li>)}</ul></Banner>}
			{!verdict.ok && <Banner tone="danger" title={t("g.theme.unreadable")}><ul className="g-issues">{verdict.errors.map((issue, i) => <li key={i}>{t(`theme.error.${issue.code}`, {path: issue.path})}</li>)}</ul></Banner>}
			{verdict.ok && verdict.corrections.length > 0 && <Banner tone="info" title={t("g.theme.corrected")}><ul className="g-issues">{verdict.corrections.map((issue, i) => <li key={i}>{t(`theme.error.${issue.code}`, {path: issue.path})}</li>)}</ul></Banner>}
			<div className="g-editor">
				<div className="g-stack">
					<TextField label={t("g.theme.name")} value={draft.name} maxLength={MAX_NAME} onChange={name => update({...draft, name})}/>
					<Segmented label={t("g.set.scheme")} value={draft.scheme} onChange={scheme => update({...BUILTIN[scheme as Theme["scheme"]], name: draft.name})} options={[{value: "dark", label: t("g.set.dark")}, {value: "light", label: t("g.set.light")}]}/>
					<Slider label={t("g.theme.tint")} hint={t("g.theme.tintHint", {tint: number(floor, {maximumFractionDigits: 2})})} min={0} max={1} step={0.01} value={draft.glass.tint} display={number(shown.glass.tint, {minimumFractionDigits: 2, maximumFractionDigits: 2})} onChange={tint => update({...draft, glass: {...draft.glass, tint}})}/>
					<Slider label={t("g.theme.blur")} min={0} max={BLUR_MAX} step={1} value={draft.glass.blur} display={number(draft.glass.blur)} onChange={blur => update({...draft, glass: {...draft.glass, blur}})}/>
					<ul className="g-colors">{COLOR_KEYS.map(key => <li key={key}>
						<input type="color" aria-label={t(`g.token.${key}`)} value={parseHex(draft.colors[key]) ? draft.colors[key].toLowerCase() : "#000000"} onChange={event => update({...draft, colors: {...draft.colors, [key]: event.target.value.toUpperCase()}})}/>
						<span className="g-swatch-text"><span className="vw-code">{key}</span><span className="vw-muted vw-small">{t(`g.token.${key}`)}</span></span>
						<span className="vw-code vw-muted vw-small">{shown.colors[key]}</span>
					</li>)}</ul>
				</div>
				<div className="vw-root vw-backdrop g-preview" data-scheme={shown.scheme} data-material="glass" style={themeVars(shown) as CSSProperties}>
					<Glass className="g-pad g-stack">
						<h3 className="vw-h2">{shown.name}</h3>
						<p className="vw-muted">{t("g.theme.previewBody")}</p>
						<div className="g-cluster"><Button variant="primary" icon="power">{t("action.connect")}</Button><Button>{t("action.cancel")}</Button></div>
						<div className="g-cluster"><RatingBadge rating="protected"/><RatingBadge rating="detectable"/><RatingBadge rating="unsafe"/></div>
						<UsageBar label={t("g.client.month")} used={31.4 * GB} total={50 * GB}/>
						<input className="vw-input vw-code" dir="ltr" readOnly aria-label={t("g.form.address")} value="fra.vpn.example.net:8443"/>
					</Glass>
				</div>
			</div>
		</Panel>
	</>;
}
