import {useState, type CSSProperties} from "react";
import {Button, COLOR_KEYS, DataTable, Glass, Icon, Tabs, audit, minTint, palette, type Theme} from "../index.ts";
import {SAMPLE_KEY} from "./data.ts";
import {Panel, useG} from "./shared.tsx";

const TYPE_STEPS = [["--text-7", "vw-h1"], ["--text-6", "vw-h1"], ["--text-5", "vw-h2"], ["--text-4", "vw-h3"], ["--text-3", ""], ["--text-2", "vw-muted"], ["--text-1", "vw-muted"]] as const;
const SPACES = ["--s-1", "--s-2", "--s-3", "--s-4", "--s-5", "--s-6", "--s-7", "--s-8"];

export function Foundations({theme}: {theme: Theme}) {
	const {t, number} = useG(), [tab, setTab] = useState("tokens"), [moved, setMoved] = useState(false);
	const colors = palette(theme), floor = minTint(colors) ?? 1, findings = audit(colors, floor);
	return <>
		<Panel title={t("g.found.colour")} note={t("g.found.colourNote")}>
			<Tabs label={t("g.found.colour")} value={tab} onChange={setTab} items={[
				{id: "tokens", label: t("g.found.tokens"), content: <ul className="g-swatches">{COLOR_KEYS.map(key => <li key={key}><span className="g-chip" style={{background: theme.colors[key]}}/><span className="g-swatch-text"><span className="vw-code">{key}</span><span className="vw-muted vw-small">{t(`g.token.${key}`)}</span></span><span className="vw-code vw-muted vw-small">{theme.colors[key]}</span></li>)}</ul>},
				{id: "contrast", label: t("g.found.pairs"), content: <DataTable caption={t("g.found.pairs")} rows={findings} rowKey={f => f.fg + f.on} columns={[
					{id: "pair", header: t("g.found.pair"), cell: f => <span className="vw-code">{f.fg} / {f.on}</span>},
					{id: "ratio", header: t("g.found.ratio"), align: "end", cell: f => <span className="vw-num">{number(f.ratio, {minimumFractionDigits: 2, maximumFractionDigits: 2})}</span>},
					{id: "min", header: t("g.found.minimum"), align: "end", cell: f => <span className="vw-num">{number(f.min)}</span>},
					{id: "result", header: t("g.found.result"), cell: f => <span className="g-result"><Icon name={f.ratio >= f.min ? "check" : "error"}/>{t(f.ratio >= f.min ? "g.found.passes" : "g.found.fails")}</span>}
				]}/>}
			]}/>
			{tab === "contrast" && <p className="vw-muted vw-small">{t("g.found.pairsNote", {tint: number(floor, {maximumFractionDigits: 2})})}</p>}
		</Panel>
		<Panel title={t("g.found.type")} note={t("g.found.typeNote")}>
			<ul className="g-type">{TYPE_STEPS.map(([token, className]) => <li key={token}>
				<span className="vw-code vw-muted vw-small">{token}</span>
				<span className={className} style={{fontSize: `var(${token})`}} lang="en" dir="ltr">Connect to Frankfurt</span>
				<span className={className} style={{fontSize: `var(${token})`}} lang="fa" dir="rtl">اتصال به فرانکفورت</span>
			</li>)}</ul>
			<div className="vw-well g-legible">
				<p className="vw-muted vw-small">{t("g.found.legible")}</p>
				<p className="g-legible-sample" lang="en" dir="ltr">Il1 O0 rn m 5S 8B</p>
				<p className="vw-code">{SAMPLE_KEY}</p>
				<p className="g-cluster"><span className="vw-code">fra.vpn.example.net:8443</span><span className="vw-code">203.0.113.42</span><span className="vw-code">2001:db8::1</span></p>
			</div>
		</Panel>
		<Panel title={t("g.found.shape")} note={t("g.found.shapeNote")}>
			<div className="g-shape">
				<div><h3 className="vw-h3">{t("g.found.space")}</h3><ul className="g-spaces">{SPACES.map(token => <li key={token}><span className="vw-code vw-muted vw-small">{token}</span><span className="g-space" style={{inlineSize: `var(${token})`}}/></li>)}</ul></div>
				<div><h3 className="vw-h3">{t("g.found.radius")}</h3><div className="g-radii">{["--r-1", "--r-2", "--r-3"].map(token => <span key={token} className="g-radius vw-code vw-small" style={{borderRadius: `var(${token})`}}>{token}</span>)}</div></div>
				<div><h3 className="vw-h3">{t("g.found.depth")}</h3><div className="g-radii">{([1, 2, 3] as const).map(depth => <Glass key={depth} depth={depth} className="g-depth vw-code vw-small">{depth}</Glass>)}</div></div>
				<div><h3 className="vw-h3">{t("g.found.motion")}</h3><ul className="g-motion" data-moved={moved ? "" : undefined}>{["--dur-1", "--dur-2", "--dur-3"].map(token => <li key={token}><span className="vw-code vw-muted vw-small">{token}</span><span className="g-track"><span style={{transitionDuration: `var(${token})`}}/></span></li>)}</ul><Button size="sm" onClick={() => setMoved(!moved)}>{t("g.found.play")}</Button></div>
			</div>
		</Panel>
		<Panel title={t("g.found.material")} note={t("g.found.materialNote")}>
			<div className="g-busy">
				<div className="g-busy-back" aria-hidden="true"><span/><span/><span/><span/><span/><strong lang="en" dir="ltr">0 1 2 3 4 5 6 7 8 9</strong></div>
				<div className="g-panes">
					<Glass className="g-pane" data-material="glass"><strong>{t("g.found.glass")}</strong><span className="vw-muted">{t("g.found.glassNote", {tint: number(theme.glass.tint, {maximumFractionDigits: 2})})}</span></Glass>
					<Glass className="g-pane" data-material="glass" style={{"--glass-tint": floor} as CSSProperties}><strong>{t("g.found.thinnest")}</strong><span className="vw-muted">{t("g.found.thinnestNote", {tint: number(floor, {maximumFractionDigits: 2})})}</span></Glass>
					<Glass className="g-pane" data-material="solid"><strong>{t("g.found.solid")}</strong><span className="vw-muted">{t("g.found.solidNote")}</span></Glass>
				</div>
			</div>
		</Panel>
	</>;
}
