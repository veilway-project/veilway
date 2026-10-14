import {useState, type CSSProperties} from "react";
import {Backdrop, Button, COLOR_KEYS, DataTable, Glass, Icon, Tabs, UnsafeNote, audit, glassTints, minTint, palette, type Theme} from "../index.ts";
import {SAMPLE_KEY} from "./data.ts";
import {Panel, useG} from "./shared.tsx";

const TYPE_STEPS = [["--text-7", "vw-h1"], ["--text-6", "vw-h1"], ["--text-5", "vw-h2"], ["--text-4", "vw-h3"], ["--text-3", ""], ["--text-2", "vw-muted"], ["--text-1", "vw-muted"]] as const;
const SPACES = ["--s-1", "--s-2", "--s-3", "--s-4", "--s-5", "--s-6", "--s-7", "--s-8"];

export function Foundations({theme}: {theme: Theme}) {
	const {t, number} = useG(), [tab, setTab] = useState("tokens"), [moved, setMoved] = useState(false);
	const colors = palette(theme), floor = minTint(colors, theme.glass.blur) ?? 1, tints = glassTints(colors, theme.glass.tint, theme.glass.blur), findings = audit(colors, theme.glass.tint, theme.glass.blur), two = (value: number) => number(value, {maximumFractionDigits: 2});
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
			{tab === "contrast" && <p className="vw-muted vw-small">{t("g.found.pairsNote", {tint: two(tints.glass), float: two(tints.float), thick: two(tints.thick)})}</p>}
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
				<div><h3 className="vw-h3">{t("g.found.motion")}</h3><ul className="g-motion" data-moved={moved ? "" : undefined}>{["--dur-1", "--dur-2", "--dur-3"].map(token => <li key={token}><span className="vw-code vw-muted vw-small">{token}</span><span className="g-track"><span style={{transitionDuration: `var(${token})`}}/></span></li>)}</ul><Button size="sm" onClick={() => setMoved(!moved)}>{t("g.found.play")}</Button></div>
			</div>
		</Panel>
		<section className="g-bare">
			<header><h2 className="vw-h2">{t("g.found.material")}</h2><p className="vw-muted">{t("g.found.materialNote")}</p></header>
			<Backdrop className="g-stage">
				<div className="g-stage-copy" aria-hidden="true" lang="en" dir="ltr"><span>fra.vpn.example.net 203.0.113.42</span><span>2001:db8::1 198.51.100.24 ams</span><span>hel.vpn.example.net 192.0.2.7</span><span>203.0.113.42 2001:db8::1 ist</span></div>
				<div className="g-panes">
					<Glass className="g-pane" data-material="glass"><strong>{t("g.found.sheet")}</strong><span className="vw-muted">{t("g.found.sheetNote", {tint: two(tints.glass)})}</span></Glass>
					<Glass className="g-pane" layer="chrome" data-material="glass"><strong>{t("g.found.chrome")}</strong><span className="vw-muted">{t("g.found.chromeNote", {tint: two(tints.float)})}</span></Glass>
					<Glass className="g-pane" layer="popover" data-material="glass"><strong>{t("g.found.popover")}</strong><span className="vw-muted">{t("g.found.popoverNote", {tint: two(tints.thick)})}</span></Glass>
					<Glass className="g-pane" layer="dialog" data-material="glass"><strong>{t("g.found.dialog")}</strong><span className="vw-muted">{t("g.found.dialogNote", {tint: two(tints.thick)})}</span></Glass>
					<Glass className="g-pane" data-material="glass" style={{"--glass-tint": floor} as CSSProperties}><strong>{t("g.found.thinnest")}</strong><span className="vw-muted">{t("g.found.thinnestNote", {tint: two(floor)})}</span></Glass>
					<Glass className="g-pane" data-material="glass"><strong>{t("g.found.well")}</strong><span className="vw-muted">{t("g.found.wellNote")}</span><div className="vw-well g-pad g-cluster"><UnsafeNote/><span className="vw-code">198.51.100.24</span></div></Glass>
					<Glass className="g-pane" data-material="solid"><strong>{t("g.found.solid")}</strong><span className="vw-muted">{t("g.found.solidNote")}</span></Glass>
				</div>
			</Backdrop>
		</section>
	</>;
}
