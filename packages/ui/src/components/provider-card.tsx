import {useEffect, useRef, useState, type CSSProperties} from "react";
import {contrast, mix, parseHex, toHex} from "../theme/color.ts";
import {MARK_MIN} from "../theme/tokens.ts";
import {Button, Icon, IconButton, useI18n} from "./core.tsx";
import {ConfirmDialog} from "./feedback.tsx";

// What a provider may put on the home screen through a signed subscription. It is data: plain text, numbers and https links. There is no way to pass markup, an icon of its own or a style.
export type ProviderItem = {type: "stat", label: string, value: string, unit?: string} | {type: "progress", label: string, used: number, total: number} | {type: "notice", text: string, severity: "info" | "warning" | "critical"} | {type: "link", label: string, url: string};
export const PROVIDER_MAX_CARDS = 6;
export const PROVIDER_MAX_LABEL = 40;
export const PROVIDER_MAX_TEXT = 200;

// The frame around provider content. It is the only dashed, unblurred surface in the system and it always says who wrote what is inside, so provider words cannot pass for the app's own. logo must be an image the app has already re-encoded itself; anything but a blob: URL is ignored.
export function ProviderCard({provider, cards, accent, logo, onHide, onOpenLink}: {provider: string, cards: ProviderItem[], accent?: string, logo?: string, onHide: () => void, onOpenLink: (url: string) => void}) {
	const {t, number, percent} = useI18n(), frame = useRef<HTMLElement>(null), [mark, setMark] = useState<string | null>(null), [pending, setPending] = useState<URL | null>(null);
	const name = provider.slice(0, PROVIDER_MAX_LABEL);
	// The provider's one colour is used for marks only and is pulled toward the text colour until it shows on the card.
	useEffect(() => {
		const style = frame.current && getComputedStyle(frame.current), ground = parseHex(style?.getPropertyValue("--c-sunken").trim()), ink = parseHex(style?.getPropertyValue("--c-text").trim()), wanted = parseHex(accent);
		if (!ground || !ink || !wanted) return setMark(null);
		let step = 0;
		while (step < 20 && contrast(mix(wanted, ink, step / 20), ground) < MARK_MIN) step++;
		setMark(toHex(mix(wanted, ink, step / 20)));
	});
	return <section className="vw-provider" ref={frame} aria-label={t("provider.from", {provider: name})} style={mark ? {"--provider-mark": mark} as CSSProperties : undefined}>
		<header className="vw-provider-head">
			{logo?.startsWith("blob:") ? <img className="vw-provider-logo" src={logo} alt=""/> : <span className="vw-provider-logo" aria-hidden="true">{Array.from(name)[0]}</span>}
			<div><strong>{t("provider.from", {provider: name})}</strong><p className="vw-muted vw-small">{t("provider.note")}</p></div>
			<IconButton icon="eyeOff" label={t("provider.hide")} onClick={onHide}/>
		</header>
		<ul className="vw-provider-cards">{cards.slice(0, PROVIDER_MAX_CARDS).map((card, i) => {
			if (card.type === "stat") return <li key={i} className="vw-provider-stat"><span className="vw-muted vw-small">{card.label.slice(0, PROVIDER_MAX_LABEL)}</span><span className="vw-stat-value">{card.value.slice(0, 16)}{card.unit && <span className="vw-stat-unit">{card.unit.slice(0, 16)}</span>}</span></li>;
			if (card.type === "progress") return <li key={i} className="vw-usage"><div className="vw-usage-head"><span>{card.label.slice(0, PROVIDER_MAX_LABEL)}</span><span className="vw-num vw-muted">{t("usage.of", {used: number(card.used), total: number(card.total)})}</span></div><div className="vw-usage-bar"><div className="vw-meter" role="meter" aria-label={card.label.slice(0, PROVIDER_MAX_LABEL)} aria-valuemin={0} aria-valuemax={card.total} aria-valuenow={card.used}><span style={{inlineSize: Math.min(100, Math.max(0, card.used / card.total * 100 || 0)) + "%"}}/></div><strong className="vw-num vw-small">{percent(card.used / card.total || 0)}</strong></div></li>;
			if (card.type === "notice") return <li key={i} className="vw-provider-notice" data-severity={card.severity}><Icon name={card.severity === "info" ? "info" : card.severity === "warning" ? "warning" : "error"}/><span>{card.text.slice(0, PROVIDER_MAX_TEXT)}</span></li>;
			const url = URL.canParse(card.url) ? new URL(card.url) : null;
			// Only https links are shown at all, and the domain is printed next to the provider's label so the label cannot lie about where it goes.
			return url?.protocol === "https:" && !url.username && !url.password ? <li key={i}><Button icon="external" onClick={() => setPending(url)}>{card.label.slice(0, PROVIDER_MAX_LABEL)}<span className="vw-code vw-muted"> {url.hostname}</span></Button></li> : null;
		})}</ul>
		<ConfirmDialog open={pending !== null} onOpenChange={open => { if (!open) setPending(null); }} title={t("provider.link.title", {domain: pending?.hostname ?? ""})} body={t("provider.link.body", {provider: name, domain: pending?.hostname ?? ""})} confirmLabel={t("provider.link.open", {domain: pending?.hostname ?? ""})} onConfirm={() => { if (pending) onOpenLink(pending.href); }}/>
	</section>;
}
