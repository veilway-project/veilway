import {Banner, Button, ConnectSwitch, Dialog, Glass, Icon, List, ListRow, ProviderCard, SelectField, StatRow, StatTile, UsageBar, useToast, type ConnectState, type ProviderItem, type TrafficPoint} from "@veilway/ui";
import {useEffect, useState} from "react";
import {agreement, failureText, fromUnix, useD, useLogo, type Prefs} from "./kit.tsx";
import {en, type DesktopKey} from "./locales/en.ts";
import {call, type Ended, type Exit, type Profile, type Running, type Subscription} from "./tauri.ts";

type Choice = {subscription: Subscription, profile: Profile};

export function Home({running, busy, ended, points, choices, chosen, prefs, onPrefs, onConnect, onDisconnect, onRefresh, onLibrary}: {running: Running, busy: boolean, ended: Ended | null, points: TrafficPoint[], choices: Choice[], chosen: Choice | undefined, prefs: Prefs, onPrefs: (next: Partial<Prefs>) => void, onConnect: () => void, onDisconnect: () => void, onRefresh: (id: string) => void, onLibrary: (found: Subscription[]) => void}) {
	const {t, rate, time, date, locale, number, bytes} = useD(), toast = useToast(), [picking, setPicking] = useState(false), [tick, setTick] = useState(() => Date.now());
	const status = running.status, state = running.connected ? status?.state ?? "connecting" : "off", subscription = chosen?.subscription, logo = useLogo(subscription?.logo ?? null);
	const link: ConnectState = state === "connected" ? "on" : state === "off" || state === "failed" ? "off" : "connecting";
	const heading = state === "connected" ? t("state.connected") : state === "connecting" ? t("state.connecting") : state === "reconnecting" ? t("state.reconnecting") : state === "stopped" ? t("state.stopped") : state === "failed" ? t("state.failed") : t("state.disconnected");
	// Before the node's list arrives (and while disconnected) the exits are the ones the connection lists, with the choice saved for the subscription.
	const exits = status?.exits ?? [], saved = subscription?.exit_choice ?? null, listed = exits.length > 0 ? exits.map(exit => ({tag: exit.tag, name: exit.name, selected: exit.selected, exit})) : (chosen?.profile.exits ?? []).map(([tag, name]) => ({tag, name, selected: tag === saved, exit: undefined})), current = exits.find(e => e.tag === status?.exit), usage = status?.usage, now = points[points.length - 1];
	const xray = status?.xray ?? null, said = xray?.say_code ?? status?.say_code, refused = chosen?.profile.legacy?.refused ?? null;
	const code = said && ("say." + said) in en ? t(("say." + said) as DesktopKey) : xray?.say ?? status?.say;
	const wait = status?.wait_until ? t("home.retryAt", {time: time(fromUnix(status.wait_until))}) : state === "stopped" ? t("home.retryAsked") : null;
	const country = (exit: Exit) => { try { return exit.country ? new Intl.DisplayNames([locale], {type: "region"}).of(exit.country.toUpperCase()) : undefined; } catch { return undefined; } };
	const exitDetail = (exit: Exit) => [country(exit), exit.working ? (["low", "medium", "high"].includes(exit.load) ? t(("home.load." + exit.load) as DesktopKey) : "") : t("home.exitDown")].filter(Boolean).join(locale === "fa" ? "، " : ", ");
	const pick = (tag: string | null) => { setPicking(false); if (subscription) call("select_exit", {id: subscription.id, tag}).then(onLibrary, error => toast({tone: "danger", title: t("home.exitFailed"), body: error})); };
	const items: ProviderItem[] = subscription ? [
		...subscription.notices.map(n => ({type: "notice" as const, text: n.text, severity: n.severity === "warning" ? "warning" as const : n.severity === "critical" ? "critical" as const : "info" as const})),
		...subscription.cards.map((card): ProviderItem => card.kind === "stat" ? {type: "stat", label: card.label, value: card.value, unit: card.unit ?? undefined} : card.kind === "progress" ? {type: "progress", label: card.label, used: card.used, total: card.total} : card.kind === "notice" ? {type: "notice", text: card.text, severity: card.severity === "warning" ? "warning" : card.severity === "critical" ? "critical" : "info"} : {type: "link", label: card.label, url: card.url}),
		...subscription.support.map(([label, url]) => ({type: "link" as const, label, url})),
		...([["terms.terms", subscription.terms], ["terms.privacy", subscription.privacy]] as const).flatMap(([label, url]) => url ? [{type: "link" as const, label: t(label), url}] : [])
	] : [];
	// Connecting waits for the user's yes to the provider's terms, asked again when a refresh changes either link.
	const terms = subscription ? agreement(subscription) : null, accepted = subscription ? prefs.accepted[subscription.id] : undefined, pending = terms !== null && accepted !== terms;
	const open = (url: string) => call("open_link", {url}).catch(error => toast({tone: "danger", title: t("home.openFailed"), body: error}));
	const connection = status?.connection ?? null, since = connection?.since ?? null;
	useEffect(() => {
		if (since === null) return;
		setTick(Date.now());
		const timer = setInterval(() => setTick(Date.now()), 1000);
		return () => clearInterval(timer);
	}, [since]);
	const up = since === null ? null : Math.max(0, Math.floor(tick / 1000) - since), clock = up === null ? null : [Math.floor(up / 3600), Math.floor(up / 60) % 60, up % 60].map((n, i) => String(n).padStart(i ? 2 : 1, "0")).join(":");
	const check = connection?.check && ("details.check." + connection.check) in en ? ("details.check." + connection.check) as DesktopKey : null;
	const rows = connection ? [
		{key: "details.server", shown: connection.address, code: true}, {key: "details.host", shown: connection.host, code: true}, {key: "details.transport", shown: connection.transport, code: true}, {key: "details.front", shown: connection.front, code: true}, {key: "details.serverName", shown: connection.server_name, code: true}, {key: "details.alpha", shown: connection.alpha ? t("details.alpha.yes") : null, plain: connection.alpha ? en["details.alpha.yes"] : null, code: false},
		{key: "details.check", shown: check && t(check), plain: check && en[check], code: false}, {key: "details.mtu", shown: number(status?.mtu ?? 0), plain: String(status?.mtu), code: true}, {key: "details.uptime", shown: clock && clock.split(":").map((part, i) => i ? number(Number(part), {minimumIntegerDigits: 2}) : number(Number(part))).join(":"), plain: clock, code: true}
	].flatMap(row => row.shown ? [{...row, key: row.key as DesktopKey, plain: row.plain ?? row.shown}] : []) : [];
	const copyDetails = () => navigator.clipboard.writeText(en["details.title"] + "\n" + rows.map(row => en[row.key] + ": " + row.plain).join("\n")).then(() => toast({tone: "success", title: t("details.copied")}), () => toast({tone: "danger", title: t("details.copyFailed")}));
	const kept = ended?.kept || (!running.connected && running.kill_switch_kept);
	return <div className="d-page">
		<div className="d-hero">
			<h1 className="vw-display" aria-live="polite">{heading}</h1>
			<p className="d-place"><span>{state === "connected" && current ? t("home.through", {exit: current.name}) : chosen?.profile.name}</span>{subscription && <span className="vw-muted vw-small">{chosen?.profile.legacy ? [subscription.provider, t("xray.tcpUdp")].join(locale === "fa" ? "، " : ", ") : subscription.provider}</span>}</p>
			{chosen?.profile.left_out && <p className="vw-muted vw-small">{t("profile.leftOut")}</p>}
			{subscription?.unknown_type && <p className="vw-muted vw-small">{t("profile.unknownType")}</p>}
			{(code || wait) && <p className="d-say">{[code, wait].filter(Boolean).join(" ")}</p>}
			<ConnectSwitch state={link} disabled={busy || !chosen || ((pending || refused !== null) && link === "off")} onToggle={link === "off" ? onConnect : onDisconnect}/>
		</div>
		{link === "off" && choices.length > 1 && chosen && <SelectField label={t("home.connection")} value={chosen.subscription.id + "\n" + chosen.profile.id} onChange={value => { const [subscription = "", profile = ""] = value.split("\n"); onPrefs({choice: {subscription, profile}}); }} options={choices.map(c => ({value: c.subscription.id + "\n" + c.profile.id, label: c.profile.name, detail: c.subscription.provider}))}/>}
		{refused && link === "off" && <Banner tone="warning" title={t("home.refused")}>{failureText(refused, t)}</Banner>}
		{pending && subscription && <Banner tone="info" title={t("terms.title", {provider: subscription.provider})} action={<Button size="sm" variant="primary" onClick={() => onPrefs({accepted: {...prefs.accepted, [subscription.id]: terms ?? ""}})}>{t("terms.accept")}</Button>}>
			{t(accepted === undefined ? "terms.body" : "terms.changed", {provider: subscription.provider})}
			<span className="d-actions d-start">{([["terms.terms", subscription.terms], ["terms.privacy", subscription.privacy]] as const).map(([label, url]) => url && <Button key={label} size="sm" variant="quiet" icon="external" onClick={() => open(url)}>{t(label)}</Button>)}</span>
		</Banner>}
		{(ended?.error || kept) && <Banner tone="danger" title={t("home.ended")} action={kept && <Button size="sm" onClick={onDisconnect}>{t("home.disconnect")}</Button>}>{[ended?.error === "alpha_off" ? t("alpha.off") : ended?.error && failureText(ended.error, t), kept ? t("home.kept") : null].filter(Boolean).join(" ")}</Banner>}
		{status?.out_of_date && subscription && <Banner tone="warning" title={t("home.outOfDate")} action={subscription.can_refresh && <Button size="sm" icon="refresh" onClick={() => onRefresh(subscription.id)}>{t("home.refresh")}</Button>}>{t("home.outOfDateBody")}</Banner>}
		{status?.notices.map((notice, i) => <Banner key={i} tone={notice.severity === "warning" ? "warning" : "info"} title={t("home.notice", {provider: subscription?.provider ?? ""})}>{notice.text}</Banner>)}
		{listed.length > 0 && <Glass className="d-list"><List label={t("home.exit")}><ListRow onClick={() => setPicking(true)} leading={<Icon name="globe"/>} title={t("home.exit")} detail={listed.find(e => e.selected)?.name ?? (state === "connected" && current ? t("home.exitAutoUsing", {exit: current.name}) : t("home.exitAuto"))} trailing={<Icon name="chevronForward"/>}/></List></Glass>}
		{connection && <Glass className="d-details"><details>
			<summary><span>{t("details.title")}</span><Icon name="chevronDown"/></summary>
			<dl>{rows.map(row => <div key={row.key}><dt>{t(row.key)}</dt><dd>{row.code ? <span className="vw-code" dir="ltr">{row.shown}</span> : row.shown}</dd></div>)}</dl>
			<div className="d-details-foot">{state !== "connected" && <p className="vw-muted vw-small">{t("details.trying")}</p>}<Button size="sm" icon="copy" onClick={copyDetails}>{t("details.copy")}</Button></div>
		</details></Glass>}
		{state === "connected" && <Glass className="d-panel">
			<StatRow>
				<StatTile label={t("chart.download")} value={rate(now?.down ?? 0).value} unit={rate(now?.down ?? 0).unit} trend={points.slice(-12).map(p => p.down)}/>
				<StatTile label={t("chart.upload")} value={rate(now?.up ?? 0).value} unit={rate(now?.up ?? 0).unit} trend={points.slice(-12).map(p => p.up)}/>
			</StatRow>
			{usage && <UsageBar label={t(("home.period." + (["daily", "weekly", "monthly"].includes(usage.period) ? usage.period : "none")) as DesktopKey)} used={usage.used_bytes} total={usage.quota_bytes || null}/>}
			{usage?.expires_at ? <p className="vw-muted vw-small">{t("home.planEnds", {date: date(fromUnix(usage.expires_at))})}</p> : null}
		</Glass>}
		{xray && <Glass className="d-panel d-xray-stats">
			<h2 className="vw-h3">{t("xray.status.title")}</h2>
			<dl>{([["xray.status.openTcp", number(xray.open_tcp)], ["xray.status.openUdp", number(xray.open_udp)], ["xray.status.carried", number(xray.carried_flows)], ["xray.status.failed", number(xray.failed_flows)], ["xray.status.sent", bytes(xray.bytes_sent).text], ["xray.status.received", bytes(xray.bytes_received).text], ["xray.status.unsupported", number(xray.unsupported_packets)], ["xray.status.droppedUdp", number(xray.dropped_udp_flows)], ["xray.status.restarts", number(xray.restarts)]] as const).map(([key, shown]) => <div key={key}><dt>{t(key)}</dt><dd className="vw-num">{shown}</dd></div>)}</dl>
			<p className="vw-muted vw-small">{t("xray.status.note")}</p>
		</Glass>}
		{subscription && items.length > 0 && (prefs.hidden.includes(subscription.id) ? <Button variant="quiet" icon="eye" className="d-start" onClick={() => onPrefs({hidden: prefs.hidden.filter(id => id !== subscription.id)})}>{t("home.showProvider", {provider: subscription.provider})}</Button>
			: <ProviderCard provider={subscription.provider} accent={subscription.accent ?? undefined} logo={logo} cards={items} onHide={() => onPrefs({hidden: [...prefs.hidden, subscription.id]})} onOpenLink={open}/>)}
		<Dialog open={picking} onOpenChange={setPicking} title={t("home.exitPick")} description={t("home.exitPickBody")}>
			<List label={t("home.exitPick")}>
				<ListRow onClick={() => pick(null)} current={!listed.some(e => e.selected)} title={t("home.exitAuto")} detail={t("home.exitAutoDetail")}/>
				{listed.map(row => <ListRow key={row.tag} onClick={() => pick(row.tag)} current={row.selected} title={row.name} detail={row.exit && exitDetail(row.exit)}/>)}
			</List>
		</Dialog>
	</div>;
}
