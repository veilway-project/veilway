import {useEffect, useRef, useState} from "react";
import {Banner, Button, ConfirmDialog, DataTable, Glass, List, ListRow, Nav, ProviderCard, RatingBadge, Shell, StatRow, StatTile, StateBlock, Switch, TrafficLine, UsageBar, useToast} from "../index.ts";
import {EXITS, PROVIDER_CARDS, PROVIDER_CARDS_FA, TREND, USERS, traffic} from "./data.ts";
import {useG} from "./shared.tsx";

const GB = 1024 ** 3;

// The two screens the system exists for, built only from library components: the window someone opens to turn the VPN on, and the page an operator watches.
export function InUse({still}: {still: boolean}) {
	const {t, rate, bytes, number, locale} = useG(), toast = useToast(), tick = useRef(60);
	const [points, setPoints] = useState(() => traffic(60)), [tab, setTab] = useState("home"), [connected, setConnected] = useState(true), [exit, setExit] = useState("de-fra"), [risky, setRisky] = useState<string | null>(null), [provider, setProvider] = useState(true), [killSwitch, setKillSwitch] = useState(true);
	useEffect(() => {
		if (still) return;
		const timer = setInterval(() => setPoints(list => [...list.slice(1), traffic(1, tick.current++)[0]!]), 1000);
		return () => clearInterval(timer);
	}, [still]);
	const current = EXITS.find(e => e.id === exit) ?? EXITS[0]!, now = points[points.length - 1]!;
	return <div className="g-use">
		<div className="g-specimen">
			<p className="vw-muted">{t("g.use.client")}</p>
			<div className="vw-backdrop g-window">
				<Shell nav={<Nav value={tab} onChange={setTab} items={[{id: "home", label: t("g.client.home"), icon: "power"}, {id: "exits", label: t("g.client.exits"), icon: "globe"}, {id: "usage", label: t("g.client.usage"), icon: "chart"}, {id: "settings", label: t("g.client.settings"), icon: "settings"}]}/>}>
					{tab === "home" && <>
						<div className="g-connect">
							<h3 className="vw-h1">{t(connected ? "state.connected" : "state.disconnected")}</h3>
							<p className="vw-muted">{t(`g.place.${current.place}`)} <span className="vw-code">{current.host}</span></p>
							<Button variant={connected ? "secondary" : "primary"} icon="power" onClick={() => setConnected(!connected)}>{t(connected ? "action.disconnect" : "action.connect")}</Button>
						</div>
						<RatingBadge rating={current.rating} detail/>
						<Glass className="g-pad"><StatRow>
							<StatTile label={t("chart.download")} value={rate(connected ? now.down : 0).value} unit={rate(now.down).unit}/>
							<StatTile label={t("chart.upload")} value={rate(connected ? now.up : 0).value} unit={rate(now.up).unit}/>
						</StatRow></Glass>
						{provider ? <ProviderCard provider="ExampleNet" accent="#C2410C" cards={locale === "fa" ? PROVIDER_CARDS_FA : PROVIDER_CARDS} onHide={() => setProvider(false)} onOpenLink={url => toast({title: t("g.client.opened"), body: url})}/> : <Button variant="quiet" icon="eye" onClick={() => setProvider(true)}>{t("g.client.showProvider")}</Button>}
					</>}
					{tab === "exits" && <Glass className="g-pad"><List label={t("g.client.exits")}>{EXITS.map(e => <ListRow key={e.id} current={e.id === exit} onClick={() => e.rating === "unsafe" ? setRisky(e.id) : setExit(e.id)} title={t(`g.place.${e.place}`)} detail={t("g.client.latency", {ms: e.latency})} trailing={<RatingBadge rating={e.rating}/>}/>)}</List></Glass>}
					{tab === "usage" && <Glass className="g-pad g-stack">
						<UsageBar label={t("g.client.month")} used={31.4 * GB} total={50 * GB}/>
						<StatRow><StatTile label={t("g.client.session")} value={bytes(1.8 * GB).value} unit={bytes(1.8 * GB).unit}/><StatTile label={t("g.client.expiry")} value={number(12)} unit={t("g.client.days")}/></StatRow>
					</Glass>}
					{tab === "settings" && <Glass className="g-pad g-stack">
						<Switch label={t("g.client.killSwitch")} hint={t("g.client.killSwitchHint")} checked={killSwitch} onChange={setKillSwitch}/>
						<StateBlock kind="empty" title={t("g.client.noLog")}>{t("g.client.noLogBody")}</StateBlock>
					</Glass>}
				</Shell>
			</div>
		</div>
		<div className="g-specimen">
			<p className="vw-muted">{t("g.use.panel")}</p>
			<Glass className="g-panel g-panel-frag">
				<Banner tone="warning" title={t("banner.http.title")}>{t("banner.http.body")}</Banner>
				<div className="g-row"><h2 className="vw-h2">{t("g.panel.title")}</h2><Button variant="primary" icon="plus" onClick={() => toast({tone: "info", title: t("g.panel.addHint")})}>{t("g.panel.addUser")}</Button></div>
				<StatRow>
					<StatTile label={t("g.panel.online")} value={number(USERS.filter(u => u.online).length)} detail={t("g.panel.ofUsers", {count: USERS.length})}/>
					<StatTile label={t("chart.download")} value={rate(now.down).value} unit={rate(now.down).unit} trend={points.slice(-12).map(p => p.down)}/>
					<StatTile label={t("g.panel.today")} value={bytes(52 * GB).value} unit={bytes(52 * GB).unit} trend={TREND}/>
				</StatRow>
				<TrafficLine points={points} label={t("g.panel.trafficLabel")}/>
				<DataTable caption={t("g.panel.title")} rows={USERS} rowKey={u => u.name} columns={[
					{id: "name", header: t("g.col.user"), cell: u => <span className="g-user"><span className="vw-code">{u.name}</span><span className="vw-muted vw-small">{t(u.online ? "g.panel.onlineNow" : "g.panel.offline")}</span></span>},
					{id: "group", header: t("g.col.group"), cell: u => <span className="vw-code">{u.group}</span>},
					{id: "usage", header: t("g.col.usage"), cell: u => <UsageBar compact label={u.name} used={u.used} total={u.quota}/>},
					{id: "expiry", header: t("g.col.expiry"), cell: u => t("count.daysLeft", {count: u.daysLeft})},
					{id: "devices", header: t("g.col.devices"), align: "end", cell: u => <span className="vw-num">{number(u.devices)}</span>}
				]}/>
			</Glass>
		</div>
		<ConfirmDialog open={risky !== null} onOpenChange={open => { if (!open) setRisky(null); }} danger title={t("g.client.unsafeTitle")} body={t("g.client.unsafeBody")} confirmLabel={t("g.client.unsafeConfirm")} onConfirm={() => { if (risky) setExit(risky); }}/>
	</div>;
}
