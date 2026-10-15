import {Glass, StatRow, StatTile, StateBlock, TrafficLine, UsageBar, type TrafficPoint} from "@veilway/ui";
import {fromUnix, useD} from "./kit.tsx";
import type {DesktopKey} from "./locales/en.ts";
import type {Running} from "./tauri.ts";

export function UsagePage({running, points}: {running: Running, points: TrafficPoint[]}) {
	const {t, bytes, date} = useD(), status = running.status, usage = status?.usage;
	if (!running.connected || !status) return <div className="d-page"><h1 className="vw-h1">{t("usage.title")}</h1><Glass className="d-panel"><StateBlock kind="empty" title={t("usage.off")}>{t("usage.offBody")}</StateBlock></Glass></div>;
	const total = bytes(status.sent_bytes + status.received_bytes), sent = bytes(status.sent_bytes), received = bytes(status.received_bytes);
	return <div className="d-page">
		<h1 className="vw-h1">{t("usage.title")}</h1>
		<Glass className="d-panel">
			<StatRow>
				<StatTile lead label={t("home.session")} value={total.value} unit={total.unit}/>
				<StatTile label={t("usage.received")} value={received.value} unit={received.unit}/>
				<StatTile label={t("usage.sent")} value={sent.value} unit={sent.unit}/>
			</StatRow>
			{points.length > 1 && <TrafficLine points={points} label={t("usage.speed")} height={200}/>}
		</Glass>
		{usage && <Glass className="d-panel">
			<UsageBar label={t(("home.period." + (["daily", "weekly", "monthly"].includes(usage.period) ? usage.period : "none")) as DesktopKey)} used={usage.used_bytes} total={usage.quota_bytes || null}/>
			{usage.expires_at ? <p className="vw-muted vw-small">{t("home.planEnds", {date: date(fromUnix(usage.expires_at))})}</p> : null}
		</Glass>}
	</div>;
}
