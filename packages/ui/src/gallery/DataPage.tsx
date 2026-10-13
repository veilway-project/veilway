import {useEffect, useRef, useState} from "react";
import {Sparkline, StatRow, StatTile, TrafficLine, UsageBar} from "../index.ts";
import {TREND, traffic} from "./data.ts";
import {Panel, useG} from "./shared.tsx";

const GB = 1024 ** 3;

export function DataPage({still}: {still: boolean}) {
	const {t, rate, bytes, number} = useG(), tick = useRef(90), [points, setPoints] = useState(() => traffic(90));
	useEffect(() => {
		if (still) return;
		const timer = setInterval(() => setPoints(list => [...list.slice(1), traffic(1, tick.current++)[0]!]), 1000);
		return () => clearInterval(timer);
	}, [still]);
	const now = points[points.length - 1]!;
	return <>
		<Panel title={t("g.data.tiles")} note={t("g.data.tilesNote")}>
			<StatRow>
				<StatTile label={t("g.panel.online")} value={number(3)} detail={t("g.panel.ofUsers", {count: 48})}/>
				<StatTile label={t("chart.download")} value={rate(now.down).value} unit={rate(now.down).unit} trend={points.slice(-12).map(p => p.down)}/>
				<StatTile label={t("chart.upload")} value={rate(now.up).value} unit={rate(now.up).unit} trend={points.slice(-12).map(p => p.up)}/>
				<StatTile label={t("g.panel.today")} value={bytes(52 * GB).value} unit={bytes(52 * GB).unit} trend={TREND}/>
			</StatRow>
		</Panel>
		<Panel title={t("g.data.live")} note={t("g.data.liveNote")}><TrafficLine points={points} label={t("g.panel.trafficLabel")} height={260}/></Panel>
		<Panel title={t("g.data.usage")} note={t("g.data.usageNote")}>
			<div className="g-usages">
				<UsageBar label="family-plan-01" used={31.4 * GB} total={50 * GB}/>
				<UsageBar label="office-router" used={188 * GB} total={200 * GB}/>
				<UsageBar label="student-04" used={5 * GB} total={5 * GB}/>
				<UsageBar label="press-desk" used={96.8 * GB} total={null}/>
			</div>
		</Panel>
		<Panel title={t("g.data.spark")} note={t("g.data.sparkNote")}>
			<div className="g-cluster g-sparks">{EXIT_TRENDS.map(([place, values]) => <span key={place} className="g-spark"><span>{t(`g.place.${place}`)}</span><Sparkline values={values} label={t(`g.place.${place}`)}/><strong className="vw-num">{bytes(values[values.length - 1]! * GB).text}</strong></span>)}</div>
		</Panel>
	</>;
}

const EXIT_TRENDS: ["fra" | "ams" | "ist", number[]][] = [["fra", TREND], ["ams", [30, 28, 31, 25, 22, 26, 21, 18, 20, 16, 15, 12]], ["ist", [8, 9, 8, 12, 9, 10, 14, 11, 12, 13, 12, 14]]];
