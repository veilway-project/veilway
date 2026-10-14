import {scaleLinear} from "d3-scale";
import {area, curveMonotoneX, line} from "d3-shape";
import {useEffect, useRef, useState, type KeyboardEvent, type PointerEvent} from "react";
import {Button, useI18n} from "../components/core.tsx";
import {DataTable} from "../components/data.tsx";

export type TrafficPoint = {time: Date, down: number, up: number};
const SERIES = ["down", "up"] as const;
const PAD = {top: 28, right: 14, bottom: 26, left: 44};

// Download and upload rate over time on one axis, in bytes per second. Time runs left to right in both languages, as it does on every speed graph people already know; the legend, the readout and the table follow the reading direction. Every value the pointer can reach is also reachable with the arrow keys and in the table view.
export function TrafficLine({points, label, height = 220}: {points: TrafficPoint[], label: string, height?: number}) {
	const {t, rate, number, time, dir} = useI18n(), frame = useRef<HTMLDivElement>(null);
	const [width, setWidth] = useState(640), [at, setAt] = useState<number | null>(null), [table, setTable] = useState(false);
	useEffect(() => {
		if (!frame.current) return;
		const observer = new ResizeObserver(entries => setWidth(Math.max(240, Math.round(entries[0]!.contentRect.width))));
		observer.observe(frame.current);
		return () => observer.disconnect();
	}, [table]);
	const names = {down: t("chart.download"), up: t("chart.upload")}, last = points[points.length - 1];
	// A window shorter than ten minutes needs seconds on its clock labels, or every label reads the same.
	const clock = (date: Date) => time(date, last !== undefined && last.time.getTime() - points[0]!.time.getTime() < 600000);
	// Ticks are chosen in the unit the axis is labelled with, so they land on round numbers of that unit and not of bytes.
	const peak = Math.max(1, ...points.flatMap(p => [p.down, p.up])), unitSize = 1024 ** Math.min(4, Math.floor(Math.log(peak) / Math.log(1024)));
	const y = scaleLinear().domain([0, peak / unitSize]).nice(4).range([height - PAD.bottom, PAD.top]), x = scaleLinear().domain([0, Math.max(1, points.length - 1)]).range([PAD.left, width - PAD.right]);
	const shown = at === null ? null : points[at];
	const move = (event: PointerEvent<SVGSVGElement>) => setAt(Math.min(points.length - 1, Math.max(0, Math.round(x.invert(event.clientX - event.currentTarget.getBoundingClientRect().left)))));
	const key = (event: KeyboardEvent<SVGSVGElement>) => {
		const next = event.key === "ArrowLeft" ? (at ?? points.length) - 1 : event.key === "ArrowRight" ? (at ?? -1) + 1 : event.key === "Home" ? 0 : event.key === "End" ? points.length - 1 : event.key === "Escape" ? null : undefined;
		if (next === undefined) return;
		event.preventDefault();
		setAt(next === null ? null : Math.min(points.length - 1, Math.max(0, next)));
	};
	return <figure className="vw-chart">
		<figcaption className="vw-chart-head">
			<ul className="vw-legend">{SERIES.map(s => <li key={s}><span className="vw-legend-key" data-series={s}/>{names[s]}{last && <strong className="vw-num">{rate(last[s]).text}</strong>}</li>)}</ul>
			<Button size="sm" variant="quiet" onClick={() => setTable(!table)}>{t(table ? "chart.showChart" : "chart.showTable")}</Button>
		</figcaption>
		{table ? <DataTable caption={label} rows={points.filter((_, i) => i % Math.ceil(points.length / 8) === 0)} rowKey={p => String(p.time.getTime())} columns={[{id: "time", header: t("chart.time"), cell: p => <span className="vw-num">{clock(p.time)}</span>}, {id: "down", header: names.down, align: "end", cell: p => <span className="vw-num">{rate(p.down).text}</span>}, {id: "up", header: names.up, align: "end", cell: p => <span className="vw-num">{rate(p.up).text}</span>}]}/> : <div className="vw-chart-frame" ref={frame} dir="ltr">
			<svg width={width} height={height} role="img" aria-label={label} tabIndex={0} onPointerMove={move} onPointerLeave={() => setAt(null)} onKeyDown={key} onBlur={() => setAt(null)}>
				{y.ticks(4).map(tick => <g key={tick}><line className="vw-grid" x1={PAD.left} x2={width - PAD.right} y1={y(tick)} y2={y(tick)}/><text className="vw-tick" x={PAD.left - 8} y={y(tick)} dy="0.32em" textAnchor="end">{number(tick)}</text></g>)}
				{(width < 400 ? [0, 0.5, 1] : [0, 1 / 3, 2 / 3, 1]).map((part, i, parts) => [part, points[Math.round(part * (points.length - 1))], i === 0 ? "start" : i === parts.length - 1 ? "end" : "middle"] as const).map(([part, p, anchor]) => p && <text key={part} className="vw-tick" x={PAD.left + part * (width - PAD.left - PAD.right)} y={height - 6} textAnchor={anchor}>{clock(p.time)}</text>)}
				{SERIES.map(s => <g key={s} data-series={s}>
					<path className="vw-area" d={area<TrafficPoint>().x((_, i) => x(i)).y0(y(0)).y1(p => y(p[s] / unitSize)).curve(curveMonotoneX)(points) ?? ""}/>
					<path className="vw-line" d={line<TrafficPoint>().x((_, i) => x(i)).y(p => y(p[s] / unitSize)).curve(curveMonotoneX)(points) ?? ""}/>
					{last && <circle className="vw-dot" cx={x(points.length - 1)} cy={y(last[s] / unitSize)} r="4"/>}
				</g>)}
				{shown && at !== null && <g><line className="vw-crosshair" x1={x(at)} x2={x(at)} y1={PAD.top} y2={height - PAD.bottom}/>{SERIES.map(s => <circle key={s} className="vw-dot" data-series={s} cx={x(at)} cy={y(shown[s] / unitSize)} r="4"/>)}</g>}
			</svg>
			<span className="vw-axis-unit">{rate(unitSize).unit}</span>
			{shown && at !== null && <div className="vw-glass vw-tooltip" data-layer="chrome" dir={dir} data-side={x(at) > width / 2 ? "before" : "after"} style={{left: x(at)}}>
				<span className="vw-muted vw-small vw-num">{clock(shown.time)}</span>
				{SERIES.map(s => <span key={s} className="vw-tooltip-row"><span className="vw-legend-key" data-series={s}/><strong className="vw-num">{rate(shown[s]).text}</strong><span className="vw-muted">{names[s]}</span></span>)}
			</div>}
		</div>}
	</figure>;
}
