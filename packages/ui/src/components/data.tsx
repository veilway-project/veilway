import {line as lineShape} from "d3-shape";
import type {ReactNode} from "react";
import {Icon, useI18n} from "./core.tsx";

export type Rating = "protected" | "detectable" | "unsafe";

// The three bars are the strokes of the app icon. How many are solid, and the stroke through them, carry the rating without colour: three solid, one solid and two hollow, three hollow and struck through.
export function RatingBadge({rating, detail}: {rating: Rating, detail?: boolean}) {
	const {t} = useI18n(), solid = rating === "protected" ? 3 : rating === "detectable" ? 1 : 0;
	return <span className="vw-rating" data-rating={rating} data-detail={detail ? "" : undefined} aria-label={detail ? undefined : t("rating.label", {rating: t(`rating.${rating}`)})}>
		<svg className="vw-rating-glyph" viewBox="0 0 20 14" aria-hidden="true">
			{[0, 1, 2].map(i => <polygon key={i} points={`${i * 5.2 + 6.4},1 ${i * 5.2 + 9.6},1 ${i * 5.2 + 3.9},13 ${i * 5.2 + 0.7},13`} data-solid={i < solid ? "" : undefined}/>)}
			{rating === "unsafe" && <line x1="1" y1="3" x2="19" y2="11"/>}
		</svg>
		<span className="vw-rating-text"><strong>{t(`rating.${rating}`)}</strong>{detail && <span>{t(`rating.${rating}.detail`)}</span>}</span>
	</span>;
}

// Bytes used against a quota. The bar is a meter, the numbers beside it say the same thing, and the level (under 80%, near the limit, over it) is spelled out in the percentage as well as the colour. total null means no limit. compact drops the visible label, for a table row that already names its user.
export function UsageBar({label, used, total, compact}: {label: string, used: number, total: number | null, compact?: boolean}) {
	const {t, bytes, percent} = useI18n(), ratio = total ? used / total : 0, level = ratio >= 1 ? "over" : ratio >= 0.8 ? "near" : "ok";
	const text = total === null ? t("usage.unlimited") : t("usage.of", {used: bytes(used).text, total: bytes(total).text});
	return <div className="vw-usage" data-level={level}>
		<div className="vw-usage-head">{!compact && <span>{label}</span>}<span className="vw-num vw-muted">{text}</span></div>
		{total !== null && <div className="vw-usage-bar"><div className="vw-meter" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={total} aria-valuenow={used} aria-valuetext={text}><span style={{inlineSize: Math.min(100, ratio * 100) + "%"}}/></div><strong className="vw-num vw-small">{t("usage.percent", {percent: percent(ratio)})}</strong></div>}
	</div>;
}

// Twelve or so points with no axes: the shape of the recent past next to a number. The last point is marked, the rest is quiet.
export function Sparkline({values, label}: {values: number[], label: string}) {
	const max = Math.max(1, ...values), x = (i: number) => 3 + i * 90 / Math.max(1, values.length - 1), y = (v: number) => 25 - v / max * 22;
	return <svg className="vw-sparkline" viewBox="0 0 96 28" role="img" aria-label={label}>
		<path d={lineShape<number>().x((_, i) => x(i)).y(v => y(v))(values) ?? ""}/>
		{values.length > 0 && <circle cx={x(values.length - 1)} cy={y(values[values.length - 1]!)} r="3"/>}
	</svg>;
}

// A figure with its label. Tiles are not boxed: a row of them is divided by hairlines inside one surface.
export function StatTile({label, value, unit, detail, trend}: {label: string, value: string, unit?: string, detail?: ReactNode, trend?: number[]}) {
	return <div className="vw-stat">
		<span className="vw-stat-label">{label}</span>
		<span className="vw-stat-value">{value}{unit && <span className="vw-stat-unit">{unit}</span>}</span>
		{trend && <Sparkline values={trend} label={label}/>}
		{detail && <span className="vw-muted vw-small">{detail}</span>}
	</div>;
}

export function StatRow({children}: {children: ReactNode}) {
	return <div className="vw-stat-row">{children}</div>;
}

export function List({children, label}: {children: ReactNode, label: string}) {
	return <ul className="vw-list" aria-label={label}>{children}</ul>;
}

// A row is a button when it does something. current marks the chosen one in a pick list, with a check as well as the fill.
export function ListRow({leading, title, detail, trailing, onClick, current}: {leading?: ReactNode, title: ReactNode, detail?: ReactNode, trailing?: ReactNode, onClick?: () => void, current?: boolean}) {
	const body = <>{leading && <span className="vw-row-leading">{leading}</span>}<span className="vw-row-text"><span>{title}</span>{detail && <span className="vw-muted vw-small">{detail}</span>}</span>{(trailing || current) && <span className="vw-row-trailing">{trailing}{current && <Icon name="check"/>}</span>}</>;
	return <li>{onClick ? <button type="button" className="vw-row" aria-pressed={current} onClick={onClick}>{body}</button> : <div className="vw-row">{body}</div>}</li>;
}

export type Column<T> = {id: string, header: string, cell: (row: T) => ReactNode, align?: "start" | "end"};

// A real table on a wide surface. On a narrow one each row becomes a block and every cell carries its column name, so nothing scrolls sideways.
export function DataTable<T>({columns, rows, rowKey, caption, empty}: {columns: Column<T>[], rows: T[], rowKey: (row: T) => string, caption: string, empty?: ReactNode}) {
	return <div className="vw-table-wrap">
		{rows.length === 0 && empty ? empty : <table className="vw-table">
			<caption className="vw-sr">{caption}</caption>
			<thead><tr>{columns.map(c => <th key={c.id} scope="col" data-align={c.align}>{c.header}</th>)}</tr></thead>
			<tbody>{rows.map(row => <tr key={rowKey(row)}>{columns.map(c => <td key={c.id} data-align={c.align} data-label={c.header}>{c.cell(row)}</td>)}</tr>)}</tbody>
		</table>}
	</div>;
}
