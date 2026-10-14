import {Tabs as TabsPrimitive, ToggleGroup} from "radix-ui";
import type {ReactNode} from "react";
import {Icon, useI18n, type IconName} from "./core.tsx";

export type NavItem = {id: string, label: string, icon: IconName};

// One navigation model for the panel and the clients. In a wide container it is a rail beside the content; in a narrow one (a phone, a compact client window) the same items become a bar under it. "auto" lets the Shell's width decide.
export function Nav({items, value, onChange, layout = "auto", header}: {items: NavItem[], value: string, onChange: (id: string) => void, layout?: "auto" | "rail" | "bar", header?: ReactNode}) {
	const {t} = useI18n();
	return <nav className="vw-glass vw-nav" data-layer="chrome" data-layout={layout} aria-label={t("nav.label")}>
		{header && <div className="vw-nav-header">{header}</div>}
		<ul>{items.map(item => <li key={item.id}><button type="button" className="vw-nav-item" aria-current={item.id === value ? "page" : undefined} onClick={() => onChange(item.id)}><Icon name={item.icon}/><span>{item.label}</span></button></li>)}</ul>
	</nav>;
}

// The frame around a screen. The page scrolls; the navigation stays put and content passes under it, which is where the glass earns its keep.
export function Shell({nav, banner, children}: {nav: ReactNode, banner?: ReactNode, children: ReactNode}) {
	return <div className="vw-shell"><div className="vw-shell-grid">{nav}<main className="vw-shell-main">{banner}{children}</main></div></div>;
}

export type TabItem = {id: string, label: string, content: ReactNode};

export function Tabs({items, value, onChange, label}: {items: TabItem[], value: string, onChange: (id: string) => void, label: string}) {
	return <TabsPrimitive.Root className="vw-tabs" value={value} onValueChange={onChange}>
		<TabsPrimitive.List className="vw-tab-list" aria-label={label}>{items.map(item => <TabsPrimitive.Trigger key={item.id} value={item.id} className="vw-tab">{item.label}</TabsPrimitive.Trigger>)}</TabsPrimitive.List>
		{items.map(item => <TabsPrimitive.Content key={item.id} value={item.id} className="vw-tab-panel">{item.content}</TabsPrimitive.Content>)}
	</TabsPrimitive.Root>;
}

// A choice between two to four short options that are all visible at once. One is always selected.
export function Segmented({label, value, onChange, options}: {label: string, value: string, onChange: (value: string) => void, options: {value: string, label: string}[]}) {
	return <ToggleGroup.Root className="vw-segmented" type="single" aria-label={label} value={value} onValueChange={next => next && onChange(next)}>
		{options.map(o => <ToggleGroup.Item key={o.value} value={o.value} className="vw-segment">{o.label}</ToggleGroup.Item>)}
	</ToggleGroup.Root>;
}
