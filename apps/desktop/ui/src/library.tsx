import {Banner, Button, Checkbox, ConfirmDialog, Dialog, Glass, Icon, IconButton, List, ListRow, StateBlock, useToast} from "@veilway/ui";
import {Fragment, useState} from "react";
import {fromUnix, useD, useLogo} from "./kit.tsx";
import {call, type Subscription} from "./tauri.ts";

function Logo({subscription}: {subscription: Subscription}) {
	const url = useLogo(subscription.logo);
	return url ? <img className="d-logo" src={url} alt=""/> : <span className="d-logo" aria-hidden="true">{Array.from(subscription.provider)[0]}</span>;
}

// The backup update addresses of one subscription. From the notice it lists the ones that wait, none ticked; from the details, the ones already answered, as they stand. A host is allowed only by a tick or by "Allow all", and an unticked one is declined, so it is not asked about again until the provider drops it and lists it again.
function Hosts({subscription, review, onClose, onChange}: {subscription: Subscription, review: boolean, onClose: () => void, onChange: (library: Subscription[]) => void}) {
	const {t} = useD(), toast = useToast(), shown = subscription.hosts.filter(host => (host.state === "waiting") === review), [ticked, setTicked] = useState(() => new Set(shown.filter(host => host.state === "allowed").map(host => host.key))), [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
	const save = (allow: string[]) => { setBusy(true); setError(null); call("answer_hosts", {id: subscription.id, allow, decline: shown.filter(host => !allow.includes(host.key)).map(host => host.key)}).then(found => { onChange(found); toast({tone: "success", title: t("library.hosts.saved")}); onClose(); }, setError).finally(() => setBusy(false)); };
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("library.hosts.title")} description={t(review ? "library.hosts.body" : "library.hosts.manageBody", {provider: subscription.provider})} footer={review ? <>
		<Button variant="quiet" disabled={busy} onClick={onClose}>{t("library.hosts.later")}</Button><Button disabled={busy} onClick={() => save([...ticked])}>{t("library.hosts.save")}</Button><Button variant="primary" disabled={busy} onClick={() => save(shown.map(host => host.key))}>{t("library.hosts.allowAll")}</Button>
	</> : <><Button disabled={busy} onClick={onClose}>{t("common.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => save([...ticked])}>{t("library.hosts.save")}</Button></>}>
		<ul className="d-hosts" aria-label={t("library.hosts.list")}>{shown.map(host => <li key={host.key} className="d-host">
			<Checkbox label={host.host} checked={ticked.has(host.key)} onChange={on => setTicked(found => { const next = new Set(found); if (on) next.add(host.key); else next.delete(host.key); return next; })}/>
			<span className="d-host-kind vw-muted vw-small" data-kind={host.kind}><Icon name={host.kind === "static" ? "lock" : "eye"}/>{t(`library.hosts.${host.kind}`, {from: host.from ?? ""})}</span>
			{host.check === "plain" && <span className="d-host-kind vw-muted vw-small" data-kind="plain"><Icon name="eye"/>{t("library.hosts.plain")}</span>}
		</li>)}</ul>
		{error && <Banner tone="danger" title={t("library.hosts.failed")}>{error}</Banner>}
	</Dialog>;
}

export function Library({library, inUse, onAdd, onRefresh, onChange}: {library: Subscription[], inUse: string | null, onAdd: () => void, onRefresh: (id: string) => Promise<void>, onChange: (library: Subscription[]) => void}) {
	const {t, date, locale} = useD(), toast = useToast(), [removing, setRemoving] = useState<Subscription | null>(null), [refreshing, setRefreshing] = useState<string | null>(null), [hosts, setHosts] = useState<{id: string, review: boolean} | null>(null), reviewing = library.find(found => found.id === hosts?.id);
	const remove = (subscription: Subscription) => call("remove", {id: subscription.id}).then(found => { onChange(found); toast({tone: "success", title: t("library.removed")}); }, error => toast({tone: "danger", title: t("library.removeFailed"), body: error}));
	const setLan = (subscription: Subscription, on: boolean) => call("set_lan", {id: subscription.id, on}).then(onChange, error => toast({tone: "danger", title: t("library.lanFailed"), body: error}));
	return <div className="d-page">
		<div className="d-head"><h1 className="vw-h1">{t("library.title")}</h1><Button variant="primary" icon="plus" onClick={onAdd}>{t("library.add")}</Button></div>
		{library.length === 0 ? <Glass className="d-panel"><StateBlock kind="empty" title={t("library.empty")}>{t("library.emptyBody")}</StateBlock></Glass> : <Glass className="d-list"><List label={t("library.title")}>{library.map(subscription => <Fragment key={subscription.id}><ListRow
			leading={<Logo subscription={subscription}/>}
			title={subscription.provider}
			detail={[t(`library.standing.${subscription.standing}`), t("library.ends", {date: date(fromUnix(subscription.expires_at))}), t("library.connections", {count: subscription.profiles.length})].join(locale === "fa" ? "، " : ", ")}
			trailing={<span className="d-row-actions">
				{subscription.can_refresh && <IconButton icon="refresh" label={t("library.refresh", {provider: subscription.provider})} disabled={refreshing === subscription.id} onClick={() => { setRefreshing(subscription.id); onRefresh(subscription.id).finally(() => setRefreshing(null)); }}/>}
				<Button size="sm" variant="quiet" disabled={inUse === subscription.id} onClick={() => setRemoving(subscription)}>{t("library.remove")}</Button>
			</span>}/>
			{subscription.hosts.some(host => host.state === "waiting") ? <li className="d-row-notice"><Icon name="info"/><span className="d-row-notice-text"><span>{t(subscription.hosts.some(host => host.state === "waiting" && host.kind === "move") ? "library.hosts.noticeMove" : "library.hosts.notice")}</span><span className="vw-muted vw-small">{t("library.hosts.noticeBody")}</span></span><Button size="sm" onClick={() => setHosts({id: subscription.id, review: true})}>{t("library.hosts.review")}</Button></li>
				: subscription.hosts.length > 0 && <li className="d-row-notice"><Icon name="globe"/><span className="d-row-notice-text"><span>{t("library.hosts.label")}</span><span className="vw-muted vw-small">{t("library.hosts.counts", {allowed: subscription.hosts.filter(host => host.state === "allowed").length, declined: subscription.hosts.filter(host => host.state === "declined").length})}</span></span><Button size="sm" variant="quiet" onClick={() => setHosts({id: subscription.id, review: false})}>{t("library.hosts.manage")}</Button></li>}
			<li className="d-row-option"><Checkbox label={t("library.lan")} checked={subscription.lan_local} onChange={on => { setLan(subscription, on); }}/><span className="vw-muted vw-small">{t("library.lanHint")}</span></li>
		</Fragment>)}</List></Glass>}
		{hosts && reviewing && <Hosts key={`${hosts.id}-${hosts.review}`} subscription={reviewing} review={hosts.review} onClose={() => setHosts(null)} onChange={onChange}/>}
		<ConfirmDialog open={removing !== null} onOpenChange={open => { if (!open) setRemoving(null); }} danger title={t("library.removeTitle", {provider: removing?.provider ?? ""})} body={t("library.removeBody")} confirmLabel={t("library.remove")} onConfirm={() => { if (removing) remove(removing); }}/>
	</div>;
}
