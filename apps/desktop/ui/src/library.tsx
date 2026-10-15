import {Button, Checkbox, ConfirmDialog, Glass, IconButton, List, ListRow, StateBlock, useToast} from "@veilway/ui";
import {Fragment, useState} from "react";
import {fromUnix, useD, useLogo} from "./kit.tsx";
import {call, type Subscription} from "./tauri.ts";

function Logo({subscription}: {subscription: Subscription}) {
	const url = useLogo(subscription.logo);
	return url ? <img className="d-logo" src={url} alt=""/> : <span className="d-logo" aria-hidden="true">{Array.from(subscription.provider)[0]}</span>;
}

export function Library({library, inUse, onAdd, onRefresh, onChange}: {library: Subscription[], inUse: string | null, onAdd: () => void, onRefresh: (id: string) => Promise<void>, onChange: (library: Subscription[]) => void}) {
	const {t, date, locale} = useD(), toast = useToast(), [removing, setRemoving] = useState<Subscription | null>(null), [refreshing, setRefreshing] = useState<string | null>(null);
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
			<li className="d-row-option"><Checkbox label={t("library.lan")} checked={subscription.lan_through_tunnel} onChange={on => { setLan(subscription, on); }}/><span className="vw-muted vw-small">{t("library.lanHint")}</span></li>
		</Fragment>)}</List></Glass>}
		<ConfirmDialog open={removing !== null} onOpenChange={open => { if (!open) setRemoving(null); }} danger title={t("library.removeTitle", {provider: removing?.provider ?? ""})} body={t("library.removeBody")} confirmLabel={t("library.remove")} onConfirm={() => { if (removing) remove(removing); }}/>
	</div>;
}
