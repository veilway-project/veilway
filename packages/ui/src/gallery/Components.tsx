import {useState} from "react";
import {Banner, Button, Checkbox, ConfirmDialog, DataTable, Dialog, IconButton, List, ListRow, NumberField, ProviderCard, RadioGroup, RatingBadge, SecretField, Segmented, SelectField, StateBlock, Switch, Tabs, TextField, UsageBar, useToast} from "../index.ts";
import {EXITS, PROVIDER_CARDS, PROVIDER_CARDS_FA, SAMPLE_KEY, SAMPLE_LINK, USERS} from "./data.ts";
import {Panel, useG} from "./shared.tsx";

export function Components() {
	const {t, locale, number} = useG(), toast = useToast();
	const [name, setName] = useState("family plan 02"), [quota, setQuota] = useState<number | "">(50), [devices, setDevices] = useState<number | "">(4), [group, setGroup] = useState("family"), [expiry, setExpiry] = useState(""), [cycle, setCycle] = useState("monthly"), [key, setKey] = useState(SAMPLE_KEY), [address, setAddress] = useState("fra.vpn.example.net:8443"), [enabled, setEnabled] = useState(true), [notify, setNotify] = useState(false);
	const [view, setView] = useState("users"), [density, setDensity] = useState("all"), [exit, setExit] = useState("de-fra"), [dialog, setDialog] = useState(false), [confirm, setConfirm] = useState(false), [provider, setProvider] = useState(true);
	const nameError = /^[a-z0-9][a-z0-9-]*$/.test(name) ? undefined : t("g.form.nameError");
	return <>
		<Panel title={t("g.comp.buttons")} note={t("g.comp.buttonsNote")}>
			<div className="g-cluster"><Button variant="primary">{t("action.save")}</Button><Button>{t("action.cancel")}</Button><Button variant="quiet">{t("g.comp.resetUsage")}</Button><Button variant="danger" icon="error">{t("g.comp.deleteUser")}</Button><Button variant="primary" disabled>{t("action.save")}</Button></div>
			<div className="g-cluster"><Button size="sm" icon="plus">{t("g.panel.addUser")}</Button><Button size="sm" icon="refresh">{t("g.comp.refresh")}</Button><IconButton icon="copy" label={t("action.copy")}/><IconButton icon="refresh" label={t("g.comp.refresh")}/><IconButton icon="chevronForward" label={t("g.comp.next")}/></div>
		</Panel>
		<Panel title={t("g.comp.forms")} note={t("g.comp.formsNote")}>
			<form className="g-form" onSubmit={event => { event.preventDefault(); toast(nameError ? {tone: "danger", title: t("g.form.notSaved"), body: nameError} : {tone: "success", title: t("g.form.saved"), body: name}); }}>
				<TextField label={t("g.form.name")} hint={t("g.form.nameHint")} error={nameError} value={name} onChange={setName} technical autoComplete="off"/>
				<SelectField label={t("g.form.group")} value={group} onChange={setGroup} options={[{value: "family", label: "family", detail: t("count.users", {count: 12})}, {value: "team", label: "team", detail: t("count.users", {count: 31})}, {value: "trial", label: "trial", detail: t("count.users", {count: 5})}]}/>
				<NumberField label={t("g.form.quota")} hint={t("g.form.quotaHint")} unit={t("unit.gb")} min={0} value={quota} onChange={setQuota}/>
				<NumberField label={t("g.form.devices")} optional unit={t("g.form.devicesUnit")} min={1} max={32} value={devices} onChange={setDevices}/>
				<SelectField label={t("g.form.expiry")} value={expiry} onChange={setExpiry} options={[{value: "30", label: t("g.form.days", {count: 30})}, {value: "90", label: t("g.form.days", {count: 90})}, {value: "never", label: t("g.form.never")}]}/>
				<TextField label={t("g.form.address")} value={address} onChange={setAddress} technical inputMode="url" autoComplete="off"/>
				<div className="g-form-wide"><SecretField label={t("g.form.key")} hint={t("g.form.keyHint")} value={key} onChange={setKey}/></div>
				<RadioGroup label={t("g.form.cycle")} value={cycle} onChange={setCycle} options={[{value: "monthly", label: t("g.form.monthly"), detail: t("g.form.monthlyHint")}, {value: "never", label: t("g.form.noReset")}]}/>
				<div className="g-stack"><Switch label={t("g.form.enabled")} hint={t("g.form.enabledHint")} checked={enabled} onChange={setEnabled}/><Checkbox label={t("g.form.notify")} checked={notify} onChange={setNotify}/></div>
				<div className="g-form-wide g-cluster"><Button variant="primary" type="submit">{t("action.save")}</Button><Button onClick={() => setName("family-plan-02")}>{t("g.form.fixName")}</Button></div>
			</form>
		</Panel>
		<Panel title={t("g.comp.lists")} note={t("g.comp.listsNote")}>
			<div className="g-row"><Segmented label={t("g.comp.show")} value={density} onChange={setDensity} options={[{value: "all", label: t("g.comp.all")}, {value: "online", label: t("g.panel.onlineNow")}]}/></div>
			<Tabs label={t("g.comp.lists")} value={view} onChange={setView} items={[
				{id: "users", label: t("g.comp.table"), content: <DataTable caption={t("g.panel.title")} rows={USERS.filter(u => density === "all" || u.online)} rowKey={u => u.name} columns={[
					{id: "name", header: t("g.col.user"), cell: u => <span className="vw-code">{u.name}</span>},
					{id: "usage", header: t("g.col.usage"), cell: u => <UsageBar compact label={u.name} used={u.used} total={u.quota}/>},
					{id: "expiry", header: t("g.col.expiry"), cell: u => t("count.daysLeft", {count: u.daysLeft})},
					{id: "devices", header: t("g.col.devices"), align: "end", cell: u => <span className="vw-num">{number(u.devices)}</span>}
				]}/>},
				{id: "list", label: t("g.comp.list"), content: <List label={t("g.client.exits")}>{EXITS.map(e => <ListRow key={e.id} current={e.id === exit} onClick={() => setExit(e.id)} title={t(`g.place.${e.place}`)} detail={<span className="vw-code">{e.host}</span>} trailing={<RatingBadge rating={e.rating}/>}/>)}</List>},
				{id: "empty", label: t("g.comp.empty"), content: <StateBlock kind="empty" title={t("g.state.emptyTitle")} action={<Button variant="primary" icon="plus">{t("g.panel.addUser")}</Button>}>{t("g.state.emptyBody")}</StateBlock>},
				{id: "error", label: t("g.comp.failed"), content: <StateBlock kind="error" title={t("g.state.errorTitle")} action={<Button icon="refresh">{t("action.retry")}</Button>}>{t("g.state.errorBody")}</StateBlock>}
			]}/>
		</Panel>
		<Panel title={t("g.comp.feedback")} note={t("g.comp.feedbackNote")}>
			<div className="g-cluster">
				<Button onClick={() => setDialog(true)}>{t("g.comp.openDialog")}</Button>
				<Button variant="danger" onClick={() => setConfirm(true)}>{t("g.comp.deleteUser")}</Button>
				<Button onClick={() => toast({tone: "success", title: t("g.toast.saved"), body: t("g.toast.savedBody")})}>{t("g.toast.showSuccess")}</Button>
				<Button onClick={() => toast({tone: "danger", title: t("g.toast.failed"), body: t("g.toast.failedBody")})}>{t("g.toast.showError")}</Button>
			</div>
			<div className="g-stack">
				<Banner tone="warning" title={t("banner.http.title")}>{t("banner.http.body")}</Banner>
				<Banner tone="info" title={t("g.banner.updateTitle")} action={<Button size="sm">{t("g.banner.updateAction")}</Button>}>{t("g.banner.updateBody")}</Banner>
				<Banner tone="danger" title={t("g.banner.downTitle")}>{t("g.banner.downBody")}</Banner>
				<Banner tone="success" title={t("g.banner.okTitle")}/>
			</div>
		</Panel>
		<Panel title={t("g.comp.rating")} note={t("g.comp.ratingNote")}>
			<div className="g-cluster"><RatingBadge rating="protected"/><RatingBadge rating="detectable"/><RatingBadge rating="unsafe"/></div>
			<div className="g-ratings"><RatingBadge rating="protected" detail/><RatingBadge rating="detectable" detail/><RatingBadge rating="unsafe" detail/></div>
		</Panel>
		<Panel title={t("g.comp.provider")} note={t("g.comp.providerNote")}>
			{provider ? <div className="g-provider"><ProviderCard provider="ExampleNet" accent="#C2410C" cards={locale === "fa" ? PROVIDER_CARDS_FA : PROVIDER_CARDS} onHide={() => setProvider(false)} onOpenLink={url => toast({title: t("g.client.opened"), body: url})}/></div> : <Button variant="quiet" icon="eye" onClick={() => setProvider(true)}>{t("g.client.showProvider")}</Button>}
		</Panel>
		<Dialog open={dialog} onOpenChange={setDialog} title={t("g.dialog.title")} description={t("g.dialog.body")} footer={<><Button onClick={() => setDialog(false)}>{t("action.close")}</Button><Button variant="primary" icon="copy" onClick={() => { setDialog(false); navigator.clipboard.writeText(SAMPLE_LINK).then(() => toast({tone: "success", title: t("action.copied")}), () => toast({tone: "danger", title: t("g.dialog.copyFailed"), body: t("g.dialog.copyFailedBody")})); }}>{t("g.dialog.copy")}</Button></>}>
			<p className="vw-well vw-code g-link">{SAMPLE_LINK}</p>
		</Dialog>
		<ConfirmDialog open={confirm} onOpenChange={setConfirm} danger title={t("g.confirm.title", {name: "student-04"})} body={t("g.confirm.body")} confirmLabel={t("g.comp.deleteUser")} onConfirm={() => toast({tone: "success", title: t("g.confirm.done", {name: "student-04"})})}/>
	</>;
}
