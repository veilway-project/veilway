import {AlertDialog, Dialog as DialogPrimitive, Toast as ToastPrimitive} from "radix-ui";
import {createContext, useCallback, useContext, useRef, useState, type ReactNode} from "react";
import {Button, Icon, IconButton, useI18n, type IconName} from "./core.tsx";

export type Tone = "info" | "success" | "warning" | "danger";
// Every tone has its own icon shape, so the tone survives without colour.
const TONE_ICON: Record<Tone, IconName> = {info: "info", success: "check", warning: "warning", danger: "error"};

export function Dialog({open, onOpenChange, title, description, children, footer}: {open: boolean, onOpenChange: (open: boolean) => void, title: string, description?: string, children?: ReactNode, footer?: ReactNode}) {
	const {t} = useI18n();
	return <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}><DialogPrimitive.Portal>
		<DialogPrimitive.Overlay className="vw-overlay"/>
		<DialogPrimitive.Content className="vw-glass vw-dialog" data-layer="dialog" {...(description ? {} : {"aria-describedby": undefined})}>
			<div className="vw-dialog-head"><DialogPrimitive.Title className="vw-h3">{title}</DialogPrimitive.Title><DialogPrimitive.Close asChild><IconButton icon="close" label={t("action.close")}/></DialogPrimitive.Close></div>
			{description && <DialogPrimitive.Description className="vw-muted">{description}</DialogPrimitive.Description>}
			{children}
			{footer && <div className="vw-dialog-foot">{footer}</div>}
		</DialogPrimitive.Content>
	</DialogPrimitive.Portal></DialogPrimitive.Root>;
}

// For an action that cannot be taken back. Focus starts on Cancel, and the confirm button names the action instead of saying "OK".
export function ConfirmDialog({open, onOpenChange, title, body, confirmLabel, danger, onConfirm}: {open: boolean, onOpenChange: (open: boolean) => void, title: string, body: string, confirmLabel: string, danger?: boolean, onConfirm: () => void}) {
	const {t} = useI18n();
	return <AlertDialog.Root open={open} onOpenChange={onOpenChange}><AlertDialog.Portal>
		<AlertDialog.Overlay className="vw-overlay"/>
		<AlertDialog.Content className="vw-glass vw-dialog" data-layer="dialog">
			<AlertDialog.Title className="vw-h3">{title}</AlertDialog.Title>
			<AlertDialog.Description className="vw-muted">{body}</AlertDialog.Description>
			<div className="vw-dialog-foot"><AlertDialog.Cancel asChild><Button>{t("action.cancel")}</Button></AlertDialog.Cancel><AlertDialog.Action asChild><Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>{confirmLabel}</Button></AlertDialog.Action></div>
		</AlertDialog.Content>
	</AlertDialog.Portal></AlertDialog.Root>;
}

export type ToastInput = {title: string, body?: string, tone?: Tone};
const ToastContext = createContext<(toast: ToastInput) => void>(() => {});

export function ToastProvider({children}: {children: ReactNode}) {
	const [items, setItems] = useState<(ToastInput & {id: number})[]>([]), next = useRef(0), {t, dir} = useI18n();
	const push = useCallback((toast: ToastInput) => setItems(list => [...list, {...toast, id: next.current++}]), []);
	return <ToastContext.Provider value={push}><ToastPrimitive.Provider label={t("toast.region")} swipeDirection={dir === "rtl" ? "left" : "right"}>
		{children}
		{items.map(item => <ToastPrimitive.Root key={item.id} className="vw-glass vw-toast" data-layer="popover" data-tone={item.tone ?? "info"} onOpenChange={open => { if (!open) setItems(list => list.filter(other => other.id !== item.id)); }}>
			<Icon name={TONE_ICON[item.tone ?? "info"]}/>
			<div><ToastPrimitive.Title className="vw-toast-title">{item.title}</ToastPrimitive.Title>{item.body && <ToastPrimitive.Description className="vw-muted vw-small">{item.body}</ToastPrimitive.Description>}</div>
			<ToastPrimitive.Close asChild><IconButton icon="close" label={t("action.dismiss")}/></ToastPrimitive.Close>
		</ToastPrimitive.Root>)}
		<ToastPrimitive.Viewport className="vw-toast-viewport"/>
	</ToastPrimitive.Provider></ToastContext.Provider>;
}

export function useToast(): (toast: ToastInput) => void {
	return useContext(ToastContext);
}

export function Banner({tone, title, children, action}: {tone: Tone, title: string, children?: ReactNode, action?: ReactNode}) {
	return <div className="vw-banner" data-tone={tone} role={tone === "info" || tone === "success" ? "status" : "alert"}>
		<Icon name={TONE_ICON[tone]}/>
		<div className="vw-banner-text"><strong>{title}</strong>{children && <p>{children}</p>}</div>
		{action}
	</div>;
}

// An empty list, a failed load, or a load still under way. The title says what is the case, the body what to do about it or what is being waited for, and the action does it. Loading shows the three strokes of the icon lighting in turn.
export function StateBlock({kind, title, children, action}: {kind: "empty" | "error" | "loading", title: string, children?: ReactNode, action?: ReactNode}) {
	return <div className="vw-state" data-kind={kind} role={kind === "error" ? "alert" : kind === "loading" ? "status" : undefined}>
		<span className="vw-state-icon">{kind === "loading" ? <span className="vw-strokes" aria-hidden="true"><i/><i/><i/></span> : <Icon name={kind === "error" ? "error" : "inbox"}/>}</span>
		<strong className="vw-h3">{title}</strong>
		{children && <p className="vw-muted">{children}</p>}
		{action}
	</div>;
}
