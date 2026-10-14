import {Icon, useI18n} from "./core.tsx";

export type ConnectState = "off" | "connecting" | "on";

// The control a client exists for: the stroke of the app icon as a key in a glass track. Off, it rests at the start. Pressed, it travels to the end and the three thinner strokes of the icon light up behind it one after another; connected, the key takes the accent colour. The label always names what a press does next, so the state is carried by position, colour and words together.
export function ConnectSwitch({state, onToggle, disabled}: {state: ConnectState, onToggle: () => void, disabled?: boolean}) {
	const {t} = useI18n();
	return <button type="button" className="vw-glass vw-connect" data-state={state} disabled={disabled} onClick={onToggle}>
		<span className="vw-connect-slide" aria-hidden="true"><span className="vw-connect-trail"><i/><i/><i/></span><span className="vw-connect-key"><Icon name="power"/></span></span>
		<span className="vw-connect-label">{t(state === "off" ? "action.connect" : state === "connecting" ? "action.cancel" : "action.disconnect")}</span>
	</button>;
}
