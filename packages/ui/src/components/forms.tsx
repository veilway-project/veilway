import {Checkbox as CheckboxPrimitive, RadioGroup as RadioGroupPrimitive, Select as SelectPrimitive, Switch as SwitchPrimitive} from "radix-ui";
import {useId, useState, type InputHTMLAttributes, type ReactNode} from "react";
import {Icon, useI18n} from "./core.tsx";

type FieldProps = {label: string, hint?: string, error?: string, optional?: boolean};
type FieldIds = {id: string, "aria-describedby": string | undefined, "aria-invalid": true | undefined};

// Label above, control, then one line under it: the error when there is one, the hint otherwise. The error replaces the hint so the line does not jump.
export function Field({label, hint, error, optional, children}: FieldProps & {children: (ids: FieldIds) => ReactNode}) {
	const id = useId(), {t} = useI18n();
	return <div className="vw-field" data-invalid={error ? "" : undefined}>
		<label className="vw-label" htmlFor={id}>{label}{optional && <span className="vw-muted"> ({t("field.optional")})</span>}</label>
		{children({id, "aria-describedby": error || hint ? id + "-note" : undefined, "aria-invalid": error ? true : undefined})}
		{(error || hint) && <p className="vw-note" id={id + "-note"} role={error ? "alert" : undefined}>{error && <Icon name="error"/>}{error ?? hint}</p>}
	</div>;
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "onChange" | "value" | "id">;

// technical marks a value that is not prose (an address, a port, a key): it is set in the mono face and stays left to right in Persian.
export function TextField({label, hint, error, optional, value, onChange, technical, ...rest}: FieldProps & InputProps & {value: string, onChange: (value: string) => void, technical?: boolean}) {
	return <Field label={label} hint={hint} error={error} optional={optional}>{ids => <input {...rest} {...ids} className={"vw-input" + (technical ? " vw-code" : "")} dir={technical ? "ltr" : undefined} spellCheck={technical ? false : undefined} value={value} onChange={e => onChange(e.target.value)}/>}</Field>;
}

export function NumberField({label, hint, error, optional, value, onChange, unit, ...rest}: FieldProps & InputProps & {value: number | "", onChange: (value: number | "") => void, unit: string}) {
	return <Field label={label} hint={hint} error={error} optional={optional}>{ids => <div className="vw-input-group">
		<input {...rest} {...ids} className="vw-input vw-num" type="number" inputMode="decimal" dir="ltr" value={value} onChange={e => onChange(e.target.value === "" ? "" : Number(e.target.value))}/>
		<span className="vw-unit" aria-hidden="true">{unit}</span>
		<span className="vw-sr">{unit}</span>
	</div>}</Field>;
}

// A secret is hidden until asked for, never offered to a password manager as a login, and never spell-checked (spell-check can send text to a server).
export function SecretField({label, hint, error, optional, value, onChange, ...rest}: FieldProps & InputProps & {value: string, onChange: (value: string) => void}) {
	const [shown, setShown] = useState(false), {t} = useI18n();
	return <Field label={label} hint={hint} error={error} optional={optional}>{ids => <div className="vw-input-group">
		<input {...rest} {...ids} className="vw-input vw-code" type={shown ? "text" : "password"} dir="ltr" autoComplete="off" autoCapitalize="off" spellCheck={false} value={value} onChange={e => onChange(e.target.value)}/>
		<button type="button" className="vw-input-action" aria-pressed={shown} aria-label={t(shown ? "secret.hide" : "secret.show", {label})} title={t(shown ? "secret.hide" : "secret.show", {label})} onClick={() => setShown(!shown)}><Icon name={shown ? "eyeOff" : "eye"}/></button>
	</div>}</Field>;
}

export type Option = {value: string, label: string, detail?: string};

export function SelectField({label, hint, error, optional, value, onChange, options, disabled}: FieldProps & {value: string, onChange: (value: string) => void, options: Option[], disabled?: boolean}) {
	const {t} = useI18n();
	return <Field label={label} hint={hint} error={error} optional={optional}>{ids => <SelectPrimitive.Root value={value} onValueChange={onChange} disabled={disabled}>
		<SelectPrimitive.Trigger {...ids} className="vw-input vw-select"><SelectPrimitive.Value placeholder={t("select.placeholder")}/><SelectPrimitive.Icon><Icon name="chevronDown"/></SelectPrimitive.Icon></SelectPrimitive.Trigger>
		<SelectPrimitive.Portal><SelectPrimitive.Content className="vw-glass vw-menu" data-depth="3" position="popper" sideOffset={4}><SelectPrimitive.Viewport>
			{options.map(o => <SelectPrimitive.Item key={o.value} value={o.value} className="vw-menu-item"><SelectPrimitive.ItemText>{o.label}</SelectPrimitive.ItemText>{o.detail && <span className="vw-muted vw-small">{o.detail}</span>}<SelectPrimitive.ItemIndicator className="vw-menu-check"><Icon name="check"/></SelectPrimitive.ItemIndicator></SelectPrimitive.Item>)}
		</SelectPrimitive.Viewport></SelectPrimitive.Content></SelectPrimitive.Portal>
	</SelectPrimitive.Root>}</Field>;
}

export function Switch({label, hint, checked, onChange, disabled}: {label: string, hint?: string, checked: boolean, onChange: (checked: boolean) => void, disabled?: boolean}) {
	const id = useId();
	return <div className="vw-toggle-row">
		<div><label className="vw-label" htmlFor={id}>{label}</label>{hint && <p className="vw-note" id={id + "-note"}>{hint}</p>}</div>
		<SwitchPrimitive.Root id={id} className="vw-switch" checked={checked} onCheckedChange={onChange} disabled={disabled} aria-describedby={hint ? id + "-note" : undefined}><SwitchPrimitive.Thumb className="vw-switch-thumb"/></SwitchPrimitive.Root>
	</div>;
}

export function Checkbox({label, checked, onChange, disabled}: {label: string, checked: boolean, onChange: (checked: boolean) => void, disabled?: boolean}) {
	const id = useId();
	return <div className="vw-check-row">
		<CheckboxPrimitive.Root id={id} className="vw-checkbox" checked={checked} onCheckedChange={state => onChange(state === true)} disabled={disabled}><CheckboxPrimitive.Indicator><Icon name="check"/></CheckboxPrimitive.Indicator></CheckboxPrimitive.Root>
		<label htmlFor={id}>{label}</label>
	</div>;
}

export function RadioGroup({label, value, onChange, options}: {label: string, value: string, onChange: (value: string) => void, options: Option[]}) {
	const id = useId();
	return <div className="vw-field">
		<span className="vw-label" id={id}>{label}</span>
		<RadioGroupPrimitive.Root className="vw-radio-group" aria-labelledby={id} value={value} onValueChange={onChange}>
			{options.map(o => <div className="vw-check-row" key={o.value}>
				<RadioGroupPrimitive.Item id={id + o.value} value={o.value} className="vw-radio"><RadioGroupPrimitive.Indicator className="vw-radio-dot"/></RadioGroupPrimitive.Item>
				<label htmlFor={id + o.value}>{o.label}{o.detail && <span className="vw-note">{o.detail}</span>}</label>
			</div>)}
		</RadioGroupPrimitive.Root>
	</div>;
}

export function Slider({label, hint, value, onChange, min, max, step, display}: {label: string, hint?: string, value: number, onChange: (value: number) => void, min: number, max: number, step: number, display: string}) {
	return <Field label={label} hint={hint}>{ids => <div className="vw-slider-row"><input {...ids} className="vw-slider" type="range" min={min} max={max} step={step} value={value} aria-valuetext={display} onChange={e => onChange(Number(e.target.value))}/><output className="vw-num" htmlFor={ids.id}>{display}</output></div>}</Field>;
}
