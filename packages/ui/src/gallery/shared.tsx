import type {ReactNode} from "react";
import {useI18n} from "../index.ts";
import type {GalleryKey} from "./copy.ts";

export const useG = () => useI18n<GalleryKey>();

export function Panel({title, note, children}: {title: string, note?: string, children: ReactNode}) {
	return <section className="vw-glass g-panel"><header><h2 className="vw-h2">{title}</h2>{note && <p className="vw-muted">{note}</p>}</header>{children}</section>;
}
