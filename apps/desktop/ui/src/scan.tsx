import {Banner, Button, Dialog} from "@veilway/ui";
import {useEffect, useRef, useState} from "react";
import {failureText, useD} from "./kit.tsx";
import {call, type LegacyOffer, type Offer} from "./tauri.ts";

// Frames the helper refuses or cannot read are not the user's problem: the next one is tried.
const SKIPPED = ["scan_busy", "picture_unreadable", "picture_large"];

// The live preview of the camera. A frame goes to the Rust decoder every 300 ms, downscaled, and is dropped after the call. The camera stops when a code is read, on an error, and when the dialog closes (the cleanup of the effect).
export function ScanDialog({onClose, onFound}: {onClose: () => void, onFound: (offer: Offer | LegacyOffer) => void}) {
	const {t} = useD(), video = useRef<HTMLVideoElement>(null), [error, setError] = useState<string | null>(null), [live, setLive] = useState(false);
	useEffect(() => {
		let stream: MediaStream | undefined, timer = 0, stopped = false, sending = false;
		const stop = () => { stopped = true; clearInterval(timer); stream?.getTracks().forEach(track => track.stop()); };
		navigator.mediaDevices.getUserMedia({video: {facingMode: "environment"}, audio: false}).then(async opened => {
			if (stopped) return opened.getTracks().forEach(track => track.stop());
			stream = opened;
			const preview = video.current!, canvas = document.createElement("canvas"), pen = canvas.getContext("2d");
			preview.srcObject = opened;
			await preview.play();
			setLive(true);
			timer = window.setInterval(() => {
				if (sending || stopped || !pen || !preview.videoWidth) return;
				const scale = Math.min(1, 800 / preview.videoWidth);
				canvas.width = Math.round(preview.videoWidth * scale);
				canvas.height = Math.round(preview.videoHeight * scale);
				pen.drawImage(preview, 0, 0, canvas.width, canvas.height);
				sending = true;
				call("scan_frame", {data: canvas.toDataURL("image/jpeg", 0.8).split(",")[1]!}).then(offer => { if (offer && !stopped) { stop(); onFound(offer); } }, code => { if (!SKIPPED.includes(code)) { stop(); setError(code); } }).finally(() => { sending = false; });
			}, 300);
		}, failure => setError(failure?.name === "NotAllowedError" || failure?.name === "SecurityError" ? "camera_denied" : failure?.name === "NotFoundError" ? "camera_none" : "scan_failed"));
		return stop;
	}, []);
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("scan.title")} description={t("scan.privacy")}>
		<div className="d-scan"><video ref={video} muted playsInline/></div>
		{!error && <p className="vw-muted vw-small">{t(live ? "scan.hint" : "scan.starting")}</p>}
		{error && <Banner tone="danger" title={t("import.failed")}>{failureText(error, t)}</Banner>}
		<div className="d-actions"><Button onClick={onClose}>{t("common.cancel")}</Button></div>
	</Dialog>;
}
