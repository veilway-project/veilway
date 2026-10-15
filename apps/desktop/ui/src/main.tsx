import "@veilway/ui/styles.css";
import {StrictMode} from "react";
import {createRoot} from "react-dom/client";
import "./app.css";

// `vite --mode mock` puts a stand-in for the Tauri side under the window first. The test is on a constant, so a production build drops the mock entirely.
if (import.meta.env.MODE === "mock") await import("./mock.ts");
const {App} = await import("./app.tsx");
createRoot(document.getElementById("app")!).render(<StrictMode><App/></StrictMode>);
