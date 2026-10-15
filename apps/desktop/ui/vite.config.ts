import react from "@vitejs/plugin-react";
import {defineConfig} from "vite";

// The design system is linked from ../../../../veilway-ui, so React must resolve to one copy. The window's CSP allows no inline scripts or data: fonts, so nothing is inlined.
export default defineConfig({
	base: "./",
	plugins: [react()],
	resolve: {dedupe: ["react", "react-dom"]},
	server: {port: 5175, strictPort: true, fs: {allow: ["..", "../../../../veilway-ui"]}},
	build: {outDir: "dist", target: "es2022", assetsInlineLimit: 0}
});
