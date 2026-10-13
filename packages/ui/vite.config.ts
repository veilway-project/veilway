import react from "@vitejs/plugin-react";
import {defineConfig} from "vite";

// The gallery is the only app in this package. The i18n package is linked from ../i18n, so React must resolve to one copy and the dev server may read one folder up.
export default defineConfig({
	plugins: [react()],
	resolve: {dedupe: ["react", "react-dom"]},
	server: {port: 5173, strictPort: true, fs: {allow: [".."]}},
	preview: {port: 4173, strictPort: true},
	build: {outDir: "dist", target: "es2022"}
});
