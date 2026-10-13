import {StrictMode} from "react";
import {createRoot} from "react-dom/client";
import "../styles/index.css";
import "./gallery.css";
import {Gallery} from "./Gallery.tsx";

createRoot(document.getElementById("app")!).render(<StrictMode><Gallery/></StrictMode>);
