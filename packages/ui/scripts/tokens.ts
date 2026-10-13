import {writeFileSync} from "node:fs";
import {builtinCss} from "../src/theme/apply.ts";

writeFileSync(new URL("../src/styles/colors.css", import.meta.url), builtinCss());
