# UI package

Design tokens, the glass material, components, the theme validator and the gallery. The product name is spelled once, in `src/brand.ts`.

- `src/theme/`: colour parsing, the token set and its contrast rules (`tokens.ts`), the theme file validator (`validate.ts`), and the only code that turns a theme into CSS variables (`apply.ts`). `schema/veilway-theme.schema.json` describes the same file.
- `src/styles/`: `colors.css` is generated from `src/theme/tokens.ts` by `npm run tokens`; a test fails when it is stale. Everything else is written by hand. Import `@veilway/ui/styles.css` once.
- `src/components/`, `src/charts/`: the components. Wrap an app in `UiProvider` and `ToastProvider`, and put `Backdrop fixed` at its root.
- `src/gallery/`: the gallery app. Its address takes `page`, `scheme`, `lang`, `material`, `motion`, `digits`, `calendar`, `still` and, for the client window, `link` (`off`, `connecting`).

## The glass and its contrast rule

The app paints its own backdrop (`Backdrop`: the page colour, two glows, the light shafts), so what can be behind a pane of glass is known. `MATERIAL` in `src/theme/tokens.ts` holds the numbers the stylesheet paints with, `backdrop()` lists every colour they can produce from a palette, and `RULES` says which text may sit on which ground. The tests fail when any allowed pair drops under AA (4.5 for text, 3 for marks) on any colour its ground can take.

| Layer | Used for | What can be behind it | Tint |
|---|---|---|---|
| sheet | panels, cards, the connect track | the backdrop only | the theme's `glass.tint` |
| chrome | navigation, chart tooltip | the backdrop and content scrolling under it | at least 0.24 more |
| popover | menus, toasts | all of that, and the dimmed page | at least 0.40 more |
| dialog | dialogs, over a scrim | the same as a popover | the same as a popover |

- The validator checks a theme's backdrop colours, surface colour, tint and blur together. A tint too thin for the theme's own backdrop is raised; a backdrop too bright for text set straight on it is refused. The two denser tints are worked out in `themeVars` and cannot be set by a file.
- Text and thin marks that pass under chrome count as smeared to half coverage once the blur is 16px or more, and in full with no blur, so a theme with little blur gets denser chrome.
- Status colours as text and chart lines are not allowed on a bare sheet. They go on a wash (badges, banners) or in a well (`vw-well`, every chart).
- A sheet inside a sheet does not blur again. Keep the number of blurred layers on a phone screen small: the client home has three (connect track, stats, navigation).
- Solid surfaces replace the glass under `prefers-reduced-transparency`, with `material: "solid"`, and where `backdrop-filter` is missing. They keep the edge, gradient and shadow.
- The grain on glass is an inline SVG data URI, so an app's content security policy needs `img-src data:`.

Everything runs in containers, with named volumes for `node_modules`. From the repository root:

```
V="-v $PWD/packages:/work/packages -v veilway-i18n-nm:/work/packages/i18n/node_modules -v veilway-ui-nm:/work/packages/ui/node_modules"
docker run --rm $V -w /work/packages/i18n node:22 sh -c "npm ci && npm run check && npm test"
docker run --rm $V -w /work/packages/ui node:22 sh -c "npm ci && npm run check && npm test && npm run build"
docker run --rm $V -w /work/packages/ui -p 127.0.0.1:5173:5173 node:22 npm run dev
```

Screenshots (the image tag must match the Playwright version; Playwright lives in its own volume and is not a dependency of this package):

```
docker run --rm --ipc=host $V -v veilway-ui-pw:/pw -v "$OUT":/out -w /work/packages/ui mcr.microsoft.com/playwright:v1.64.0-noble sh -c "test -d /pw/node_modules/playwright || (cd /pw && npm init -y && npm install playwright@1.64.0); npx vite preview --host 127.0.0.1 & sleep 3; PW_HOME=/pw OUT=/out node scripts/shots.mjs"
```

The script fails on any console error or warning, page error, request that leaves the origin, or sideways scroll. The backdrop is pinned to the viewport, so whole pages are shot through a viewport as tall as the page.

Never run a formatter on this package.
