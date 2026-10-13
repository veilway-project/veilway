# UI package

Design tokens, the glass material, components, the theme validator and the gallery. The product name is spelled once, in `src/brand.ts`.

- `src/theme/`: colour parsing, the token set and its contrast rules (`tokens.ts`), the theme file validator (`validate.ts`), and the only code that turns a theme into CSS variables (`apply.ts`). `schema/veilway-theme.schema.json` describes the same file.
- `src/styles/`: `colors.css` is generated from `src/theme/tokens.ts` by `npm run tokens`; a test fails when it is stale. Everything else is written by hand. Import `@veilway/ui/styles.css` once.
- `src/components/`, `src/charts/`: the components. Wrap an app in `UiProvider` and `ToastProvider`.
- `src/gallery/`: the gallery app. Its address takes `page`, `scheme`, `lang`, `material`, `motion`, `digits`, `calendar` and `still`.

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

The script fails on any console error or warning, page error, request that leaves the origin, or sideways scroll.

Never run a formatter on this package.
