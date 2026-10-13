# @veilway/sdk

A typed client for the control API of a Veilway node. The node serves the API on a unix socket, so the client takes a `fetch` function and a base URL and leaves the choice of how to reach the socket to you. It has no runtime dependencies.

## Use

```ts
import {Agent, fetch as undiciFetch} from "undici";
import {Client, VeilwayError, type Fetch} from "@veilway/sdk";

const dispatcher = new Agent({connect: {socketPath: "/run/veilway/veilway.sock"}});
const fetch: Fetch = (url, init) => undiciFetch(url, {...init, dispatcher}) as unknown as ReturnType<Fetch>;
const client = new Client(fetch, "http://veilway");
console.log(await client.status());
const running = await client.getConfig();
try {
	await client.applyConfig({...running.document, log: {level: "debug"}}, running.revision);
} catch (e) {
	if (e instanceof VeilwayError) console.log(e.status, e.code, e.message, e.details);
}
const stop = new AbortController();
for await (const event of client.events(stop.signal)) {
	if (event.event === "user_cut_off") console.log(event.data.user);
}
```

Every failure from the node is thrown as `VeilwayError` with `status`, `code`, `message` and `details`. A stale revision on `applyConfig` has the code `stale_revision`, and its first detail holds the revision that runs now.

`events` yields `{id, event, data}`, ends when the node closes the stream or the signal aborts, and tells a slow reader how many events it missed with a `lagged` event (which has no id). Event names the client does not know are skipped.

The config document in `getConfig` has every secret replaced by `"<redacted>"`. Pass it back as it is and the node keeps the real values.

## Commands

Everything runs in Docker with the image `node:22`.

```
docker run --rm -v "$PWD/../..:/w" -v veilway-sdk-nm:/w/packages/sdk/node_modules -w /w/packages/sdk node:22 sh -c "npm ci && npm run generate"
docker run --rm -v "$PWD/../..:/w" -v veilway-sdk-nm:/w/packages/sdk/node_modules -w /w/packages/sdk node:22 sh -c "npm ci && npm run check"
```

- `npm run generate` writes `src/schema.ts` from `crates/veilway-api/openapi.json`. Run it after the Rust tests rewrite that file.
- `npm run check` generates into a temporary file, fails if it differs from `src/schema.ts`, then type-checks.
- `npm test` compiles and runs the tests. The ones that talk to a node need `VEILWAY_API_SOCKET` and are skipped without it. The parser test needs no node.

## Test against a running node

The test starts nothing. `test/live.sh` starts a node from a release binary with a throwaway config and keys, runs `npm test` against its socket and stops the node. Run it in a container that has both node 22 and a `veilway` binary that matches its libc, with `VEILWAY_BIN` set to the binary. Without the script, start a node with `veilway run --api /path/to.sock` and set `VEILWAY_API_SOCKET` to that path.
