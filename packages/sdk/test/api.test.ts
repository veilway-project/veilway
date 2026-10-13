import assert from "node:assert/strict";
import {test} from "node:test";
import {Agent, fetch as undiciFetch} from "undici";
import {Client, VeilwayError, type Fetch} from "../src/index.js";

const socket = process.env.VEILWAY_API_SOCKET;
const live = {skip: socket ? false : "VEILWAY_API_SOCKET is not set"};
const dispatcher = new Agent({connect: {socketPath: socket ?? ""}});
const viaSocket: Fetch = (url, init) => undiciFetch(url, {...init, dispatcher}) as unknown as ReturnType<Fetch>;
const client = new Client(viaSocket, "http://veilway");

test("status", live, async () => {
	const status = await client.status();
	assert.equal(typeof status.version, "string");
	assert.ok(status.generation >= 1);
	assert.ok(status.revision.length > 0);
});

test("config is redacted and validates and diffs against itself", live, async () => {
	const running = await client.getConfig();
	assert.equal(running.document.version, 1);
	assert.doesNotMatch(JSON.stringify(running.document), /"private_key":"(?!<redacted>)/);
	const validation = await client.validateConfig(running.document);
	assert.equal(validation.valid, true);
	const difference = await client.diffConfig(running.document);
	assert.equal(difference.valid, true);
});

test("apply with a stale revision is refused with the revision that runs", live, async () => {
	const running = await client.getConfig();
	await assert.rejects(client.applyConfig(running.document, "0".repeat(64)), (e: unknown) => e instanceof VeilwayError && e.status === 409 && e.code === "stale_revision" && e.details[0]?.message === running.revision);
});

test("a body that is not a config is an error document", live, async () => {
	const validation = await client.validateConfig({version: 1, inbounds: "no"});
	assert.equal(validation.valid, false);
	assert.ok(validation.report.errors.length > 0);
});

test("stats, users, sessions and exits", live, async () => {
	const stats = await client.stats();
	assert.equal(typeof stats.flows, "number");
	assert.ok(Array.isArray(await client.listUsers()));
	assert.ok(Array.isArray(await client.listSessions()));
	assert.ok(Array.isArray(await client.listExits()));
});

test("one event from the stream", live, async () => {
	const stop = new AbortController();
	const timer = setTimeout(() => stop.abort(), 10000);
	let seen: string | undefined;
	for await (const event of client.events(stop.signal)) {
		seen = event.event;
		break;
	}
	clearTimeout(timer);
	assert.equal(seen, "stats");
});

test("the stream ends quietly on abort", live, async () => {
	const stop = new AbortController();
	setTimeout(() => stop.abort(), 200);
	for await (const _ of client.events(stop.signal)) {}
});

test("an unknown user is a user_not_found error", live, async () => {
	await assert.rejects(client.getUser("no.such.user"), (e: unknown) => e instanceof VeilwayError && e.status === 404 && e.code === "user_not_found");
});

test("a usage reset answers with the user, zeroes the totals when asked and knows no unknown user", live, async () => {
	const user = await client.resetUsage("alice");
	assert.equal(user.name, "alice");
	assert.equal(user.used_bytes, 0);
	assert.deepEqual((await client.resetUsage("alice", {totals: true})).traffic, {up_bytes: 0, up_packets: 0, down_bytes: 0, down_packets: 0});
	await assert.rejects(client.resetUsage("no.such.user"), (e: unknown) => e instanceof VeilwayError && e.status === 404 && e.code === "user_not_found");
});

test("the event stream parser reads ids, comments, CRLF and lagged", async () => {
	const body = ": keepalive\r\nid: 7\r\nevent: user_restored\r\ndata: {\"user\":\r\ndata: \"a\"}\r\n\r\nevent: lagged\ndata: {\"missed\":3}\n\nevent: other\ndata: 1\n\n";
	const bytes = new TextEncoder().encode(body);
	const double: Fetch = async () => ({status: 200, headers: {get: () => null}, text: async () => "", body: new ReadableStream({start(c) {for (let i = 0; i < bytes.length; i += 3) c.enqueue(bytes.slice(i, i + 3)); c.close()}})});
	const seen = [];
	for await (const event of new Client(double, "http://x").events()) seen.push(event);
	assert.deepEqual(seen, [{id: "7", event: "user_restored", data: {user: "a"}}, {id: undefined, event: "lagged", data: {missed: 3}}]);
});
