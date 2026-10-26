import type {components} from "./schema.js";

type Schemas = components["schemas"];
export type {components, paths, operations} from "./schema.js";
export type Status = Schemas["Status"];
export type Applied = Schemas["Applied"];
export type Difference = Schemas["Difference"];
export type Validation = Schemas["Validation"];
export type User = Schemas["User"];
export type Stats = Schemas["Stats"];
export type Replay = Schemas["Replay"];
export type Session = Schemas["Session"];
export type Exit = Schemas["Exit"];
export type Link = Schemas["Link"];
export type Upstream = Schemas["Upstream"];
export type UpstreamPreview = Schemas["UpstreamPreview"];
export type UpstreamPreviewRequest = Schemas["UpstreamPreviewRequest"];
export type UpstreamConfirmed = Schemas["UpstreamConfirmed"];
export type UpstreamChoice = Schemas["UpstreamChoice"];
export type UpstreamChosen = Schemas["UpstreamChosen"];
export type UpstreamRemoved = Schemas["UpstreamRemoved"];
export type InboundInfo = Schemas["InboundInfo"];
export type Problem = Schemas["Problem"];
/** A config v1 document. The generated schema calls it an object nobody can fill in, so the client takes any object and the node does the checking. */
export type ConfigDocument = Record<string, unknown>;
export type RunningConfig = Omit<Schemas["Running"], "document"> & {document: ConfigDocument};
/** The data of each event on the stream, by the name of the event. */
export interface EventData {
	config_applied: Schemas["ConfigApplied"];
	config_refused: Schemas["ConfigRefused"];
	user_cut_off: Schemas["UserCutOff"];
	user_restored: Schemas["UserRestored"];
	usage_reset: Schemas["UsageReset"];
	exit_udp_changed: Schemas["ExitUdpChanged"];
	exit_working_changed: Schemas["ExitWorkingChanged"];
	stats: Schemas["Stats"];
	lagged: Schemas["Lagged"];
}
/** One event of the stream. `id` is empty for `lagged`, which has none. */
export type NodeEvent = {[K in keyof EventData]: {id: string | undefined, event: K, data: EventData[K]}}[keyof EventData];
/** The part of a fetch response the client uses, so the fetch of undici, the global one and a test double all fit. */
export interface FetchResponse {
	status: number;
	headers: {get(name: string): string | null};
	text(): Promise<string>;
	body: ReadableStream<Uint8Array> | null;
}
export type Fetch = (url: string, init: {method: string, headers: Record<string, string>, body?: string, signal?: AbortSignal}) => Promise<FetchResponse>;
/** The most one line of the event stream may hold before the client gives up on it. */
const MAX_LINE = 1 << 20;
const EVENTS = new Set<string>(["config_applied", "config_refused", "user_cut_off", "user_restored", "usage_reset", "exit_udp_changed", "exit_working_changed", "stats", "lagged"]);

/** Every answer that is not a success, and an answer the client could not read. */
export class VeilwayError extends Error {
	constructor(readonly status: number, readonly code: string, message: string, readonly details: Problem[] = []) {
		super(message);
		this.name = "VeilwayError";
	}
}

export class Client {
	/** `base` is only the start of every URL, for example "http://veilway": over a unix socket the host is never looked up, the `fetch` decides where the bytes go. */
	constructor(private readonly fetch: Fetch, private readonly base: string) {}

	private async send(method: string, path: string, headers: Record<string, string> = {}, body?: string, signal?: AbortSignal): Promise<FetchResponse> {
		const response = await this.fetch(this.base.replace(/\/+$/, "") + path, {method, headers: {accept: "application/json", ...headers}, body, signal});
		if (response.status >= 200 && response.status < 300) return response;
		const text = await response.text().catch(() => "");
		let failure: {code?: unknown, message?: unknown, details?: unknown} | undefined;
		try {failure = JSON.parse(text).error} catch {}
		if (failure && typeof failure.code === "string" && typeof failure.message === "string") throw new VeilwayError(response.status, failure.code, failure.message, Array.isArray(failure.details) ? failure.details : []);
		throw new VeilwayError(response.status, "bad_response", "The node answered " + response.status + " with a body that is not an error document.");
	}

	private async json<T>(method: string, path: string, headers: Record<string, string> = {}, body?: ConfigDocument | UpstreamChoice): Promise<T> {
		const response = await this.send(method, path, body ? {"content-type": "application/json", ...headers} : headers, body && JSON.stringify(body));
		try {return JSON.parse(await response.text()) as T} catch {throw new VeilwayError(response.status, "bad_response", "The node answered with a body that is not JSON.")}
	}

	status(): Promise<Status> {return this.json("GET", "/v1/status")}

	/** The running config with every secret replaced by "<redacted>", and the revision to give `applyConfig`. */
	getConfig(): Promise<RunningConfig> {return this.json("GET", "/v1/config")}

	/** Puts a document in force. `revision` is the one of the config the change was made on. A stale one throws a `stale_revision` error whose details hold the revision that runs. */
	applyConfig(document: ConfigDocument, revision: string): Promise<Applied> {return this.json("PUT", "/v1/config", {"if-match": "\"" + revision.replace(/"/g, "") + "\""}, document)}

	validateConfig(document: ConfigDocument): Promise<Validation> {return this.json("POST", "/v1/config/validate", {}, document)}

	diffConfig(document: ConfigDocument): Promise<Difference> {return this.json("POST", "/v1/config/diff", {}, document)}

	async listUsers(): Promise<User[]> {return (await this.json<{users: User[]}>("GET", "/v1/users")).users}

	getUser(name: string): Promise<User> {return this.json("GET", "/v1/users/" + encodeURIComponent(name))}

	/** Starts the user's quota count over, which lets a user who was out of quota connect again at once. With `totals` the user's `traffic` goes back to zero as well. The answer is the user as `getUser` gives them, and the same call again changes nothing more. */
	resetUsage(name: string, options: {totals?: boolean} = {}): Promise<User> {return this.json("POST", "/v1/users/" + encodeURIComponent(name) + "/usage/reset", {}, {totals: options.totals === true})}

	/** Empties the replay memory of the obfuscated transports and sets its floor and limit to the node's clock plus 60 seconds. Every client is refused for those 60 seconds, and a proof that was accepted with a timestamp above the new floor can be used once more. A node that has run no obfuscated transport throws `replay_absent`. The answer is the replay memory after the reset. */
	resetReplay(): Promise<Replay> {return this.json("POST", "/v1/replay/reset")}

	stats(): Promise<Stats> {return this.json("GET", "/v1/stats")}

	async listSessions(): Promise<Session[]> {return (await this.json<{sessions: Session[]}>("GET", "/v1/sessions")).sessions}

	async listExits(): Promise<Exit[]> {return (await this.json<{exits: Exit[]}>("GET", "/v1/exits")).exits}

	/** Every inbound with its WireGuard public key, the public half of its node transport key, and the rating of each transport. No private key. */
	async listInbounds(): Promise<InboundInfo[]> {return (await this.json<{inbounds: InboundInfo[]}>("GET", "/v1/inbounds")).inbounds}

	/** Every enabled node link with its state and its counters. */
	async listLinks(): Promise<Link[]> {return (await this.json<{links: Link[]}>("GET", "/v1/links")).links}

	/** Every enabled upstream, the subscription of another provider that an exit uses: its state and why, the provider, the profile, transport and exit in use, quota, notices as plain text, the refresh state, a move of the provider's endpoint or new refresh hosts that wait for `confirmUpstream`, and its counters. No key, no secret and no link. */
	async listUpstreams(): Promise<Upstream[]> {return (await this.json<{upstreams: Upstream[]}>("GET", "/v1/upstreams")).upstreams}

	/** Fetches the subscription of another provider from the node with the device the request gives, which takes a place at the provider, and returns what the document holds. The node keeps the document for `expires_in_secs` for the config that names the same link and device, so that the provider is not asked again; `declinePreview` gives the place back. At most four wait. Throws `body_invalid` (422) for a request the node cannot read, `provider_failed` (502) when the provider cannot be asked or its answer fails the checks, and `previews_full` (409). */
	previewUpstream(request: UpstreamPreviewRequest): Promise<UpstreamPreview> {return this.json("POST", "/v1/upstreams/preview", {}, request)}

	/** Says no to a preview: the provider is told to release the place. Throws `preview_not_found` for one that was declined, taken by a config or ran out. */
	declinePreview(id: string): Promise<{id: string}> {return this.json("POST", "/v1/upstreams/preview/" + encodeURIComponent(id) + "/decline")}

	/** Removes an upstream: the provider is told that the device left, for at most ten seconds, and `confirmed` says whether it took the word. The upstream stops and a config that still names it does not start it again: apply a config without it to finish. */
	removeUpstream(tag: string): Promise<UpstreamRemoved> {return this.json("DELETE", "/v1/upstreams/" + encodeURIComponent(tag))}

	/** Confirms the move of the provider's endpoint and the new refresh hosts that `listUpstreams` reports as pending. Without options both are confirmed; with them a field that is left out is false. The answer says what had been waiting. */
	confirmUpstream(tag: string, options: {move?: boolean, hosts?: boolean} = {}): Promise<UpstreamConfirmed> {return this.json("POST", "/v1/upstreams/" + encodeURIComponent(tag) + "/confirm", {}, options)}

	/** Changes what the config chooses on an upstream: `profile`, `failover`, `transport` and `exit`. A field that is left out stays and null is automatic. Only an exit change keeps the running tunnel (`live`). The link, keys, allow, allow_private and via cannot be changed this way. */
	chooseUpstream(tag: string, choice: UpstreamChoice): Promise<UpstreamChosen> {return this.json("PATCH", "/v1/upstreams/" + encodeURIComponent(tag), {}, choice)}

	/** Asks the upstream to connect again now: every wait it was in starts over. */
	retryUpstream(tag: string): Promise<{tag: string}> {return this.json("POST", "/v1/upstreams/" + encodeURIComponent(tag) + "/retry")}

	/** The event stream. It ends when the node closes it or when `signal` aborts, and throws when the node refuses it or sends something that is not an event. Event names this client does not know are skipped. */
	async *events(signal?: AbortSignal): AsyncGenerator<NodeEvent, void, undefined> {
		let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
		try {
			const response = await this.send("GET", "/v1/events", {accept: "text/event-stream"}, undefined, signal);
			if (!response.body) throw new VeilwayError(response.status, "bad_response", "The node answered the event stream without a body.");
			reader = response.body.getReader();
			const decoder = new TextDecoder();
			let pending = "", id: string | undefined, event = "message", data: string[] = [], skipLf = false;
			while (true) {
				const {done, value} = await reader.read();
				if (done) return;
				pending += decoder.decode(value, {stream: true});
				if (skipLf && pending.startsWith("\n")) pending = pending.slice(1);
				skipLf = false;
				let cut: RegExpExecArray | null;
				while ((cut = /\r\n|\n|\r/.exec(pending))) {
					const line = pending.slice(0, cut.index);
					// A CR at the very end may be the first half of a CRLF whose LF has not arrived yet.
					if (cut[0] === "\r" && cut.index + 1 === pending.length) skipLf = true;
					pending = pending.slice(cut.index + cut[0].length);
					if (line === "") {
						const name = event, text = data.join("\n"), last = name === "lagged" ? undefined : id;
						event = "message"; data = [];
						if (!EVENTS.has(name)) continue;
						let parsed: unknown;
						try {parsed = JSON.parse(text)} catch {throw new VeilwayError(response.status, "bad_event", "An event of the stream holds no JSON.")}
						yield {id: last, event: name, data: parsed} as NodeEvent;
						continue;
					}
					if (line.startsWith(":")) continue;
					const colon = line.indexOf(":");
					const field = colon < 0 ? line : line.slice(0, colon);
					let value = colon < 0 ? "" : line.slice(colon + 1);
					if (value.startsWith(" ")) value = value.slice(1);
					if (field === "id" && !value.includes("\0")) id = value;
					else if (field === "event") event = value;
					else if (field === "data") data.push(value);
				}
				if (pending.length > MAX_LINE) throw new VeilwayError(response.status, "bad_event", "A line of the event stream is longer than " + MAX_LINE + " bytes.");
			}
		} catch (e) {
			if (signal?.aborted) return;
			throw e;
		} finally {
			await reader?.cancel().catch(() => {});
		}
	}
}
