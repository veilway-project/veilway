"""The panel's admin side as the web app calls it: HTTP and JSON through the web server in front, no browser. Run by scripts/gate-alpha.sh in a container on the gate network, never by hand.

drive.py setup      first-run setup with the token the install script printed, TOTP computed here
drive.py config     login, reauth, settings and the node's config with its inbound
drive.py publish    the profile with the node's own pins, a user and its subscription link
drive.py usage      login and the user's usage and the live rates as the panel has them

Prints PASS or FAIL per check and exits 1 if any failed. What it learns goes to $STATE/state.json."""
import base64, hashlib, hmac, http.client, json, os, ssl, struct, sys, time, urllib.parse

E = os.environ
STATE = E.get("STATE", "/state") + "/state.json"
HOST, PREFIX = E["PANEL_HOST"], E["PANEL_PREFIX"]
FAILS = []


def check(ok, name, detail=""):
	print(("PASS  " if ok else "FAIL  ") + name + (": " + detail if detail else ""), flush=True)
	if not ok:
		FAILS.append(name)


def load():
	try:
		return json.load(open(STATE))
	except FileNotFoundError:
		return {}


def save(state):
	json.dump(state, open(STATE, "w"), indent=1)


def totp(secret, step):
	tag = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
	at = tag[19] & 15
	return "%06d" % ((struct.unpack(">I", tag[at:at + 4])[0] & 0x7FFFFFFF) % 1000000)


def next_code(state):
	"""A code the panel has not seen: the step has to be above the last one it took, and one step ahead of the clock is accepted."""
	secret = base64.b32decode(state["totp_secret"] + "=" * (-len(state["totp_secret"]) % 8))
	while True:
		step = max(int(time.time()) // 30, state.get("last_step", 0) + 1)
		if step <= int(time.time()) // 30 + 1:
			state["last_step"] = step
			save(state)
			return totp(secret, step)
		time.sleep(2)


class Panel:
	def __init__(self):
		self.cookie, self.csrf = None, None
		self.context = ssl.create_default_context(cafile=E["CA"])

	def call(self, method, path, body=None, expect=200):
		connection = http.client.HTTPSConnection(HOST, context=self.context, timeout=60)
		headers = {"Host": HOST, "Content-Type": "application/json", "Origin": "https://" + HOST}
		if self.cookie:
			headers["Cookie"] = "vw_session=" + self.cookie
		if self.csrf and method != "GET":
			headers["X-CSRF-Token"] = self.csrf
		connection.request(method, PREFIX + "/api" + path, json.dumps(body) if body is not None else None, headers)
		response = connection.getresponse()
		raw = response.read()
		for name, value in response.getheaders():
			if name.lower() == "set-cookie" and value.startswith("vw_session="):
				self.cookie = value.split(";")[0].split("=", 1)[1]
		try:
			data = json.loads(raw)
		except ValueError:
			data = {"raw": raw.decode(errors="replace")[:300]}
		if expect and response.status != expect:
			raise SystemExit("FAIL  %s %s answered %d, wanted %d: %s" % (method, path, response.status, expect, json.dumps(data)[:600]))
		return response.status, data

	def login(self, state):
		_, data = self.call("POST", "/login", {"username": state["username"], "password": state["password"], "totp": next_code(state)})
		self.csrf = data["csrf"]
		return data

	def reauth(self, state):
		self.call("POST", "/session/reauth", {"password": state["password"], "totp": next_code(state)})


def setup():
	panel, state = Panel(), load()
	_, data = panel.call("GET", "/status")
	check("setup" in json.dumps(data).lower() and "true" in json.dumps(data).lower(), "the panel asks for first-run setup", json.dumps(data))
	state.update(username="gate-admin", password="gate-admin-password-1")
	_, data = panel.call("POST", "/setup", {"accepted_terms": True, "token": E["SETUP_TOKEN"], "username": state["username"], "password": state["password"]})
	state["totp_secret"] = data["totp_secret"]
	save(state)
	check(len(state["totp_secret"]) >= 16 and data["otpauth"].startswith("otpauth://"), "setup made the admin and showed the TOTP secret once")
	status, _ = panel.call("POST", "/setup", {"accepted_terms": True, "token": E["SETUP_TOKEN"], "username": "second", "password": "second-password-12"}, expect=None)
	check(status in (403, 409), "the setup token works once", "second try answered %d" % status)
	status, _ = panel.call("GET", "/users", expect=None)
	check(status == 401, "an API call without a session is refused", "answered %d" % status)
	logged = panel.login(state)
	check(logged["username"] == state["username"] and len(logged["csrf"]) >= 16, "login with the password and a computed TOTP code")
	status, _ = panel.call("POST", "/logout", {}, expect=None)
	check(status == 200, "logout with the CSRF token")
	panel.cookie = None
	status, _ = panel.call("GET", "/session", expect=None)
	check(status == 401, "the session is gone after logout", "answered %d" % status)


def config():
	panel, state = Panel(), load()
	panel.login(state)
	kept, panel.csrf = panel.csrf, None
	status, _ = panel.call("POST", "/users", {"name": "x"}, expect=None)
	check(status in (401, 403), "a change without the CSRF token is refused", "answered %d" % status)
	panel.csrf = kept
	panel.reauth(state)
	_, settings = panel.call("GET", "/settings")
	settings.update(provider_name="Gate Provider", endpoints=[{"name": "main", "url": "https://%s/sub/main" % HOST, "pins": [E["ENDPOINT_PIN"]]}], default_endpoint="main", node_host=E["NODE_IP"], pool_v4="10.66.0.0/16", default_device_limit=3)
	panel.call("PUT", "/settings", settings)
	_, node = panel.call("GET", "/node")
	check(node.get("reachable", node.get("connected", True)) is not False, "the panel reaches the node's control socket", json.dumps(node)[:200])
	_, config = panel.call("GET", "/config")
	document = config["document"]
	document["dns"] = {"servers": [E["DNS_IP"] + ":53"]}
	document["public_addresses"] = [E["NODE_IP"]]
	check(any(rule["tag"] == "no-private" for rule in document["routing"]["rules"]), "the config an install starts with refuses private networks and traffic between users")
	document["inbounds"] = [{
		"tag": "home", "type": "veilway", "private_key": E["INBOUND_PRIVATE"], "address": ["10.66.0.1/16"],
		"transport_keys": [E["TRANSPORT_PRIVATE"]], "upgrade_cookie": "sid",
		"transports": [
			{"type": "udp-obfs", "listen": "0.0.0.0:51821"},
			{"type": "tls", "listen": "0.0.0.0:8443", "path": "/assets/app-3f9c2e71.js", "tls": {"self_signed": True, "name": "node.gate.test"}, "decoy": {"origin": "http://127.0.0.1:8080"}},
		],
	}]
	status, bad = panel.call("PUT", "/config", {"revision": "0" * 64, "document": document}, expect=None)
	check(status in (409, 422, 428), "a config change on a wrong revision is refused", "answered %d" % status)
	_, applied = panel.call("PUT", "/config", {"revision": config["revision"], "document": document})
	check(applied.get("saved") is True, "the node put the config in force and wrote it to its file", json.dumps({k: applied.get(k) for k in ("generation", "saved", "save_error")}))
	_, config = panel.call("GET", "/config")
	check([i["tag"] for i in config["document"]["inbounds"]] == ["home"], "the panel reads back the inbound it made")
	check(not any(E["INBOUND_PRIVATE"] in json.dumps(v) for v in config["document"].values()), "the node's answer hides the inbound's private key")


def publish():
	panel, state = Panel(), load()
	panel.login(state)
	panel.reauth(state)
	state["tls_pin"] = E["TLS_PIN"]
	transports = [
		{"type": "udp-obfs", "endpoints": ["%s:51821" % E["NODE_IP"]]},
		{"type": "tls", "path": "/assets/app-3f9c2e71.js", "candidates": [{"address": "%s:8443" % E["NODE_IP"], "sni": HOST, "host": HOST, "pins": [state["tls_pin"]], "self_signed": True}]},
	]
	panel.call("PUT", "/profiles/overrides/home", {"set": {"inbound_public_key": E["INBOUND_PUBLIC"], "transport_public_key": E["TRANSPORT_PUBLIC"], "transports": transports, "name": "Gate, both transports"}})
	_, derived = panel.call("GET", "/profiles/derived")
	check(all(not t["missing"] for t in derived["templates"]), "the derived profile lacks nothing", json.dumps([t["missing"] for t in derived["templates"]]))
	_, published = panel.call("POST", "/profiles/publish", {})
	check(len(published["profiles"]) == 1, "the profile is published to the subscription")
	_, created = panel.call("POST", "/users", {"name": "alice", "quota_bytes": 5 * 1024 ** 3, "quota_period": "monthly"})
	link = (created.get("link") or {}).get("veilway", "")
	check(link.startswith("veilway://sub/" + HOST + "/sub/main#v1."), "a user was made with a subscription link", created.get("link_error") or "")
	check("<svg" in created["link"]["qr_svg"], "the link comes with a QR code")
	_, shown = panel.call("POST", "/users/%d/subscription/show" % created["user"]["id"], {})
	check(shown["veilway"] == link, "showing the link again gives the same link")
	state.update(link=link, user_id=created["user"]["id"])
	save(state)
	status, _ = panel.call("POST", "/node/sync", {}, expect=None)
	check(status == 200, "the users are pushed to the node")


def usage():
	panel, state = Panel(), load()
	panel.login(state)
	deadline, seen = time.time() + 60, None
	while time.time() < deadline:
		_, users = panel.call("GET", "/users")
		seen = next((u for u in users["users"] if u["name"] == "alice"), None)
		if seen and seen.get("node") and json.dumps(seen["node"]).count("bytes") and (seen["node"].get("usage") or seen["node"].get("traffic")):
			break
		time.sleep(5)
	check(seen is not None and seen.get("devices", 0) >= 1, "alice has an enrolled device", json.dumps(seen)[:300])
	node = (seen or {}).get("node") or {}
	used = (node.get("usage") or {}).get("used_bytes", 0) or ((node.get("traffic") or {}).get("up_bytes", 0) + (node.get("traffic") or {}).get("down_bytes", 0))
	check(used > 0, "the panel shows alice's usage from the node", "%d bytes" % used)
	for _ in range(12):
		_, now = panel.call("GET", "/stats/now")
		if "alice" in now.get("online_users", []):
			break
		time.sleep(5)
	check(now.get("reachable") is True and "alice" in now.get("online_users", []), "live stats: the node is reachable and alice is online", json.dumps({k: now.get(k) for k in ("reachable", "online_users", "sessions")}))
	check(json.dumps(now.get("rates", {})).count("alice") > 0, "live stats have a rate for alice")
	_, by_user = panel.call("GET", "/stats/usage?kind=user&period=day")
	check(json.dumps(by_user).count("alice") > 0, "the usage per day lists alice", json.dumps(by_user)[:200])


{"setup": setup, "config": config, "publish": publish, "usage": usage}[sys.argv[1]]()
print("%d failed" % len(FAILS) if FAILS else "all passed")
sys.exit(1 if FAILS else 0)
