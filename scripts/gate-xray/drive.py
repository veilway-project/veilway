"""The panel's admin side as the web app calls it: HTTP and JSON through the web server in front, no browser. Run by scripts/gate-xray.sh in a container on the gate network, never by hand.

drive.py setup      first-run setup with the token the install script printed, TOTP computed here
drive.py config     login, reauth, settings and the node's config with its inbound
drive.py xray       an xray inbound, a user with a device, and the user's link
drive.py usage      the user's usage as the panel has it
drive.py limit      QUOTA bytes and ENABLED 0 or 1 for the user, pushed to the node

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
	_, data = panel.call("POST", "/setup", {"token": E["SETUP_TOKEN"], "username": state["username"], "password": state["password"]})
	state["totp_secret"] = data["totp_secret"]
	save(state)
	check(len(state["totp_secret"]) >= 16 and data["otpauth"].startswith("otpauth://"), "setup made the admin and showed the TOTP secret once")
	status, _ = panel.call("POST", "/setup", {"token": E["SETUP_TOKEN"], "username": "second", "password": "second-password-12"}, expect=None)
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
	settings.update(provider_name="Gate Provider", endpoint_url="https://%s/sub" % HOST, endpoint_pins=[E["ENDPOINT_PIN"]], node_host=E["NODE_IP"], pool_v4="10.66.0.0/16", default_device_limit=3)
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


def xray():
	panel, state = Panel(), load()
	panel.login(state)
	panel.reauth(state)
	_, node = panel.call("GET", "/xray")
	check(node["installed"] is True and node["inbounds"] == [], "the panel sees the add-on installed and no xray inbound yet", json.dumps(node)[:200])
	status, _ = panel.call("POST", "/xray/inbounds", {"tag": "web", "protocol": "vless", "port": 8444, "cert": "/gate/node.crt", "key": "/gate/node.key", "host": E["PANEL_HOST"]}, expect=None)
	check(status == 200, "an xray inbound with the node's certificate is made", "answered %d" % status)
	_, created = panel.call("POST", "/users", {"name": "alice", "quota_bytes": 5 * 1024 ** 3, "quota_period": "monthly"})
	uid = created["user"]["id"]
	_, made = panel.call("POST", "/users/%d/devices" % uid, {"name": "panel-keyed"})
	check(made["node"]["synced"] is True, "alice has a device, so the node knows her", json.dumps(made["node"]))
	_, node = panel.call("GET", "/xray")
	check([(i["tag"], i["protocol"], i["port"], i["security"], i["clients"]) for i in node["inbounds"]] == [("web", "vless", 8444, "tls", 1)], "the inbound lists alice as its one client", json.dumps(node["inbounds"]))
	_, shown = panel.call("GET", "/users/%d/xray" % uid)
	links = shown["links"]
	check(len(links) == 1 and links[0]["link"].startswith("vless://") and "<svg" in links[0]["qr_svg"], "alice's xray link comes with a QR code")
	_, config = panel.call("GET", "/config")
	secrets = json.dumps(config["document"].get("xray", {}))
	check(links[0]["link"].split("//")[1].split("@")[0] not in secrets, "the node's config shown by the panel hides the client's id")
	state.update(xray_link=links[0]["link"], user_id=uid)
	save(state)


def usage():
	panel, state = Panel(), load()
	panel.login(state)
	deadline, seen, used = time.time() + 60, None, 0
	while time.time() < deadline:
		_, users = panel.call("GET", "/users")
		seen = next((u for u in users["users"] if u["name"] == "alice"), None)
		node = (seen or {}).get("node") or {}
		used = (node.get("usage") or {}).get("used_bytes", 0) or ((node.get("traffic") or {}).get("up_bytes", 0) + (node.get("traffic") or {}).get("down_bytes", 0))
		if used > 0:
			break
		time.sleep(3)
	check(used > 0, "the panel shows alice's usage from the node, counted at the xray hop", "%d bytes" % used)
	_, by_user = panel.call("GET", "/stats/usage?kind=user&period=day")
	check(json.dumps(by_user).count("alice") > 0, "the usage per day lists alice", json.dumps(by_user)[:200])


def limit():
	panel, state = Panel(), load()
	panel.login(state)
	panel.reauth(state)
	_, user = panel.call("GET", "/users/%d" % state["user_id"])
	body = {"enabled": E.get("ENABLED", "1") == "1", "quota_bytes": int(E["QUOTA"]), "quota_period": "monthly"}
	_, changed = panel.call("PATCH", "/users/%d" % state["user_id"], body)
	status, _ = panel.call("POST", "/node/sync", {}, expect=None)
	check(status == 200, "the change is pushed to the node", "quota %s, enabled %s" % (body["quota_bytes"], body["enabled"]))


{"setup": setup, "config": config, "xray": xray, "usage": usage, "limit": limit}[sys.argv[1]]()
print("%d failed" % len(FAILS) if FAILS else "all passed")
sys.exit(1 if FAILS else 0)
