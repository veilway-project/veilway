#!/usr/bin/env bash
# The alpha gate (PLAN.md, Phase 4 and 5): a fresh server goes from install to a working subscription with only scripts/veilway.sh and the panel, and a client imports the link, connects, and shows live stats and the provider's name. Everything runs in Docker containers on this machine.
#   bash scripts/gate-alpha.sh                run the whole gate
#   SKIP_BUILD=1 bash scripts/gate-alpha.sh  reuse the binaries of an earlier run (Docker volume veilway-alpha-rel)
#   KEEP=1 bash scripts/gate-alpha.sh        leave the containers running afterwards (names vwalpha-*)
#   WORK=/some/dir OUT=/some/dir/out         where keys, logs and screenshots go (default $TMPDIR/veilway-gate-alpha)
# Needs Docker with 4 GB, the sibling checkouts ../veilway-panel and ../veilway-ui (VEILWAY_PANEL_SRC and VEILWAY_UI_SRC name other places), and internet for the images and for apt inside the server container. Exit status 0 only when every check passed.
# What it does:
#   1. builds veilway (musl, the host's own architecture) and veilway-panel with its web app, one build at a time with --cpus 3 --memory 2500m, signs both with throwaway minisign keys made for this run (never the release key) and serves them from an nginx container laid out like GitHub releases
#   2. starts a "server" container with systemd as PID 1 and runs scripts/veilway.sh install both against that release server through its VEILWAY_RELEASE_BASE and key overrides, then puts nginx in front of the panel with the snippet the script prints
#   3. drives the panel through its HTTP API as the web app does (setup token, TOTP computed here, login, CSRF, re-authentication): an inbound with udp-obfs and tls, public addresses, a user, the subscription link
#   4. a "client" container on another network runs `veilway connect <link>`: traffic through the node, DNS through the tunnel, status, the kill switch, a fall back to tls when UDP is cut, then the panel's usage and live stats for the user
#   5. screenshots of the panel (login, users, traffic; English and Persian; dark) in $OUT, by Playwright
# Networks: client (A) - router - server, responder and release server (B). The node is not on the client's network on purpose: a node inside the device's own networks is not dialled.
# shellcheck disable=SC2001,SC2015,SC2086,SC2319
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/scripts/gate-alpha"
PANEL_SRC="${VEILWAY_PANEL_SRC:-$ROOT/../veilway-panel}"
UI_SRC="${VEILWAY_UI_SRC:-$ROOT/../veilway-ui}"
WORK="${WORK:-${TMPDIR:-/tmp}/veilway-gate-alpha}"
OUT="${OUT:-$WORK/out}"
P=vwalpha
# Public-looking addresses on purpose: a client refuses private ones for the subscription server and for a node, and the networks are Docker bridges that go nowhere else.
A=11.95.5; B=11.96.5
CLIENT=$A.40; RA=$A.2; RB=$B.2; SERVER=$B.10; RESP=$B.20; REL=$B.30
HOST=node.gate.test; RELHOST=releases.gate.test
TAG=v0.0.1-gate
REL_VOL=veilway-alpha-rel; TGT_VOL=veilway-alpha-target
LIMITS="--cpus 1 --memory 512m"
FAILS=0
cleanup() { docker rm -f $P-server $P-client $P-router $P-resp $P-rel >/dev/null 2>&1; docker network rm $P-a $P-b >/dev/null 2>&1; return 0; }
die() { echo "SETUP FAILED: $1"; exit 2; }
check() { if [ "$1" = 0 ]; then echo "PASS  $2${3:+: $3}"; else echo "FAIL  $2${3:+: $3}"; FAILS=$((FAILS + 1)); fi; }
wait_for() { local n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; n=$((n - 1)); done; return 1; }
srv() { docker exec $P-server "$@"; }
cli() { docker exec $P-client "$@"; }
node_api() { srv curl -s --unix-socket /run/veilway/control.sock "http://node$1"; }
connected() { cli veilway status 2>/dev/null | grep -q "^State: Connected"; }
down() { cli veilway status 2>/dev/null | grep -q "^State: .*\(Reconnecting\|Connecting\|lost\)"; }
flows() { cli curl -sS --max-time 5 "http://$RESP:8000/" 2>/dev/null | grep -q "src=$SERVER\$"; }
tunnelled() { cli curl -sS --max-time 8 "http://$RESP:8000/" 2>&1; }
build_wait() { while docker ps --format '{{.Image}} {{.Names}}' | grep -E '^(rust|node)' | grep -v "$P" | grep -q .; do echo "another build runs, waiting"; sleep 20; done; }
drive() { local cmd=$1; shift; docker run --rm --network $P-b --add-host $HOST:$SERVER -v "$WORK/state":/state -v "$WORK/tls/ca.pem":/ca.pem:ro -v "$HERE/drive.py":/drive.py:ro -e STATE=/state -e CA=/ca.pem -e PANEL_HOST=$HOST -e PANEL_PREFIX="$PREFIX" -e NODE_IP=$SERVER -e DNS_IP=$RESP -e ENDPOINT_PIN="$ENDPOINT_PIN" "$@" $P-tools python3 -I /drive.py "$cmd"; }
count_drive() { local out rc lines; out="$(drive "$@" 2>&1)"; rc=$?; echo "$out"; lines=$(grep -c '^FAIL' <<<"$out"); [ "$lines" = 0 ] && [ "$rc" != 0 ] && lines=1; FAILS=$((FAILS + lines)); }
[ -d "$PANEL_SRC/server" ] && [ -d "$UI_SRC/packages" ] || die "need the panel checkout ($PANEL_SRC) and the design system ($UI_SRC)"
PANEL_SRC="$(cd "$PANEL_SRC" && pwd)"; UI_SRC="$(cd "$UI_SRC" && pwd)"
rm -rf "$WORK/tls" "$WORK/keys" "$WORK/site" "$WORK/state"; mkdir -p "$WORK/tls" "$WORK/keys" "$WORK/site" "$WORK/state" "$OUT"
cleanup
trap '[ -n "${KEEP:-}" ] || cleanup' EXIT
ARCH="$(docker run --rm alpine:3.22 uname -m)"; TARGET="$ARCH-unknown-linux-musl"
echo "== alpha gate: $TARGET, work dir $WORK, screenshots in $OUT"
docker volume create $REL_VOL >/dev/null; docker volume create $TGT_VOL >/dev/null; docker volume create veilway-alpha-zig >/dev/null
# 1. Builds. The node is built the way the release workflow does it, with cargo zigbuild for the musl target (BoringSSL in the client needs libclang in its build script, which a musl host cannot load). The panel has no such dependency and builds natively on Alpine.
if [ -z "${SKIP_BUILD:-}" ] || ! docker run --rm -v $REL_VOL:/rel:ro alpine:3.22 sh -c "test -x /rel/veilway-bin -a -x /rel/veilway-panel-bin"; then
	build_wait
	docker run --rm --cpus 3 --memory 2500m -v "$ROOT":/w/veilway:ro -v veilway-cargo:/usr/local/cargo/registry -v $TGT_VOL:/t -v $REL_VOL:/rel -v veilway-alpha-zig:/zb -e CARGO_TARGET_DIR=/t/zig -e CARGO_INSTALL_ROOT=/zb rust:1 sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq python3-pip cmake clang libclang-dev perl >/dev/null && pip install -q --break-system-packages ziglang && rustup target add '$TARGET' >/dev/null 2>&1 && { test -x /zb/bin/cargo-zigbuild || cargo install -q --locked cargo-zigbuild; } && cd /w/veilway && /zb/bin/cargo-zigbuild zigbuild --release --locked --target '$TARGET' -p veilway --bin veilway && cp /t/zig/'$TARGET'/release/veilway /rel/veilway-bin' || die "building veilway failed"
	build_wait
	docker run --rm --cpus 3 --memory 2500m -v "$PANEL_SRC":/src/veilway-panel:ro -v "$UI_SRC":/src/veilway-ui:ro -v $REL_VOL:/rel node:22-alpine sh -c 'mkdir -p /b/veilway-panel/web /b/veilway-ui && cd /src/veilway-ui && tar cf - --exclude=node_modules --exclude=.git . | tar xf - -C /b/veilway-ui && cd /src/veilway-panel/web && tar cf - --exclude=node_modules --exclude=dist . | tar xf - -C /b/veilway-panel/web && for d in i18n ui; do (cd /b/veilway-ui/packages/$d && npm ci --no-audit --no-fund) || exit 1; done && cd /b/veilway-panel/web && npm ci --no-audit --no-fund && npm run build && rm -rf /rel/web-dist && cp -r dist /rel/web-dist' || die "building the panel's web app failed"
	build_wait
	docker run --rm --cpus 3 --memory 2500m -v "$PANEL_SRC":/src/veilway-panel:ro -v "$ROOT":/b/veilway:ro -v veilway-cargo:/usr/local/cargo/registry -v $TGT_VOL:/t -v $REL_VOL:/rel -e CARGO_TARGET_DIR=/t/panel rust:1-alpine sh -c 'apk add -q --no-cache build-base perl && mkdir -p /b/veilway-panel/web && cp -a /src/veilway-panel/server /b/veilway-panel/server && cp -a /rel/web-dist /b/veilway-panel/web/dist && cd /b/veilway-panel/server && cargo build --release --locked --bin veilway-panel && cp /t/panel/release/veilway-panel /rel/veilway-panel-bin' || die "building veilway-panel failed"
fi
[ -n "${BUILD_ONLY:-}" ] && exit 0
# One image with the tools of a client, a router and the signing, and one that is a server with systemd. The server has neither curl nor minisign, which the install script has to get itself.
docker build -q -t $P-tools - <<'EOF' >/dev/null || die "tools image"
FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 nftables curl tcpdump procps python3 openssl ca-certificates minisign bind9-dnsutils >/dev/null && rm -rf /var/lib/apt/lists/*
EOF
docker build -q -t $P-server-img - <<'EOF' >/dev/null || die "server image"
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus nginx-light iproute2 procps ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
# 2. Keys, certificates and the release tree of this run. The CA signs the release server and the panel's web server; the panel's endpoint is pinned in the link as well.
docker run --rm -v "$WORK":/w -v $REL_VOL:/rel:ro -v "$ROOT/config.example.json":/example.json:ro -e TAG=$TAG -e TARGET="$TARGET" -e HOST=$HOST -e RELHOST=$RELHOST -e SERVER=$SERVER -e REL=$REL $P-tools sh -c '
set -e
cd /w/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/CN=veilway gate test CA" >/dev/null 2>&1
for pair in "node $HOST $SERVER" "rel $RELHOST $REL"; do
	set -- $pair
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $1.key -out $1.csr -subj "/CN=$2" >/dev/null 2>&1
	printf "subjectAltName=DNS:$2,IP:$3\nbasicConstraints=CA:FALSE\n" > $1.ext
	openssl x509 -req -in $1.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out $1.crt -days 2 -extfile $1.ext >/dev/null 2>&1
done
chmod 644 *.key
openssl x509 -in node.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 > node.pin
cd /w/keys
minisign -G -W -f -p node.pub -s node.key >/dev/null
minisign -G -W -f -p panel.pub -s panel.key >/dev/null
D=/w/site/veilway-project
mkdir -p $D/veilway/releases/download/$TAG $D/veilway-panel/releases/download/$TAG /w/site/raw/veilway-project/veilway/$TAG
cp /rel/veilway-bin $D/veilway/releases/download/$TAG/veilway-$TARGET
cp /rel/veilway-panel-bin $D/veilway-panel/releases/download/$TAG/veilway-panel-$TARGET
cp /example.json /w/site/raw/veilway-project/veilway/$TAG/config.example.json
minisign -S -s node.key -m $D/veilway/releases/download/$TAG/veilway-$TARGET -t "veilway $TAG veilway-$TARGET" </dev/null >/dev/null
minisign -S -s panel.key -m $D/veilway-panel/releases/download/$TAG/veilway-panel-$TARGET -t "veilway-panel $TAG veilway-panel-$TARGET" </dev/null >/dev/null
' || die "keys and release tree"
ENDPOINT_PIN="$(cat "$WORK/tls/node.pin")"
NODE_PUBKEY="$(sed -n 2p "$WORK/keys/node.pub")"; PANEL_PUBKEY="$(sed -n 2p "$WORK/keys/panel.pub")"
cat >"$WORK/rel.conf" <<EOF
server {
	listen 443 ssl;
	server_name $RELHOST;
	ssl_certificate /tls/rel.crt;
	ssl_certificate_key /tls/rel.key;
	root /srv;
	location ~ ^/(.+)/releases/latest\$ { return 302 /\$1/releases/tag/$TAG; }
	location ~ /releases/tag/ { return 200 "release page\n"; }
}
EOF
docker network create --subnet $A.0/24 $P-a >/dev/null && docker network create --subnet $B.0/24 $P-b >/dev/null || die "networks $A.0/24 and $B.0/24"
docker run -d --name $P-rel --network $P-b --ip $REL --cpus 0.5 --memory 64m -v "$WORK/site":/srv:ro -v "$WORK/tls":/tls:ro -v "$WORK/rel.conf":/etc/nginx/conf.d/default.conf:ro nginx:alpine >/dev/null || die "release server"
docker run -d --name $P-router --network $P-a --ip $RA $LIMITS --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 $P-tools sleep infinity >/dev/null && docker network connect --ip $RB $P-b $P-router || die "router"
docker run -d --name $P-resp --network $P-b --ip $RESP $LIMITS --cap-add NET_ADMIN -v "$HERE/resp.py":/resp.py:ro $P-tools sh -c "ip route add $A.0/24 via $RB; python3 -u /resp.py $RESP >/resp.log 2>&1" >/dev/null || die "responder"
docker run -d --name $P-server --network $P-b --ip $SERVER --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp --cpus 1 --memory 768m --add-host $RELHOST:$REL --add-host $HOST:$SERVER -v "$WORK/tls":/gate:ro -v "$ROOT/scripts/veilway.sh":/veilway.sh:ro $P-server-img >/dev/null || die "server container"
wait_for 60 srv sh -c 'systemctl is-system-running 2>/dev/null | grep -q -E "running|degraded"' || die "systemd did not come up in the server container"
srv ip route add $A.0/24 via $RB
srv sh -c 'cp /gate/ca.pem /usr/local/share/ca-certificates/gate-ca.crt && update-ca-certificates >/dev/null 2>&1' || die "trusting the test CA in the server"
echo "== 1. the install script, node and panel, against the local release server"
srv env VEILWAY_TESTING=1 VEILWAY_RELEASE_BASE=https://$RELHOST VEILWAY_RAW_BASE=https://$RELHOST/raw VEILWAY_NODE_PUBKEY="$NODE_PUBKEY" VEILWAY_PANEL_PUBKEY="$PANEL_PUBKEY" bash /veilway.sh install both --yes 2>&1 | tee "$WORK/install.log" | sed 's/^/    /'
[ "${PIPESTATUS[0]}" = 0 ]; check $? "veilway.sh install both finished" "log in $WORK/install.log"
srv systemctl is-active veilway.service veilway-panel.service >/dev/null; check $? "the node and the panel services run"
srv test -S /run/veilway/control.sock; check $? "the node's control socket exists"
srv sh -c 'curl -sS --max-time 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:8480/ | grep -q 404'; check $? "the panel answers on loopback and gives a stranger its 404"
TOKEN="$(sed -n 's/.*Setup token (one time): \([^ ]*\).*/\1/p' "$WORK/install.log" | tail -n 1)"
[ -n "$TOKEN" ]; check $? "the install output prints the one-time setup token"
PREFIX="$(srv sed -n 's/.*"prefix": *"\([^"]*\)".*/\1/p' /etc/veilway/panel.json)"
# The nginx in front is made of the snippet the script printed, whatever its box looks like.
SNIPPET="$(sed -E -n '/location ~/,/proxy_set_header X-Forwarded-For/{s/^ *[|] +(nginx: +)?//; s/ +[|]$//; p;}' "$WORK/install.log")"
[ -n "$SNIPPET" ]; check $? "the install output prints an nginx snippet"
{
	echo "server { listen 443 ssl; server_name $HOST; ssl_certificate /gate/node.crt; ssl_certificate_key /gate/node.key;"
	echo "$SNIPPET"
	echo "}"
	echo 'server { listen 127.0.0.1:8080; location / { return 200 "a plain site"; } }'
} >"$WORK/nginx-gate.conf"
docker cp "$WORK/nginx-gate.conf" $P-server:/etc/nginx/conf.d/gate.conf
srv systemctl restart nginx; check $? "nginx started with the printed snippet"
srv curl -sS --max-time 5 -o /dev/null -w '%{http_code}' https://$HOST$PREFIX/api/status | grep -q 200; check $? "the panel answers through nginx over TLS"
# 3. The panel's side.
echo "== 2. the panel, driven through its HTTP API"
read -r INBOUND_PRIVATE INBOUND_PUBLIC < <(srv veilway genkey | awk '{printf "%s ", $2}')
read -r TRANSPORT_PRIVATE TRANSPORT_PUBLIC < <(srv veilway genkey --transport | awk '{printf "%s ", $2}')
count_drive setup -e SETUP_TOKEN="$TOKEN"
count_drive config -e INBOUND_PRIVATE="$INBOUND_PRIVATE" -e TRANSPORT_PRIVATE="$TRANSPORT_PRIVATE" -e INBOUND_PUBLIC="$INBOUND_PUBLIC" -e TRANSPORT_PUBLIC="$TRANSPORT_PUBLIC"
TLS_PIN="$(node_api /v1/status | grep -o '"pin":"[^"]*"' | head -n 1 | cut -d'"' -f4)"
[ -n "$TLS_PIN" ]; check $? "the node reports the pin of the certificate it made for tls" "$TLS_PIN"
count_drive publish -e INBOUND_PUBLIC="$INBOUND_PUBLIC" -e TRANSPORT_PUBLIC="$TRANSPORT_PUBLIC" -e TLS_PIN="$TLS_PIN"
LINK="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["link"])' "$WORK/state/state.json")"
# 4. The client. Nothing below means anything when the server side failed.
[ "$FAILS" = 0 ] || { echo "== stopping: $FAILS check(s) failed before the client"; exit 1; }
echo "== 3. the client"
docker run -d --name $P-client --network $P-a --ip $CLIENT $LIMITS --cap-add NET_ADMIN --device /dev/net/tun --add-host $HOST:$SERVER -v $REL_VOL:/rel:ro $P-tools sleep infinity >/dev/null || die "client container"
cli ln -sf /rel/veilway-bin /usr/local/bin/veilway
cli ip route replace default via $RA || die "client route"
docker exec $P-router sh -c "nft add table inet cut; nft add chain inet cut f '{ type filter hook forward priority 0; }'" || die "router rules"
cli sh -c "tcpdump -i eth0 -n -U -w /eth0-dns.pcap 'port 53' >/dev/null 2>&1 &"
docker exec -d $P-client sh -c "yes yes | veilway connect '$LINK' >/connect.log 2>&1; echo \$? >/connect.exit"
wait_for 180 connected; check $? "veilway connect imported the link and connected" "$(cli sh -c 'grep -E "Provider|Fingerprint|Connection|Kept" /connect.log | tr "\n" " "')"
cli sh -c 'grep -q "Provider (its own claim): Gate Provider" /connect.log'; check $? "the import showed the provider's name"
[ "$FAILS" = 0 ] || { echo "== stopping: the client did not connect"; cli tail -n 30 /connect.log; exit 1; }
OUTPUT="$(tunnelled)"
grep -q "src=$SERVER\$" <<<"$OUTPUT"; check $? "a web server behind the node sees the node's address, not the client's" "$OUTPUT"
cli sh -c "dig +short +time=5 +tries=1 app.gate.test | grep -q '^$RESP\$'"; check $? "a name is resolved through the tunnel" "app.gate.test is $RESP"
docker exec $P-resp grep -q "^dns app.gate.test type=1 from=$SERVER\$" /resp.log; check $? "the DNS server was asked by the node, not by the client"
cli sh -c "sleep 1; kill \$(pidof tcpdump); sleep 1; test \"\$(tcpdump -nr /eth0-dns.pcap 2>/dev/null | wc -l)\" = 0"; check $? "no DNS packet left the client's own interface"
STATUS="$(cli veilway status)"; echo "$STATUS" | sed 's/^/    /'
grep -q "^State: Connected" <<<"$STATUS"; check $? "status says connected"
grep -q "^Traffic: [1-9]" <<<"$STATUS"; check $? "status shows live traffic counters"
grep -q "^Usage: .* of 5.0 GB used\|^Usage: " <<<"$STATUS"; check $? "status shows the usage the panel set a quota for"
grep -q "^Kill switch: on" <<<"$STATUS"; check $? "status says the kill switch is on"
SESSIONS="$(node_api /v1/sessions)"; echo "    node sessions: $SESSIONS" | cut -c1-400
grep -q '"user":"alice"' <<<"$SESSIONS"; check $? "the node has a session for alice"
# The kill switch: cut the path to the node. The client must reconnect, and nothing may reach the responder meanwhile.
docker exec $P-router nft add rule inet cut f ip daddr $SERVER drop
wait_for 90 down; check $? "status notices that the tunnel is cut"
! cli curl -sS --max-time 6 "http://$RESP:8000/" >/dev/null 2>&1; check $? "while the tunnel is cut a direct request is blocked"
! cli curl -sS --max-time 6 --interface eth0 "http://$RESP:8000/" >/dev/null 2>&1; check $? "while the tunnel is cut a request bound to the physical interface is blocked"
! docker exec $P-resp grep -q "src=$CLIENT" /resp.log; check $? "the responder never saw the client's own address"
docker exec $P-router nft flush chain inet cut f
wait_for 150 connected; check $? "the client reconnects by itself when the path comes back"
OUTPUT="$(tunnelled)"; grep -q "src=$SERVER\$" <<<"$OUTPUT"; check $? "traffic flows through the node again" "$OUTPUT"
# tls: with UDP cut the other transport has to carry it.
docker exec $P-router nft add rule inet cut f ip daddr $SERVER meta l4proto udp drop
wait_for 90 down
wait_for 300 flows; check $? "with UDP cut the client carries traffic again, over tls"
SESSIONS="$(node_api /v1/sessions)"; echo "    node sessions: $SESSIONS" | cut -c1-400
grep -q '"transport":"tls"' <<<"$SESSIONS"; check $? "the node's session for alice is on the tls transport"
docker exec $P-router nft flush chain inet cut f
# 5. The panel again, with the user's traffic in it.
echo "== 4. the panel's view of the client"
count_drive usage
echo "== 5. screenshots"
docker run --rm --ipc=host --network $P-b --add-host $HOST:$SERVER -v veilway-ui-pw:/pw -v "$HERE/shots.mjs":/shots.mjs:ro -v "$WORK/state":/state -v "$OUT":/out -e PW_HOME=/pw -e STATE=/state -e OUT=/out -e PANEL_HOST=$HOST -e PANEL_PREFIX="$PREFIX" mcr.microsoft.com/playwright:v1.64.0-noble sh -c 'test -d /pw/node_modules/playwright || (cd /pw && npm init -y >/dev/null && npm install playwright@1.64.0 >/dev/null 2>&1); cp /shots.mjs /pw/shots.mjs && cd /pw && node shots.mjs'
check $? "screenshots of login, users and traffic in English and Persian" "$OUT"
cli veilway disconnect | sed 's/^/    /'
cli curl -sS --max-time 6 "http://$RESP:8000/" 2>&1 | grep -q "src=$CLIENT"; check $? "after disconnect the client reaches the network directly again"
echo "== alpha gate: $FAILS failed"
[ "$FAILS" = 0 ]
