#!/usr/bin/env bash
# The Xray add-on gate (PLAN.md, Phase 6): the node installs the pinned Xray-core with `veilway.sh addon xray install`, the panel makes a VLESS inbound for an existing user, and a stock Xray client uses the link the panel gives (VLESS, Trojan and Shadowsocks 2022) as a local SOCKS proxy to fetch through the node. The user's bytes show in the panel, the node's gate, rules and exits apply, and a user who is disabled or over quota loses the connection. Xray runs as a user of its own with no capability, sees nothing of the node's, answers a stranger with the decoy web server, ends with the node, and its credentials are made new on request. Everything runs in Docker containers on this machine.
#   bash scripts/gate-xray.sh                run the whole gate
#   SKIP_BUILD=1 bash scripts/gate-xray.sh  reuse the binaries of an earlier run (Docker volume veilway-alpha-rel)
#   KEEP=1 bash scripts/gate-xray.sh        leave the containers running afterwards (names vwxray-*)
#   WORK=/some/dir                          where keys, logs and state go (default $TMPDIR/veilway-gate-xray)
# Needs what scripts/gate-alpha.sh needs, and internet once for the Xray-core release archive (kept in the volume veilway-alpha-rel). The archive is served by the local release server and checked against the pins in veilway.sh and in the node like any other.
# Exit status 0 only when every check passed.
# shellcheck disable=SC2001,SC2015,SC2086,SC2319
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/scripts/gate-xray"
ALPHA="$ROOT/scripts/gate-alpha"
PANEL_SRC="${VEILWAY_PANEL_SRC:-$ROOT/../veilway-panel}"
UI_SRC="${VEILWAY_UI_SRC:-$ROOT/../veilway-ui}"
WORK="${WORK:-${TMPDIR:-/tmp}/veilway-gate-xray}"
OUT="$WORK/out"
P=vwxray
# Public-looking addresses on purpose: a client refuses private ones for the subscription server and for a node, and the networks are Docker bridges that go nowhere else.
A=11.95.7; B=11.96.7
CLIENT=$A.40; RA=$A.2; RB=$B.2; SERVER=$B.10; RESP=$B.20; REL=$B.30
HOST=node.gate.test; RELHOST=releases.gate.test
TAG=v0.0.1-gate
XRAY=v26.3.27
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
proxied() { cli curl -sS --max-time 10 --socks5-hostname 127.0.0.1:${2:-1080} "$1" 2>&1; }
build_wait() { while docker ps --format '{{.Image}} {{.Names}}' | grep -E '^(rust|node)' | grep -v "$P" | grep -q .; do echo "another build runs, waiting"; sleep 20; done; }
drive() { local cmd=$1; shift; docker run --rm --network $P-b --add-host $HOST:$SERVER -v "$WORK/state":/state -v "$WORK/tls/ca.pem":/ca.pem:ro -v "$HERE/drive.py":/drive.py:ro -e STATE=/state -e CA=/ca.pem -e PANEL_HOST=$HOST -e PANEL_PREFIX="$PREFIX" -e NODE_IP=$SERVER -e DNS_IP=$RESP -e ENDPOINT_PIN="$ENDPOINT_PIN" "$@" $P-tools python3 -I /drive.py "$cmd"; }
count_drive() { local out rc lines; out="$(drive "$@" 2>&1)"; rc=$?; echo "$out"; lines=$(grep -c '^FAIL' <<<"$out"); [ "$lines" = 0 ] && [ "$rc" != 0 ] && lines=1; FAILS=$((FAILS + lines)); }
[ -d "$PANEL_SRC/server" ] && [ -d "$UI_SRC/packages" ] || die "need the panel checkout ($PANEL_SRC) and the design system ($UI_SRC)"
PANEL_SRC="$(cd "$PANEL_SRC" && pwd)"; UI_SRC="$(cd "$UI_SRC" && pwd)"
mkdir -p "$WORK"; docker run --rm -v "$WORK":/w alpine:3.22 sh -c "rm -rf /w/*"; mkdir -p "$WORK/tls" "$WORK/keys" "$WORK/site" "$WORK/state" "$WORK/xrayc" "$OUT"
cleanup
trap '[ -n "${KEEP:-}" ] || cleanup' EXIT
ARCH="$(docker run --rm alpine:3.22 uname -m)"; TARGET="$ARCH-unknown-linux-musl"
echo "== xray gate: $TARGET, work dir $WORK, screenshots in $OUT"
case "$ARCH" in x86_64) XARCH=linux-64 ;; *) XARCH=linux-arm64-v8a ;; esac
docker volume create $REL_VOL >/dev/null; docker volume create $TGT_VOL >/dev/null; docker volume create veilway-alpha-zig >/dev/null
docker run --rm -v $REL_VOL:/rel alpine:3.22 sh -c "test -s /rel/Xray-$XARCH.zip || { apk add -q --no-cache curl >/dev/null && curl -fsSL --proto '=https' -o /rel/Xray-$XARCH.zip https://github.com/XTLS/Xray-core/releases/download/$XRAY/Xray-$XARCH.zip; }" || die "fetching the Xray-core archive"
# 1. Builds. The node is built the way the release workflow does it, with cargo zigbuild for the musl target (BoringSSL in the client needs libclang in its build script, which a musl host cannot load). The panel has no such dependency and builds natively on Alpine.
if [ -z "${SKIP_BUILD:-}" ] || ! docker run --rm -v $REL_VOL:/rel:ro alpine:3.22 sh -c "test -x /rel/veilway-bin -a -x /rel/veilway-panel-bin"; then
	build_wait
	docker run --rm --cpus 2 --memory 2500m -v "$ROOT":/w/veilway:ro -v veilway-cargo:/usr/local/cargo/registry -v $TGT_VOL:/t -v $REL_VOL:/rel -v veilway-alpha-zig:/zb -e CARGO_TARGET_DIR=/t/zig -e CARGO_INSTALL_ROOT=/zb rust:1 sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq python3-pip cmake clang libclang-dev perl >/dev/null && pip install -q --break-system-packages ziglang && rustup target add '$TARGET' >/dev/null 2>&1 && { test -x /zb/bin/cargo-zigbuild || cargo install -q --locked cargo-zigbuild; } && cd /w/veilway && /zb/bin/cargo-zigbuild zigbuild --release --locked --target '$TARGET' -p veilway --bin veilway && cp /t/zig/'$TARGET'/release/veilway /rel/veilway-bin' || die "building veilway failed"
	build_wait
	docker run --rm --cpus 2 --memory 2500m -v "$PANEL_SRC":/src/veilway-panel:ro -v "$UI_SRC":/src/veilway-ui:ro -v $REL_VOL:/rel node:22-alpine sh -c 'mkdir -p /b/veilway-panel/web /b/veilway-ui && cd /src/veilway-ui && tar cf - --exclude=node_modules --exclude=.git . | tar xf - -C /b/veilway-ui && cd /src/veilway-panel/web && tar cf - --exclude=node_modules --exclude=dist . | tar xf - -C /b/veilway-panel/web && for d in i18n ui; do (cd /b/veilway-ui/packages/$d && npm ci --no-audit --no-fund) || exit 1; done && cd /b/veilway-panel/web && npm ci --no-audit --no-fund && npm run build && rm -rf /rel/web-dist && cp -r dist /rel/web-dist' || die "building the panel's web app failed"
	build_wait
	docker run --rm --cpus 2 --memory 2500m -v "$PANEL_SRC":/src/veilway-panel:ro -v "$ROOT":/b/veilway:ro -v veilway-cargo:/usr/local/cargo/registry -v $TGT_VOL:/t -v $REL_VOL:/rel -e CARGO_TARGET_DIR=/t/panel rust:1-alpine sh -c 'apk add -q --no-cache build-base perl && mkdir -p /b/veilway-panel/web && cp -a /src/veilway-panel/server /b/veilway-panel/server && cp -a /rel/web-dist /b/veilway-panel/web/dist && cd /b/veilway-panel/server && cargo build --release --locked --bin veilway-panel && cp /t/panel/release/veilway-panel /rel/veilway-panel-bin' || die "building veilway-panel failed"
fi
[ -n "${BUILD_ONLY:-}" ] && exit 0
# One image with the tools of a client, a router and the signing, and one that is a server with systemd. The server has neither curl nor minisign, which the install script has to get itself.
docker build -q -t $P-tools - <<'EOF' >/dev/null || die "tools image"
FROM debian:12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 nftables curl tcpdump procps python3 openssl ca-certificates minisign bind9-dnsutils unzip >/dev/null && rm -rf /var/lib/apt/lists/*
EOF
docker build -q -t $P-server-img - <<'EOF' >/dev/null || die "server image"
FROM debian:12
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus nginx-light iproute2 procps ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
# 2. Keys, certificates and the release tree of this run. The CA signs the release server and the panel's web server; the panel's endpoint is pinned in the link as well.
docker run --rm -v "$WORK":/w -v $REL_VOL:/rel:ro -v "$ROOT/config.example.json":/example.json:ro -e TAG=$TAG -e XRAY=$XRAY -e XARCH=$XARCH -e TARGET="$TARGET" -e HOST=$HOST -e RELHOST=$RELHOST -e SERVER=$SERVER -e REL=$REL $P-tools sh -c '
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
X=/w/site/XTLS/Xray-core/releases/download/$XRAY
mkdir -p $X /w/xrayc
cp /rel/Xray-$XARCH.zip $X/
unzip -p /rel/Xray-$XARCH.zip xray >/w/xrayc/xray
chmod 755 /w/xrayc/xray
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
docker run -d --name $P-resp --network $P-b --ip $RESP $LIMITS --cap-add NET_ADMIN -v "$ALPHA/resp.py":/resp.py:ro $P-tools sh -c "ip route add $A.0/24 via $RB; python3 -u /resp.py $RESP >/resp.log 2>&1" >/dev/null || die "responder"
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
[ "$FAILS" = 0 ] || { echo "== stopping: $FAILS check(s) failed before the add-on"; exit 1; }
echo "== 3. the add-on, installed with the script"
ADDONS=/usr/local/lib/veilway/addons/xray
ZIP="$WORK/site/XTLS/Xray-core/releases/download/$XRAY/Xray-$XARCH.zip"
addon() { srv env VEILWAY_TESTING=1 VEILWAY_RELEASE_BASE=https://$RELHOST VEILWAY_RAW_BASE=https://$RELHOST/raw bash /veilway.sh addon xray "$@" --yes; }
[ "$(node_api /v1/status | grep -o '"installed":[a-z]*')" = '"installed":false' ]; check $? "the node says the add-on is not installed"
cp "$ZIP" "$ZIP.real"; head -c 4096 /dev/urandom >"$ZIP"
addon install >"$WORK/addon-bad.log" 2>&1; [ $? != 0 ]; check $? "an archive that is not the pinned one is refused"
grep -q "pinned" "$WORK/addon-bad.log"; check $? "the refusal names the pin" "$(tail -n 1 "$WORK/addon-bad.log")"
srv test ! -e $ADDONS/xray; check $? "nothing was installed from it"
mv "$ZIP.real" "$ZIP"
addon install 2>&1 | tee "$WORK/addon.log" | sed 's/^/    /'
[ "${PIPESTATUS[0]}" = 0 ]; check $? "veilway.sh addon xray install finished"
srv sh -c "test -x $ADDONS/xray && [ \"\$(stat -c %U $ADDONS/xray)\" = root ] && [ \"\$(stat -c %U $ADDONS)\" = root ]"; check $? "the executable is root's, in a folder the node cannot write"
node_api /v1/status | grep -q '"installed":true'; check $? "the node says the add-on is installed"
echo "== 4. the panel makes a VLESS inbound for an existing user"
count_drive xray -e NODE_IP=$SERVER
statekey() { python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$WORK/state/state.json" "$1"; }
LINK="$(statekey xray_link)"; SS_LINK="$(statekey ss_link)"; TJ_LINK="$(statekey tj_link)"
case "$LINK" in vless://*) true ;; *) false ;; esac; check $? "the panel gives a vless:// link for alice"
case "$SS_LINK" in ss://2022-blake3-aes-256-gcm:*) true ;; *) false ;; esac; check $? "and a Shadowsocks 2022 link with a server key and her key"
case "$TJ_LINK" in trojan://*) true ;; *) false ;; esac; check $? "and a trojan:// link"
[ "$FAILS" = 0 ] || { echo "== stopping: the panel side failed"; exit 1; }
wait_for 60 srv sh -c 'ss -ltn | grep -q ":8444 "'; check $? "xray listens on the port the operator chose"
XPID="$(srv pgrep -f '^xray run -config' | head -n 1)"
[ -n "$XPID" ]; check $? "xray runs, started by the host unit" "pid $XPID"
srv sh -c "ss -ltnp | grep 'pid=$XPID,' | grep -v ':8444 \|:8445 \|:8446 '"; [ $? != 0 ]; check $? "xray listens on no other port, so its hop and any API stay inside the node"
srv sh -c 'ss -ltnp | grep "\"veilway\"" | grep -q "127.0.0.1:[0-9]* .*users:"'; check $? "the node's local hop is on 127.0.0.1"
srv sh -c "test \"\$(wc -c </proc/$XPID/environ)\" = 0"; check $? "xray runs with an empty environment"
srv sh -c "grep -q '^CapEff:.0000000000000000\$' /proc/$XPID/status && grep -q '^CapAmb:.0000000000000000\$' /proc/$XPID/status"; check $? "xray holds no capability at all (CapEff and CapAmb are 0)" "$(srv grep -E '^Cap(Eff|Amb)' /proc/$XPID/status | tr '\n\t' '  ')"
srv sh -c "grep -q '^NoNewPrivs:.1' /proc/$XPID/status"; check $? "xray cannot gain privileges (no_new_privs)"
[ "$(srv stat -c %U /proc/$XPID)" = veilway-xray ] && [ "$(srv stat -c %U /proc/$(srv systemctl show -p MainPID --value veilway.service))" = veilway ]; check $? "xray runs as its own user, not the node's"
srv nsenter -t $XPID -m setpriv --reuid veilway-xray --regid veilway-xray --clear-groups sh -c "! ls /etc/veilway/node >/dev/null 2>&1 && ! ls /var/lib/veilway >/dev/null 2>&1 && ! ls /run/veilway >/dev/null 2>&1"; check $? "the node's config, state and control socket are out of xray's sight (tried as its user, in its own mounts)"
srv sh -c "! cat /proc/$XPID/root/var/lib/veilway/veilway-state.json >/dev/null 2>&1"; check $? "xray cannot read the node's usage state"
srv sh -c "sed -n 's/^MemoryMax=//p' /etc/systemd/system/veilway-xray.service | grep -q ."; check $? "the host unit limits xray's memory"
srv sh -c 'find /var/lib/veilway /etc/veilway /run/veilway /run/veilway-xray /tmp -type f \( -iname "*xray*" -o -iname "*.json" \) 2>/dev/null | grep -v "/etc/veilway/node/config.json\|/etc/veilway/panel.json\|/var/lib/veilway/veilway-state.json" | xargs -r grep -l "\"inbounds\"" 2>/dev/null | grep -q .'; [ $? != 0 ]; check $? "no xray config file is written anywhere"
srv sh -c "grep -r -l 'BEGIN' /proc/$XPID/cmdline /proc/$XPID/environ 2>/dev/null"; [ $? != 0 ]; check $? "the certificate key is not on xray's command line or in its environment"
echo "== 5. a stock Xray client uses the panel's link"
docker run -d --name $P-client --network $P-a --ip $CLIENT $LIMITS --cap-add NET_ADMIN --add-host $HOST:$SERVER -v "$WORK/xrayc":/xc:ro -v "$WORK/tls/ca.pem":/ca.pem:ro $P-tools sleep infinity >/dev/null || die "client container"
cli sh -c 'cp /ca.pem /usr/local/share/ca-certificates/gate-ca.crt && update-ca-certificates >/dev/null 2>&1' || die "client CA"
cli ip route replace default via $RA || die "client route"
python3 -I "$HERE/clientcfg.py" "$LINK" 1080 >"$WORK/xrayc/client.json" || die "client config"
python3 -I "$HERE/clientcfg.py" "$LINK" 1081 --wrong >"$WORK/xrayc/wrong.json" || die "client config"
docker exec -d $P-client sh -c '/xc/xray run -config /xc/client.json >/xray-client.log 2>&1'
python3 -I "$HERE/clientcfg.py" "$SS_LINK" 1082 >"$WORK/xrayc/ss.json" || die "client config"
python3 -I "$HERE/clientcfg.py" "$TJ_LINK" 1083 >"$WORK/xrayc/tj.json" || die "client config"
docker exec -d $P-client sh -c '/xc/xray run -config /xc/wrong.json >/xray-wrong.log 2>&1'
docker exec -d $P-client sh -c '/xc/xray run -config /xc/ss.json >/xray-ss.log 2>&1'
docker exec -d $P-client sh -c '/xc/xray run -config /xc/tj.json >/xray-tj.log 2>&1'
wait_for 20 cli sh -c 'ss -ltn | grep -q ":1080 " && ss -ltn | grep -q ":1081 " && ss -ltn | grep -q ":1082 " && ss -ltn | grep -q ":1083 "'; check $? "the stock client runs as a local SOCKS proxy"
OUTPUT="$(proxied http://$RESP:8000/ 1082)"
grep -q "src=$SERVER\$" <<<"$OUTPUT"; check $? "Shadowsocks 2022 with the server key and the user's key carries a fetch through the node" "$OUTPUT"
OUTPUT="$(proxied http://$RESP:8000/ 1083)"
grep -q "src=$SERVER\$" <<<"$OUTPUT"; check $? "Trojan carries a fetch through the node" "$OUTPUT"
flows_x() { proxied "http://$RESP:8000/" | grep -q "src=$SERVER\$"; }
blocked_x() { ! flows_x; }
OUTPUT="$(proxied http://$RESP:8000/)"
grep -q "src=$SERVER\$" <<<"$OUTPUT"; check $? "a web server behind the node sees the node's address, not the client's" "$OUTPUT"
OUTPUT="$(proxied http://app.gate.test:8000/)"
grep -q "src=$SERVER\$" <<<"$OUTPUT"; check $? "a name is resolved by the node and fetched through it" "$OUTPUT"
docker exec $P-resp grep -q "^dns app.gate.test type=1 from=$SERVER\$" /resp.log; check $? "the DNS server was asked by the node, with the node's DNS set"
! docker exec $P-resp grep -q "src=$CLIENT" /resp.log; check $? "the responder never saw the client's own address"
OUTPUT="$(cli curl -sS --max-time 8 https://$HOST:8444/ 2>&1)"
grep -q "a plain site" <<<"$OUTPUT"; check $? "a stranger on the xray port is answered by the decoy web server" "$OUTPUT"
OUTPUT="$(cli curl -sS --max-time 8 -X POST --data x https://$HOST:8445/login 2>&1)"
grep -q "a plain site" <<<"$OUTPUT"; check $? "and on the trojan port too" "$OUTPUT"
! srv sh -c "journalctl -u veilway-xray.service --no-pager 2>/dev/null | grep -q '$CLIENT'"; check $? "xray logs no client address (no access log, masked addresses)"
U1="$(node_api /v1/users/alice | grep -o '"used_bytes":[0-9]*')"; E1="$(node_api /v1/exits)"
proxied http://nothere.gate.test:8000/ >/dev/null
U2="$(node_api /v1/users/alice | grep -o '"used_bytes":[0-9]*')"; E2="$(node_api /v1/exits)"
docker exec $P-resp grep -q "^dns nothere.gate.test type=1 from=$SERVER\$" /resp.log; check $? "a name that does not exist is asked of the DNS server by the node, like a tunnel's query"
[ -n "$U1" ] && [ "$U1" != "$U2" ] && [ "$E1" != "$E2" ]; check $? "and the query counts for the user and for the exit" "$U1 -> $U2"
! proxied http://127.0.0.1:8000/ >/dev/null; check $? "the destination gate holds: the node's own loopback is refused"
! proxied http://10.55.0.1:8000/ >/dev/null; check $? "the routing rules hold: private networks are refused"
! proxied http://$RESP:8000/ 1081 >/dev/null; check $? "a client with another user's id gets nothing"
echo "== 6. the panel's view"
count_drive usage -e NODE_IP=$SERVER
echo "== 7. a quota and a disabled user take the access away"
count_drive limit -e NODE_IP=$SERVER -e QUOTA=1
wait_for 40 blocked_x; check $? "a user over quota loses the xray connection"
count_drive limit -e NODE_IP=$SERVER -e QUOTA=5368709120
wait_for 60 flows_x; check $? "and gets it back when the quota is raised"
count_drive limit -e NODE_IP=$SERVER -e QUOTA=5368709120 -e ENABLED=0
wait_for 60 blocked_x; check $? "a disabled user loses it too"
echo "== 8. new credentials, and xray ends with the node"
count_drive limit -e NODE_IP=$SERVER -e QUOTA=5368709120 -e ENABLED=1
wait_for 60 flows_x; check $? "alice is back before the rotation"
count_drive rotate -e NODE_IP=$SERVER
NEW_LINK="$(statekey xray_link)"
[ "$NEW_LINK" != "$LINK" ]; check $? "the panel's link for alice is a different one after the rotation"
python3 -I "$HERE/clientcfg.py" "$NEW_LINK" 1084 >"$WORK/xrayc/new.json" || die "client config"
docker exec -d $P-client sh -c '/xc/xray run -config /xc/new.json >/xray-new.log 2>&1'
wait_for 20 cli sh -c 'ss -ltn | grep -q ":1084 "'
newer_x() { proxied "http://$RESP:8000/" 1084 | grep -q "src=$SERVER\$"; }
wait_for 60 newer_x; check $? "the new link works once the node has taken the change"
wait_for 20 blocked_x; check $? "and the old link no longer does"
OLD="$(srv pgrep -f '^xray run -config' | head -n 1)"
srv systemctl stop veilway.service
wait_for 15 srv sh -c '! pgrep -f "^xray run -config"'; check $? "xray ends when the node is stopped"
srv systemctl start veilway.service
wait_for 60 srv sh -c 'pgrep -f "^xray run -config"'; check $? "and comes back when the node does"
KILLED="$(srv pgrep -f '^xray run -config' | head -n 1)"
srv sh -c "kill -9 \$(systemctl show -p MainPID --value veilway.service)"
wait_for 15 srv sh -c "! kill -0 $KILLED"; check $? "xray ends when the node is killed outright"
wait_for 60 srv sh -c 'pgrep -f "^xray run -config"'; check $? "and comes back with the node that systemd starts"
echo "== 9. the host refuses an executable that is not the pinned one"
srv sh -c "pkill -f '^xray run -config'; printf '#!/bin/sh\nsleep 1000\n' >$ADDONS/xray.fake && chmod 755 $ADDONS/xray.fake && mv -f $ADDONS/xray.fake $ADDONS/xray"
count_drive limit -e NODE_IP=$SERVER -e QUOTA=5368709120 -e ENABLED=1
sleep 8
srv sh -c "journalctl -u veilway.service --no-pager 2>/dev/null | grep -q 'not the pinned release'"; check $? "the node logs that it will not run an executable that does not match its pin"
srv sh -c "pgrep -f '^xray run -config'" >/dev/null; [ $? != 0 ]; check $? "and no xray runs"
srv sh -c "journalctl -u veilway-xray.service --no-pager 2>/dev/null | grep -q 'not the pinned release'"; check $? "the host logs the same refusal"
echo "== xray gate: $FAILS failed"
[ "$FAILS" = 0 ]
