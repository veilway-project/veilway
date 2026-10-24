#!/bin/sh
# v0.3.0 gate: one panel manages two remote nodes through managed node links, end to end, in containers on one private network.
# Node 1 runs with the panel, which reaches node 1's control socket through a volume both mount, as the installer does through the group veilway.
# Node 2 is managed with node 1 dialling it; node 3 is managed with node 3 dialling node 1. Both pairings run `veilway link offer` and `answer`
# in their containers with the typed confirmations on stdin, and `--apply` puts each entry into its own node's config through that node's control socket.
# A user with a 20 MB quota is on all three servers. A device enrolls through the subscription in a client container and downloads through node 2
# and node 3 until the sum passes the quota, and the user is cut on all three. Node 3's link is blocked with iptables in a sidecar that shares node 1's
# network namespace while the user is changed: node 3 is reported down and node 2 syncs. Once the block is lifted node 3 catches up.
# Node 2 is then removed normally and node 3 as taken.
# The binaries must be in the volume veilway-nodes-bin as veilway and veilway-panel, built in Docker, one heavy build at a time:
#   core checkout:  cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p veilway --bin veilway
#   panel server:   cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --bin veilway-panel
# The panel reads the core checkout as ../../veilway, so mount both checkouts side by side and touch their .rs files first when the target volume is shared.
# Takes no argument. Keys, the panel password and the setup token are made at run time and never printed. VEILWAY_GATE_KEEP=1 keeps the containers after a run.
# Exit status 0 only when every step passed. The first failing step stops the run and prints the logs it needs.
set -u
P=veilway-gate-nodes
NET=$P-net
RUN=$P-run
BINS=veilway-nodes-bin
SUB=172.31.77
NODE1=$SUB.10; NODE2=$SUB.11; NODE3=$SUB.12; CLIENT=$SUB.40; TOOLS=$SUB.50
PREFIX=/gate-admin
VW=/opt/veilway/veilway
PANEL=/opt/veilway/veilway-panel
QUOTA=20000000
BLOB=12000000
PW=$(od -An -N12 -tx1 /dev/urandom | tr -d " \n")
START=$(date +%s)
cleanup(){ [ "${VEILWAY_GATE_KEEP:-}" = 1 ] && return 0; docker rm -f $P-node1 $P-panel $P-node2 $P-node3 $P-client $P-tools $P-blocker >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; docker volume rm $RUN >/dev/null 2>&1; return 0; }
ok(){ echo "PASS  $1: $2"; }
die(){ echo "FAIL  $1: $2"; for c in node1 node2 node3; do echo "== $c node log (tail)"; docker exec $P-$c tail -n 25 /var/lib/veilway/node.log 2>/dev/null; done; echo "== panel log (tail)"; docker exec $P-panel tail -n 25 /var/lib/veilway-panel/panel.log 2>/dev/null; echo "GATE FAILED at: $1 after $(( $(date +%s) - START ))s"; exit 1; }
js(){ docker exec -i $P-tools python3 -c "import json, sys; d = json.load(sys.stdin); print($1)"; }
api(){
	if [ "$1" = GET ]; then out=$(docker exec $P-panel curl -s -w "\n%{http_code}" -b /tmp/jar -c /tmp/jar "http://127.0.0.1:8480$PREFIX/api$2")
	else out=$(printf "%s" "${3:-}" | docker exec -i $P-panel curl -s -w "\n%{http_code}" -X "$1" -b /tmp/jar -c /tmp/jar -H "x-csrf-token: ${CSRF:-}" -H "content-type: application/json" --data-binary @- "http://127.0.0.1:8480$PREFIX/api$2"); fi
	case "$(printf "%s" "$out" | tail -n 1)" in 2??) printf "%s" "$(printf "%s" "$out" | sed '$d')";; *) echo "api $1 $2 answered $(printf "%s" "$out" | tail -n 1): $(printf "%s" "$out" | sed '$d')" >&2; return 1;; esac
}
nodeapi(){ docker exec $P-$1 curl -s --unix-socket /run/veilway/control.sock "http://veilway$2"; }
nstate(){ api GET /nodes | js "[n for n in d['nodes'] if n['id'] == $1][0]['$2']"; }
poll(){ s=$1; shift; i=0; until "$@" >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt $((s / 2)) ] || return 1; sleep 2; done; }
reauth(){ api POST /session/reauth "{\"password\": \"$PW\"}" >/dev/null || die "$1" "the panel refused the re-authentication"; }
wait_line(){ i=0; until grep -m1 "$2" "$1" 2>/dev/null; do i=$((i + 1)); [ $i -lt 240 ] || return 1; sleep 0.5; done; }
wait_socket(){ i=0; until docker exec $P-$1 test -S /run/veilway/control.sock; do i=$((i + 1)); [ $i -lt 60 ] || die setup "$1 did not open its control socket"; sleep 0.5; done; docker exec $P-$1 chmod 660 /run/veilway/control.sock; }
box(){ docker run -d --name "$P-$1" --network $NET --ip "$2" --cpus 2 --memory 1g $3 python:3 sleep infinity >/dev/null || die setup "container $1"; }
docker rm -f $P-node1 $P-panel $P-node2 $P-node3 $P-client $P-tools $P-blocker >/dev/null 2>&1
docker network rm $NET >/dev/null 2>&1
docker volume rm $RUN >/dev/null 2>&1
trap cleanup EXIT
docker run --rm -v $BINS:/opt/veilway:ro python:3 sh -c "test -x $VW && test -x $PANEL" >/dev/null 2>&1 || { echo "SETUP FAILED: no release binaries in the volume $BINS (veilway and veilway-panel). Build them first, see the header of this script."; exit 2; }
docker volume create $RUN >/dev/null
docker network create --subnet $SUB.0/24 $NET >/dev/null || { echo "SETUP FAILED: cannot create the network $NET"; exit 2; }
box node1 $NODE1 "-v $RUN:/run/veilway -v $BINS:/opt/veilway:ro"
box panel $SUB.5 "-v $RUN:/run/veilway -v $BINS:/opt/veilway:ro"
box node2 $NODE2 "-v $BINS:/opt/veilway:ro"
box node3 $NODE3 "-v $BINS:/opt/veilway:ro"
box client $CLIENT "-v $BINS:/opt/veilway:ro"
box tools $TOOLS ""
docker run -d --name $P-blocker --network container:$P-node1 --cap-add NET_ADMIN --cpus 2 --memory 1g python:3 sleep infinity >/dev/null || die setup "the blocker sidecar"
docker exec $P-panel sh -c "apt-get update -qq && apt-get install -y -qq socat >/dev/null 2>&1" & a=$!
docker exec $P-blocker sh -c "apt-get update -qq && apt-get install -y -qq iptables >/dev/null 2>&1" & b=$!
wait $a || die setup "socat did not install in the panel"
wait $b || die setup "iptables did not install in the blocker"
docker exec $P-blocker iptables -L INPUT -n >/dev/null 2>&1 || die setup "iptables does not work in the blocker"
for c in node1 node2 node3; do docker exec $P-$c sh -c "groupadd -g 900 veilway && useradd -r -u 900 -g 900 -M -s /usr/sbin/nologin veilway && install -d -o veilway -g veilway -m 750 /etc/veilway/node /var/lib/veilway /run/veilway" || die setup "the veilway user in $c"; done
docker exec $P-panel sh -c "groupadd -g 900 veilway && groupadd -g 901 veilway-panel && useradd -r -u 901 -g 901 -G 900 -M -s /usr/sbin/nologin veilway-panel && install -d -o veilway-panel -g veilway-panel -m 750 /var/lib/veilway-panel && install -d -o root -g veilway-panel -m 750 /etc/veilway-panel" || die setup "the users of the panel"
KEYS=$(docker exec $P-node1 sh -c "for i in 1 2 3 4 5; do $VW genkey; done") || die setup "genkey"
key(){ printf "%s\n" "$KEYS" | sed -n "s/^private_key: *//p" | sed -n "$1p"; }
K1M=$(key 1); K1L=$(key 2); K2M=$(key 3); K2L=$(key 4); K3M=$(key 5)
NODE1_DOC=$(cat <<EOF
{
	"version": 1,
	"log": {"level": "info", "destinations": false},
	"dns": {"servers": ["$TOOLS:53"]},
	"public_addresses": ["$NODE1"],
	"inbounds": [
		{"tag": "home", "type": "veilway", "private_key": "$K1M", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]},
		{"tag": "link", "type": "veilway", "private_key": "$K1L", "address": ["10.90.1.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51830"}]}
	],
	"outbounds": [{"tag": "plain", "type": "direct"}],
	"exits": [{"tag": "main", "name": "Main", "backend": {"type": "netstack", "outbound": "plain"}}],
	"routing": {"default": "main", "rules": []},
	"users": []
}
EOF
)
printf "%s\n" "$NODE1_DOC" | docker exec -i $P-node1 sh -c "umask 077; cat > /etc/veilway/node/config.json && chown veilway:veilway /etc/veilway/node/config.json"
docker exec -i $P-node2 sh -c "umask 077; cat > /etc/veilway/node/config.json && chown veilway:veilway /etc/veilway/node/config.json" <<EOF
{
	"version": 1,
	"log": {"level": "info", "destinations": false},
	"dns": {"servers": ["$TOOLS:53"]},
	"public_addresses": ["$NODE2"],
	"inbounds": [
		{"tag": "home", "type": "veilway", "private_key": "$K2M", "address": ["10.67.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]},
		{"tag": "link", "type": "veilway", "private_key": "$K2L", "address": ["10.90.2.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51830"}]}
	],
	"outbounds": [{"tag": "plain", "type": "direct"}],
	"exits": [{"tag": "main", "name": "Main", "backend": {"type": "netstack", "outbound": "plain"}}],
	"routing": {"default": "main", "rules": []},
	"users": []
}
EOF
docker exec -i $P-node3 sh -c "umask 077; cat > /etc/veilway/node/config.json && chown veilway:veilway /etc/veilway/node/config.json" <<EOF
{
	"version": 1,
	"log": {"level": "info", "destinations": false},
	"dns": {"servers": ["$TOOLS:53"]},
	"public_addresses": ["$NODE3"],
	"inbounds": [
		{"tag": "home", "type": "veilway", "private_key": "$K3M", "address": ["10.68.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}
	],
	"outbounds": [{"tag": "plain", "type": "direct"}],
	"exits": [{"tag": "main", "name": "Main", "backend": {"type": "netstack", "outbound": "plain"}}],
	"routing": {"default": "main", "rules": []},
	"users": []
}
EOF
printf "%s" "[{\"type\": \"udp\", \"endpoints\": [\"$NODE1:51830\"]}]" | docker exec -i $P-node1 sh -c "umask 077; cat > /etc/veilway/node/transports.json && chown veilway:veilway /etc/veilway/node/transports.json"
printf "%s" "[{\"type\": \"udp\", \"endpoints\": [\"$NODE2:51830\"]}]" | docker exec -i $P-node2 sh -c "umask 077; cat > /etc/veilway/node/transports.json && chown veilway:veilway /etc/veilway/node/transports.json"
for c in node1 node2 node3; do out=$(docker exec -u veilway $P-$c $VW check --config /etc/veilway/node/config.json 2>&1) || die setup "veilway check refused the config of $c: $(echo "$out" | tr "\n" " ")"; done
for c in node1 node2 node3; do docker exec -d -u veilway $P-$c sh -c "$VW run --config /etc/veilway/node/config.json --state /var/lib/veilway/state.json --replay /var/lib/veilway/replay --api /run/veilway/control.sock >/var/lib/veilway/node.log 2>&1"; wait_socket $c; done
docker exec -d $P-tools sh -c "mkdir -p /srv && head -c $BLOB /dev/urandom > /srv/blob.bin && echo ok > /srv/small.txt && cd /srv && exec python3 -m http.server 8000"
docker exec -i $P-panel sh -c "umask 027; cat > /etc/veilway-panel/panel.json && chown root:veilway-panel /etc/veilway-panel/panel.json" <<EOF
{
	"listen": "127.0.0.1:8480",
	"prefix": "$PREFIX",
	"sub_path": "/sub",
	"database": "/var/lib/veilway-panel/panel.db",
	"keys": "/var/lib/veilway-panel/panel.keys",
	"signing": "/var/lib/veilway-panel/signing.keys",
	"gateway": "/var/lib/veilway-panel/gateway.keys",
	"gateway_next": "/var/lib/veilway-panel/gateway.next",
	"node_socket": "/run/veilway/control.sock",
	"update_request": "/var/lib/veilway-panel/update-request",
	"trusted_proxies": ["127.0.0.1", "::1"],
	"allowed_hosts": [],
	"secure_cookies": false,
	"update_check": false,
	"two_step": "off"
}
EOF
docker exec -d -u veilway-panel $P-panel sh -c "$PANEL run --config /etc/veilway-panel/panel.json >/var/lib/veilway-panel/panel.log 2>&1"
docker exec -d $P-panel socat TCP-LISTEN:80,fork,reuseaddr TCP:127.0.0.1:8480
i=0; until TOKEN=$(docker exec $P-panel sed -n 's/^Setup token (one time): //p' /var/lib/veilway-panel/panel.log 2>/dev/null | head -n 1) && [ -n "$TOKEN" ]; do i=$((i + 1)); [ $i -lt 60 ] || die setup "the panel printed no setup token"; sleep 0.5; done
CSRF=
api POST /setup "{\"token\": \"$TOKEN\", \"username\": \"owner\", \"password\": \"$PW\", \"accepted_terms\": true}" >/dev/null || die setup "the panel setup"
ans=$(api POST /login "{\"username\": \"owner\", \"password\": \"$PW\"}") || die setup "the panel login"
CSRF=$(printf "%s" "$ans" | js "d['csrf']")
reauth setup
REV=$(api GET /config | js "json.dumps(d['revision'])") || die setup "the panel cannot read node 1's config"
api PUT /config "{\"revision\": $REV, \"document\": $NODE1_DOC}" >/dev/null || die setup "the panel did not take node 1's config with its keys, which it needs for the inbound public keys"
api PUT /settings "{\"provider_name\": \"Gate\", \"endpoints\": [{\"name\": \"main\", \"url\": \"http://$P-panel/sub/main\", \"pins\": []}], \"default_endpoint\": \"main\", \"pool_v4\": \"10.66.0.0/24\", \"node_host\": \"$NODE1\", \"default_device_limit\": 3, \"show_links_once\": false, \"update_interval\": 900, \"document_days\": 14, \"refresh_mirrors\": []}" >/dev/null || die setup "the panel settings"
api POST /profiles/publish >/dev/null || die setup "publishing node 1's profiles"
ok setup "node 1 (home and link inbounds), node 2 and node 3 (home each) run; the panel runs as veilway-panel on node 1's socket in volume $RUN; admin signed in; node 1's profiles published"

# pair OFFERER OFFER_ARGS OFFER_LINES ANSWERER ANSWER_ARGS ANSWER_LINES: the operators' part, each side's typed lines on its stdin, and the groups each side reads carried across.
pair(){
	d=$(mktemp -d); mkfifo "$d/offer.in" "$d/answer.in"
	docker exec -i -u veilway $P-$1 sh -c "$VW link offer $2" < "$d/offer.in" > "$d/offer.out" 2> "$d/offer.err" & o=$!
	exec 3> "$d/offer.in"
	[ -n "$3" ] && printf "%s\n" $3 >&3
	docker exec -i -u veilway $P-$4 sh -c "$VW link answer $5" < "$d/answer.in" > "$d/answer.out" 2> "$d/answer.err" & a=$!
	exec 4> "$d/answer.in"
	code=$(wait_line "$d/offer.out" "^vwlink1"); [ -n "$code" ] || die "pair $1 with $4" "no offer code from $1: $(tail -n 3 "$d/offer.err" | tr "\n" " ")"
	printf "%s\n" "$code" $6 >&4
	answer=$(wait_line "$d/answer.out" "^vwlinka1"); [ -n "$answer" ] || die "pair $1 with $4" "no answer code from $4: $(tail -n 3 "$d/answer.err" | tr "\n" " ")"
	theirs=$(wait_line "$d/answer.err" "over a channel you trust" | sed "s/.*trust: //")
	printf "%s\n%s\n" "$answer" "$theirs" >&3
	ours=$(wait_line "$d/offer.err" "over a channel you trust" | sed "s/.*trust: //")
	printf "%s\n" "$ours" >&4
	exec 3>&- 4>&-
	wait $o; ro=$?; wait $a; ra=$?
	[ $ro = 0 ] && [ $ra = 0 ] || die "pair $1 with $4" "exit $ro from $1 and $ra from $4: $(tail -n 4 "$d/offer.err" | tr "\n" " ") | $(tail -n 4 "$d/answer.err" | tr "\n" " ")"
	rm -rf "$d"
}
pair node2 "--config /etc/veilway/node/config.json --tag panel --inbound link --name Panel --address 10.90.2.2 --listener-address 10.90.2.10 --managed --transports /etc/veilway/node/transports.json --apply=/run/veilway/control.sock" yes node1 "--config /etc/veilway/node/config.json --tag node2 --apply=/run/veilway/control.sock" yes
links1=$(nodeapi node1 /v1/links | js "sorted([(l['tag'], l.get('manage')) for l in d['links']])")
links2=$(nodeapi node2 /v1/config | js "[(l['tag'], l.get('manage')) for l in d['document']['links']]")
[ "$links1" = "[('node2', 'peer')]" ] && [ "$links2" = "[('panel', 'by_peer')]" ] || die "pair node 2" "node 1 has $links1, node 2 has $links2"
ok "pair node 2" "node 2 offered as managed, node 1 dialled it: node 1 holds manage peer, node 2 manage by_peer, both applied through their own sockets"
pair node1 "--config /etc/veilway/node/config.json --tag node3 --inbound link --name Node3 --address 10.90.1.2 --listener-address 10.90.1.10 --manages --transports /etc/veilway/node/transports.json --apply=/run/veilway/control.sock" "" node3 "--config /etc/veilway/node/config.json --tag panel --apply=/run/veilway/control.sock" "yes yes"
links1=$(nodeapi node1 /v1/links | js "sorted([(l['tag'], l.get('manage')) for l in d['links']])")
links3=$(nodeapi node3 /v1/config | js "[(l['tag'], l.get('manage')) for l in d['document']['links']]")
[ "$links1" = "[('node2', 'peer'), ('node3', 'peer')]" ] && [ "$links3" = "[('panel', 'by_peer')]" ] || die "pair node 3" "node 1 has $links1, node 3 has $links3"
ok "pair node 3" "node 3 dialled node 1, node 3 typed yes to being managed: node 1 holds manage peer for node3, node 3 manage by_peer"

reauth "add node 2"
ans=$(api POST /nodes '{"name": "Node 2", "link": "node2", "pool_v4": "10.67.0.0/24"}') || die "add node 2" "the panel refused it"
ID2=$(printf "%s" "$ans" | js "d['id']")
reauth "add node 3"
ans=$(api POST /nodes '{"name": "Node 3", "link": "node3", "pool_v4": "10.68.0.0/24"}') || die "add node 3" "the panel refused it"
ID3=$(printf "%s" "$ans" | js "d['id']")
up_applied(){ [ "$(nstate $1 link_state)" = up ] && [ "$(nstate $1 behind)" = False ]; }
poll 300 up_applied $ID2 || die "add node 2" "link $(nstate $ID2 link_state), behind $(nstate $ID2 behind)"
poll 300 up_applied $ID3 || die "add node 3" "link $(nstate $ID3 link_state), behind $(nstate $ID3 behind)"
ok "add nodes" "node 2 (id $ID2) and node 3 (id $ID3) added through their links, links up and applied"

ans=$(api POST /users "{\"name\": \"alice\", \"quota_bytes\": $QUOTA, \"quota_period\": \"monthly\"}") || die "user" "the panel refused alice"
USERID=$(printf "%s" "$ans" | js "d['user']['id']")
LINK=$(printf "%s" "$ans" | js "d['link']['veilway']")
has_quota(){ nodeapi $1 /v1/users | js "len(d['users']) == 1 and d['users'][0]['quota_bytes'] == $QUOTA"; }
quota_ok(){ [ "$(has_quota node1)" = True ] && [ "$(has_quota node2)" = True ] && [ "$(has_quota node3)" = True ]; }
user_ok(){ api GET /users/$USERID | js "d['quota_bytes'] == $QUOTA and d['quota_period'] == 'monthly' and d['enabled']"; }
[ "$(user_ok)" = True ] || die "user" "the panel does not hold alice with the quota and the monthly period"
ok "user" "alice (id $USERID) with a $QUOTA byte monthly quota on the panel; a node holds her once she has a device there"

docker exec $P-client sh -c "mkdir -p -m 700 /var/lib/vw && yes yes | head -n 12 > /var/lib/vw/answers"
docker exec -e VW_LINK="$LINK" $P-client sh -c "$VW connect \"\$VW_LINK\" --proxy-only --local-proxy 127.0.0.1:10808 --data-dir /var/lib/vw < /var/lib/vw/answers > /var/lib/vw/enroll-1.log 2>&1"
device_applied(){ [ "$(nstate $ID2 devices)" -ge 1 ] && [ "$(nstate $ID3 devices)" -ge 1 ] && up_applied $ID2 && up_applied $ID3; }
poll 300 device_applied || die "enroll" "the nodes do not hold the device: node 2 has $(nstate $ID2 devices), node 3 has $(nstate $ID3 devices)"
poll 240 quota_ok || die "enroll" "alice is not on all three nodes with the quota after her device: node 1 $(has_quota node1), node 2 $(has_quota node2), node 3 $(has_quota node3)"
docker exec $P-client sh -c "$VW connect --refresh --proxy-only --local-proxy 127.0.0.1:10808 --data-dir /var/lib/vw < /var/lib/vw/answers > /var/lib/vw/enroll-2.log 2>&1"
LISTED=$(docker exec $P-client sed -n "s/^error: The subscription has more than one connection, pick one with --profile: //p" /var/lib/vw/enroll-2.log | tr "," "\n" | sed "s/^ *//")
for id in home node-2-home node-3-home; do echo "$LISTED" | grep -q "^$id (" || die "enroll" "the refreshed subscription does not list $id: $(docker exec $P-client tail -n 3 /var/lib/vw/enroll-2.log | tr "\n" ";")"; done
ok "enroll" "device enrolled through the link; connect --refresh fetched a document that lists $(echo "$LISTED" | wc -l | tr -d " ") connections: $(echo "$LISTED" | tr "\n" ";")"

# fetch PROFILE: a connection of that profile in the client container, one download of $BLOB bytes through the local SOCKS5 proxy, then the connection ends.
fetch(){ docker exec -e VW_PROFILE="$1" -e VW_TOOLS=$TOOLS $P-client sh -c "rm -f /var/lib/vw/run.log; $VW connect --profile \"\$VW_PROFILE\" --proxy-only --local-proxy 127.0.0.1:10808 --data-dir /var/lib/vw < /var/lib/vw/answers > /var/lib/vw/run.log 2>&1 & pid=\$!; sleep 1; L=\$(sed -n 's/^Local proxy login: user \(.*\) password \(.*\)/\1:\2/p' /var/lib/vw/run.log); i=0; until curl -s -o /dev/null -x socks5h://\$L@127.0.0.1:10808 http://\$VW_TOOLS:8000/small.txt || [ \$i -ge 60 ]; do i=\$((i + 1)); sleep 1; done; curl -s -o /dev/null -w '%{size_download} %{http_code}' -x socks5h://\$L@127.0.0.1:10808 http://\$VW_TOOLS:8000/blob.bin; kill \$pid; wait \$pid"; }
R2=$(fetch node-2-home)
[ "$R2" = "$BLOB 200" ] || die "download via node 2" "got \"$R2\", expected \"$BLOB 200\": $(docker exec $P-client sh -c "grep -v password /var/lib/vw/run.log | tail -n 3" | tr "\n" " ")"
usage_of(){ nodeapi $1 /v1/users | js "'%s used of %s' % (d['users'][0]['used_bytes'], d['users'][0]['quota_bytes'])"; }
ok "download via node 2" "$R2 bytes at 200 through node 2 (node 2 counts $(usage_of node2))"
R3=$(fetch node-3-home)
[ "$R3" = "$BLOB 200" ] || die "download via node 3" "got \"$R3\", expected \"$BLOB 200\": $(docker exec $P-client sh -c "grep -v password /var/lib/vw/run.log | tail -n 3" | tr "\n" " ")"
ok "download via node 3" "$R3 bytes at 200 through node 3 (node 3 counts $(usage_of node3)): the sum is past the $QUOTA byte quota"

cut_of(){ nodeapi $1 /v1/users | js "d['users'][0]['quota_bytes'] <= max(1, d['users'][0]['used_bytes'])"; }
cut_done(){ [ "$(cut_of node1)" = True ] && [ "$(cut_of node2)" = True ] && [ "$(cut_of node3)" = True ]; }
poll 300 cut_done || die "cut" "not cut on every node: node 1 $(usage_of node1), node 2 $(usage_of node2), node 3 $(usage_of node3)"
R4=$(fetch node-2-home)
[ "$R4" != "$BLOB 200" ] || die "cut" "a download through node 2 still works after the cut: $R4"
ok "cut" "all three nodes hold quota = max(1, used): node 1 $(usage_of node1), node 2 $(usage_of node2), node 3 $(usage_of node3); after the cut node 2 gives \"$R4\", client says: $(docker exec $P-client grep -i -m1 quota /var/lib/vw/run.log 2>/dev/null || echo nothing about quota)"

docker exec $P-blocker sh -c "iptables -I INPUT -s $NODE3 -j DROP && iptables -I OUTPUT -d $NODE3 -j DROP" || die "block" "the rules were not set in the blocker"
api PATCH /users/$USERID '{"enabled": false}' >/dev/null || die "block" "the panel refused the user change"
node3_down(){ [ "$(nstate $ID3 link_state)" != up ]; }
poll 330 node3_down || die "block" "node 3 is still reported $(nstate $ID3 link_state) after 330 s"
node2_synced(){ [ "$(nstate $ID2 behind)" = False ] && [ "$(nodeapi node2 /v1/config | js "d['document']['users'][0]['enabled']")" = False ]; }
poll 180 node2_synced || die "block" "node 2 did not take the change: behind $(nstate $ID2 behind)"
ok "block" "node 3 reported $(nstate $ID3 link_state) since $(nstate $ID3 down_since) and behind (behind $(nstate $ID3 behind)); node 2 applied the user change"

docker exec $P-blocker sh -c "iptables -D INPUT -s $NODE3 -j DROP && iptables -D OUTPUT -d $NODE3 -j DROP" || die "unblock" "the rules were not removed from the blocker"
node3_caught_up(){ up_applied $ID3 && [ "$(nodeapi node3 /v1/config | js "d['document']['users'][0]['enabled']")" = False ]; }
poll 330 node3_caught_up || die "unblock" "node 3 is $(nstate $ID3 link_state), behind $(nstate $ID3 behind), after 330 s"
ok "unblock" "node 3 is $(nstate $ID3 link_state) again and applied the change it missed (behind $(nstate $ID3 behind))"

reauth "remove node 2"
ans=$(api DELETE /nodes/$ID2) || die "remove node 2" "the panel refused the removal: $ans"
emptied2(){ [ "$(nodeapi node2 /v1/config | js "(len(d['document'].get('users', [])), [l['tag'] for l in d['document'].get('links', []) if l.get('manage') == 'by_peer'])")" = "(0, [])" ]; }
# Node 2 answers the removal before it goes into force, since the answer goes back through the link it removes.
poll 20 emptied2 || true
left2=$(nodeapi node2 /v1/config | js "(len(d['document'].get('users', [])), [l['tag'] for l in d['document'].get('links', []) if l.get('manage') == 'by_peer'])")
tags1=$(nodeapi node1 /v1/links | js "sorted(l['tag'] for l in d['links'])")
[ "$left2" = "(0, [])" ] && [ "$tags1" = "['node3']" ] || die "remove node 2" "node 2 has $left2 (users, by_peer links), node 1 has links $tags1"
ok "remove node 2" "removed normally: node 2 asked to empty itself (users and by_peer link gone), node 1 dropped its link"

reauth "remove node 3"
api DELETE "/nodes/$ID3?taken=true" >/dev/null || die "remove node 3" "the panel refused the removal"
tags1=$(nodeapi node1 /v1/links | js "sorted(l['tag'] for l in d['links'])")
listed=$(api GET /nodes | js "len(d['nodes'])")
[ "$tags1" = "[]" ] && [ "$listed" = 1 ] || die "remove node 3" "node 1 has links $tags1 and the panel lists $listed nodes"
ok "remove node 3" "removed as taken: node 1 dropped its link, the panel lists node 1 only"

echo "GATE PASSED: every step, $(( $(date +%s) - START ))s"
