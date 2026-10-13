#!/bin/sh
# Phase 1 gate: one veilway process serves two WireGuard inbounds on two ports with two exits, a domain rule sends one name to the second (l3) exit,
# ping and IP protocol 253 pass through the l3 exit, peers cannot reach each other, and the control API returns live stats for a user.
# Everything runs in containers on one private Docker network. Nothing is built here: the release binary must already be in the volume veilway-target-p1
# (docker run --rm -v "$PWD":/w -v veilway-target-p1:/w/target -v veilway-cargo:/usr/local/cargo -w /w rust:1 cargo build --release --locked -p veilway).
# Keys are made at run time, live only in shell variables and inside the containers, and are never printed. Takes no argument. Exit status 0 only when every check passed.
set -u
P=veilway-gate1
SUBNET=172.30.71
NODE=$SUBNET.10; NODE2=$SUBNET.11; RA=$SUBNET.20; RB=$SUBNET.21; DNS=$SUBNET.30
GW1=10.71.0.1; ALICE=10.71.0.2; GW2=10.72.0.1; BOB=10.72.0.2
BIN=/t/release/veilway
FAILS=0
cleanup(){ docker rm -f $P-node $P-resp $P-dns $P-alice $P-bob >/dev/null 2>&1; docker network rm $P-net >/dev/null 2>&1; return 0; }
die(){ echo "SETUP FAILED: $1"; docker exec $P-node sh -c "tail -n 30 /gate/node.log" 2>/dev/null; exit 2; }
check(){ if [ "$1" = 0 ]; then echo "PASS  $2: $3"; else echo "FAIL  $2: $3"; FAILS=$((FAILS + 1)); fi; }
api(){ docker exec $P-node curl -sS -f --max-time 5 --unix-socket /gate/veilway.sock "http://veilway$1"; }
# Evaluates one Python expression over the JSON document on stdin, named d.
js(){ docker exec -i $P-node python3 -c "import json, sys; d = json.load(sys.stdin); print($1)"; }
exits(){ sleep 1; api /v1/exits | js "' '.join(str(sum(e['traffic'].values())) for e in sorted(d['exits'], key = lambda e: e['tag']))"; }
seen(){ docker exec $P-resp grep -c "^$1\$" /responder.log; }
key(){ printf "%s\n" "$K" | sed -n "s/^$1_key: *//p" | sed -n "$2p"; }
client(){ # name, tunnel address, gateway, server port, server public key, private key, the other peer's address
	printf "%s\n" "$6" | docker exec -i $P-$1 sh -c "umask 077; cat > /wg.key" || die "no key file in $1"
	docker exec $P-$1 sh -c "set -e
	ip link add wg0 type wireguard
	wg set wg0 private-key /wg.key peer $5 endpoint $NODE:$4 allowed-ips $3/32,$RA/32,$RB/32,$7/32 persistent-keepalive 5
	ip addr add $2/32 dev wg0 && ip link set wg0 mtu 1380 up
	for d in $3 $RA $RB $7; do ip route add \$d/32 dev wg0; done
	echo nameserver $3 > /etc/resolv.conf" || die "WireGuard client $1 did not come up"
	docker exec -d $P-$1 python -u /c.py listen $2
}
cleanup; trap cleanup EXIT
docker run --rm -v veilway-target-p1:/t:ro rust:1 test -x $BIN || { echo "SETUP FAILED: no release binary in the volume veilway-target-p1 (release/veilway). Build it first, see the header of this script."; exit 2; }
docker network create --subnet $SUBNET.0/24 $P-net >/dev/null || die "cannot create the network $P-net ($SUBNET.0/24)"
docker run -d --name $P-node --network $P-net --ip $NODE --cap-add NET_ADMIN --device /dev/net/tun -v veilway-target-p1:/t:ro rust:1 sleep infinity >/dev/null || die "node container"
docker run -d --name $P-resp --network $P-net --ip $RA --cap-add NET_ADMIN python:3-alpine sleep infinity >/dev/null || die "responder container"
docker run -d --name $P-dns --network $P-net --ip $DNS python:3-alpine sleep infinity >/dev/null || die "dns container"
docker run -d --name $P-alice --network $P-net --ip $SUBNET.40 --cap-add NET_ADMIN python:3-alpine sleep infinity >/dev/null || die "client container alice"
docker run -d --name $P-bob --network $P-net --ip $SUBNET.41 --cap-add NET_ADMIN python:3-alpine sleep infinity >/dev/null || die "client container bob"
docker exec -i $P-resp sh -c "cat > /responder.py" <<"EOF"
# Greets on TCP 7000, logs every ICMP echo request, and echoes IP protocol 253 from the address it was sent to.
import select, socket
tcp = socket.socket(); tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); tcp.bind(("0.0.0.0", 7000)); tcp.listen(64)
icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253)
while True:
	for s in select.select([tcp, icmp, raw], [], [])[0]:
		if s is tcp:
			conn, peer = tcp.accept(); print("tcp src=%s dst=%s" % (peer[0], conn.getsockname()[0]), flush = True); conn.sendall(b"hello-gate1"); conn.close()
			continue
		data = s.recv(2048); head = (data[0] & 15) * 4; src, dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
		if s is icmp and data[head] == 8: print("icmp src=%s dst=%s" % (src, dst), flush = True)
		if s is raw:
			print("raw src=%s dst=%s" % (src, dst), flush = True)
			out = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253); out.bind((dst, 0)); out.sendto(b"echo:" + data[head:], (src, 0)); out.close()
EOF
docker exec -i $P-dns sh -c "cat > /dns.py" <<"EOF"
# Answers A queries for the names given as name=address, everything else with NXDOMAIN or an empty answer.
import socket, struct, sys
names = dict(a.split("=") for a in sys.argv[1:])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 53))
while True:
	q, peer = s.recvfrom(1500)
	try:
		i, labels = 12, []
		while q[i]: labels.append(q[i + 1:i + 1 + q[i]].decode().lower()); i += q[i] + 1
		name, qtype = ".".join(labels), struct.unpack("!H", q[i + 1:i + 3])[0]
		answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(names[name]) if name in names and qtype == 1 else b""
		s.sendto(q[:2] + struct.pack("!HHHHH", 0x8180 | (0 if name in names else 3), 1, 1 if answer else 0, 0, 0) + q[12:i + 5] + answer, peer)
		print("dns %s type=%d from=%s" % (name, qtype, peer[0]), flush = True)
	except (IndexError, UnicodeDecodeError, struct.error): pass
EOF
for c in alice bob; do docker exec -i $P-$c sh -c "cat > /c.py" <<"EOF"
# listen ADDR | tcp NAME PORT COUNT | raw NAME. Names go through the resolver in /etc/resolv.conf, which is the node's gateway address.
import socket, sys, time
cmd, target = sys.argv[1], sys.argv[2]
try:
	if cmd == "listen":
		srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind((target, 7100)); srv.listen(8)
		while True: conn = srv.accept()[0]; conn.sendall(b"peer-listener"); conn.close()
	addr = socket.gethostbyname(target)
	if cmd == "tcp":
		for i in range(int(sys.argv[4])): conn = socket.create_connection((addr, int(sys.argv[3])), timeout = 4); data = conn.recv(64); conn.close(); time.sleep(0.1)
		print(addr, data.decode())
	if cmd == "raw":
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 253); s.settimeout(4); s.sendto(b"gate1-probe", (addr, 0)); data = s.recv(2048)
		print(addr, socket.inet_ntoa(data[12:16]), data[(data[0] & 15) * 4:].decode())
except OSError as e:
	print("error", type(e).__name__, e); sys.exit(1)
EOF
done
(docker exec $P-node sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iproute2 nftables >/dev/null 2>&1 && ip addr add $NODE2/24 dev eth0" || touch "/tmp/$P-failed.$$") &
for c in alice bob; do (docker exec $P-$c apk add -q wireguard-tools-wg iproute2 >/dev/null 2>&1 || touch "/tmp/$P-failed.$$") & done
wait
if [ -e "/tmp/$P-failed.$$" ]; then rm -f "/tmp/$P-failed.$$"; die "package install failed (iproute2 and nftables in the node, wireguard-tools and iproute2 in the clients)"; fi
docker exec $P-resp sh -c "ip addr add $RB/24 dev eth0" || die "second responder address"
docker exec -d $P-resp sh -c "python -u /responder.py >/responder.log 2>&1"
docker exec -d $P-dns sh -c "python -u /dns.py main.gate.test=$RA l3.gate.test=$RB >/dns.log 2>&1"
K=$(docker exec $P-node sh -c "for i in 1 2 3 4; do $BIN genkey; done") || die "genkey"
docker exec -i $P-node sh -c "umask 077; mkdir -p /gate; cat > /gate/config.json" <<EOF
{
	"version": 1,
	"log": {"level": "info", "destinations": false},
	"dns": {"servers": ["$DNS:53"], "hijack": true},
	"inbounds": [
		{"tag": "one", "type": "wireguard", "private_key": "$(key private 1)", "address": ["$GW1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]},
		{"tag": "two", "type": "wireguard", "private_key": "$(key private 2)", "address": ["$GW2/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51821"}]}
	],
	"outbounds": [{"tag": "plain", "type": "direct", "bind": "$NODE2"}],
	"exits": [
		{"tag": "main", "name": "Main", "backend": {"type": "netstack", "outbound": "plain"}},
		{"tag": "node", "name": "This node", "backend": {"type": "l3", "interface": "vwgate0", "masquerade": true}}
	],
	"routing": {
		"default": "main",
		"rules": [
			{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"},
			{"tag": "second-exit", "domain": ["l3.gate.test"], "action": {"exit": "node"}},
			{"tag": "lab", "ip": ["$RA/32", "$RB/32", "$DNS/32"], "action": "user"},
			{"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}
		]
	},
	"users": [
		{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": "$(key public 3)", "addresses": ["$ALICE"]}]},
		{"name": "bob", "exits": "all", "devices": [{"name": "desktop", "public_key": "$(key public 4)", "addresses": ["$BOB"]}]}
	]
}
EOF
[ "$(docker exec $P-node stat -c %a /gate/config.json)" = 600 ] || die "config is not mode 600"
docker exec $P-node $BIN check --config /gate/config.json >/dev/null 2>&1 || { docker exec $P-node $BIN check --config /gate/config.json; die "veilway check refused the config"; }
docker exec -d $P-node sh -c "cd /gate && $BIN run --config /gate/config.json >/gate/node.log 2>&1; echo \$? >/gate/node.exit"
i=0; until docker exec $P-node test -S /gate/veilway.sock; do i=$((i + 1)); [ $i -lt 30 ] || die "the node did not open its control socket within 15 seconds"; sleep 0.5; done
client alice $ALICE $GW1 51820 "$(key public 1)" "$(key private 3)" $BOB
client bob $BOB $GW2 51821 "$(key public 2)" "$(key private 4)" $ALICE
K=
sleep 1
echo "== Phase 1 gate, $(docker exec $P-node $BIN --version), kernel WireGuard clients, non-TCP/UDP protocol is IP protocol 253"
PID=$(docker exec $P-node pidof veilway)
PORTS=$(docker exec $P-node ss -Hlunp | sed -n "s/.*:\(5182[01]\) .*pid=\([0-9]*\).*/\1=\2/p" | sort | tr "\n" " ")
[ "$PORTS" = "51820=$PID 51821=$PID " ]; check $? "two inbounds, one process" "udp listeners by pid: ${PORTS}veilway pid(s): $PID"
E0=$(exits); OUT=$(docker exec $P-alice python /c.py tcp main.gate.test 7000 1); E1=$(exits)
[ "$OUT" = "$RA hello-gate1" ] && [ "$(seen "tcp src=$NODE2 dst=$RA")" = 1 ] && [ "${E0% *}" != "${E1% *}" ] && [ "${E0#* }" = "${E1#* }" ]
check $? "default exit" "alice got \"$OUT\" for main.gate.test, responder saw $(seen "tcp src=$NODE2 dst=$RA") connection(s) from the bind address $NODE2, exit bytes main ${E0% *} -> ${E1% *}, node ${E0#* } -> ${E1#* }"
OUT=$(docker exec $P-alice python /c.py tcp l3.gate.test 7000 1); E2=$(exits)
[ "$OUT" = "$RB hello-gate1" ] && [ "$(seen "tcp src=$NODE dst=$RB")" = 1 ] && [ "${E1% *}" = "${E2% *}" ] && [ "${E1#* }" != "${E2#* }" ]
check $? "domain rule to the second exit" "alice got \"$OUT\" for l3.gate.test, responder saw $(seen "tcp src=$NODE dst=$RB") connection(s) from the masquerade address $NODE, exit bytes main ${E1% *} -> ${E2% *}, node ${E1#* } -> ${E2#* }"
GOT=$(docker exec $P-alice ping -c 3 -W 2 l3.gate.test 2>&1 | sed -n "s/.* \([0-9]*\) packets received.*/\1/p"); E3=$(exits)
[ "$GOT" = 3 ] && [ "$(seen "icmp src=$NODE dst=$RB")" = 3 ] && [ "${E2% *}" = "${E3% *}" ] && [ "${E2#* }" != "${E3#* }" ]
check $? "ping through the l3 exit" "${GOT:-0} of 3 replies, responder saw $(seen "icmp src=$NODE dst=$RB") echo request(s) from $NODE, exit bytes main ${E2% *} -> ${E3% *}, node ${E2#* } -> ${E3#* }"
OUT=$(docker exec $P-alice python /c.py raw l3.gate.test); E4=$(exits)
[ "$OUT" = "$RB $RB echo:gate1-probe" ] && [ "$(seen "raw src=$NODE dst=$RB")" = 1 ] && [ "${E3% *}" = "${E4% *}" ] && [ "${E3#* }" != "${E4#* }" ]
check $? "IP protocol 253 through the l3 exit" "alice got \"$OUT\", responder saw $(seen "raw src=$NODE dst=$RB") datagram(s) from $NODE, exit bytes main ${E3% *} -> ${E4% *}, node ${E3#* } -> ${E4#* }"
OWN="$(docker exec $P-alice python /c.py tcp $ALICE 7100 1) / $(docker exec $P-bob python /c.py tcp $BOB 7100 1)"
BA_PING=$(docker exec $P-bob ping -c 2 -W 2 $ALICE 2>&1 | sed -n "s/.* \([0-9]*\) packets received.*/\1/p"); BA_TCP=$(docker exec $P-bob python /c.py tcp $ALICE 7100 1)
AB_PING=$(docker exec $P-alice ping -c 2 -W 2 $BOB 2>&1 | sed -n "s/.* \([0-9]*\) packets received.*/\1/p"); AB_TCP=$(docker exec $P-alice python /c.py tcp $BOB 7100 1)
A_OUT=$(docker exec $P-alice python /c.py tcp main.gate.test 7000 1); B_OUT=$(docker exec $P-bob python /c.py tcp main.gate.test 7000 1)
[ "$OWN" = "$ALICE peer-listener / $BOB peer-listener" ] && [ "$BA_PING" = 0 ] && [ "$AB_PING" = 0 ] && [ "${BA_TCP%% *}" = error ] && [ "${AB_TCP%% *}" = error ] && [ "$A_OUT" = "$RA hello-gate1" ] && [ "$B_OUT" = "$RA hello-gate1" ]
check $? "peers are isolated" "bob to alice: ping ${BA_PING:-?}/2, tcp \"$BA_TCP\"; alice to bob: ping ${AB_PING:-?}/2, tcp \"$AB_TCP\"; own listeners answer locally: \"$OWN\"; responder still reached by alice \"$A_OUT\" and by bob (second inbound) \"$B_OUT\""
SUM="str(sum(d['traffic'].values()))"
U1=$(api /v1/users/alice | js "d['name'] + ' ' + $SUM"); docker exec -d $P-alice python /c.py tcp main.gate.test 7000 80; sleep 4
RATE=$(api /v1/stats | js "' '.join(str(u[k]) for u in d['users'] if u['name'] == 'alice' for k in ('up_bytes_per_sec', 'down_bytes_per_sec')) + ' ' + str(d['window_secs'])")
S1=$(api /v1/stats | js "' '.join($SUM for d in d['users'] if d['name'] == 'alice')"); sleep 2
S2=$(api /v1/stats | js "' '.join($SUM for d in d['users'] if d['name'] == 'alice')"); U2=$(api /v1/users/alice | js "d['name'] + ' ' + $SUM")
UP=${RATE%% *}; UP=${UP%.*}
[ "${U1% *}" = alice ] && [ "${U2#* }" -gt "${U1#* }" ] && [ "$S2" -gt "$S1" ] && [ "${UP:-0}" -gt 0 ]
check $? "live stats for a user" "GET /v1/users/alice bytes ${U1#* } -> ${U2#* }, GET /v1/stats alice bytes $S1 -> $S2, rate up/down/window: $RATE"
OUT=$(api /v1/status | js "'version %s generation %d inbounds %d exits %d users %d flows %d uptime %ds' % tuple(d[k] for k in ('version', 'generation', 'inbounds', 'exits', 'users', 'flows', 'uptime_secs'))")
case "$OUT" in *"generation 1 inbounds 2 exits 2 users 2"*) true;; *) false;; esac; check $? "GET /v1/status" "${OUT:-no answer}"
BEFORE=$(docker exec $P-node sh -c "test -S /gate/veilway.sock && echo socket; ip -o link show vwgate0 >/dev/null 2>&1 && echo link; nft list tables | grep -c veilway_vwgate0" | tr "\n" " ")
docker exec $P-node kill -TERM "$PID"
i=0; until docker exec $P-node test -e /gate/node.exit || [ $i -ge 30 ]; do i=$((i + 1)); sleep 0.5; done
AFTER=$(docker exec $P-node sh -c "echo exit=\$(cat /gate/node.exit 2>/dev/null); test -e /gate/veilway.sock && echo socket; ip -o link show vwgate0 >/dev/null 2>&1 && echo link; nft list tables | grep -c veilway_vwgate0" | tr "\n" " ")
[ "$BEFORE" = "socket link 1 " ] && [ "$AFTER" = "exit=0 0 " ]; check $? "clean shutdown on SIGTERM" "before: ${BEFORE}(socket, interface, nft tables named veilway_vwgate0); after: ${AFTER}(exit status, then what is left, then nft table count)"
if [ $FAILS -gt 0 ]; then
	echo "== node log (last 60 lines)"; docker exec $P-node tail -n 60 /gate/node.log
	echo "== responder log:"; docker exec $P-resp cat /responder.log; echo "== dns log:"; docker exec $P-dns cat /dns.log
	echo "GATE FAILED: $FAILS check(s)"; exit 1
fi
echo "GATE PASSED: every check"
