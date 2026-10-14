#!/bin/sh
# Client gate for the Linux layer (Phase 2 step 4, part 2): `veilway connect` on a client container against a real `veilway run` node, over a real TUN device, policy routes, nftables kill switch and a pinned resolver. What it holds the client to:
# HTTP and DNS reach a responder that only the node can reach, and DNS goes only into the tunnel. The kill switch is proved by itself: probes from the client (TCP, UDP, DNS, mDNS, IPv6, a socket with the engine's mark to a non-node address) are counted on the wire at a router, and they are also sent with the blackhole routes removed, so that only the nftables chain stands between them and the network. The kill switch holds while connected, while the path to the node is cut and the client reconnects, after a change of network, after `kill -9`, after the TUN device is deleted under a running client (a failure of the client: it must exit non-zero and leave the kill switch in force), while a question waits on the terminal, and lifts on a clean disconnect and on a no to a question. A second client, and a `connect` with another run directory in the environment, do not touch a running one, and `disconnect` stops a client that is still connecting the clean way. Other programs' policy rules at the client's priorities survive. Routes pushed after connect do not move traffic out of the tunnel, a split tunnel and `--allow-lan` leave a tunnelled network that is inside the LAN's ranges in the tunnel, and names (DNS, mDNS, LLMNR) are not asked on the LAN. An IPv4-only profile refuses IPv6, and the vault is encrypted with its key in root's key file.
# Containers on four Docker networks: client (A) - routers r1 and r2 (A and B) - node (B and I) - responder (I). The node is not on the client's network on purpose: a node inside the device's own networks is not dialled.
# The binaries must be built already, in the volume veilway-target-usage (cargo build -p veilway --bin veilway -p veilway-linux --example gate_setup, with CARGO_TARGET_DIR=/w/target/linux-client). Keys are made at run time and live in the containers. The client runs with Docker's default seccomp profile. Takes no argument; KEEP=1 keeps the containers. Exit status 0 only when every check passed.
set -u
P=veilway-gc
A=172.31.91; B=172.31.92; I=172.31.93
CLIENT=$A.40; R1A=$A.2; R2A=$A.3; R1B=$B.2; R2B=$B.3; NODE=$B.10; NODEI=$I.10; RESP=$I.20
CLIENT6=fd91::40; R2A6=fd91::3
V6=1
VOL=veilway-target-usage
BIN=/t/linux-client/debug
FAILS=0
cleanup(){ docker rm -f $P-client $P-node $P-r1 $P-r2 $P-resp >/dev/null 2>&1; docker network rm $P-a $P-b $P-i >/dev/null 2>&1; return 0; }
die(){ echo "SETUP FAILED: $1"; docker exec $P-node sh -c "tail -n 20 /gate/node.log" 2>/dev/null; exit 2; }
check(){ if [ "$1" = 0 ]; then echo "PASS  $2: $3"; else echo "FAIL  $2: $3"; FAILS=$((FAILS + 1)); fi; }
c(){ docker exec $P-client "$@"; }
q(){ docker exec $P-client "$@" >/dev/null 2>&1; }
wait_for(){ n=$1; shift; while [ $n -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; n=$((n - 1)); done; return 1; }
connected(){ docker exec $P-client veilway status 2>/dev/null | grep -q "^State: Connected"; }
lost(){ docker exec $P-client veilway status 2>/dev/null | grep -q "^State: .*\(Reconnecting\|Connecting\|lost\)"; }
exited(){ docker exec $P-client sh -c 'test -s /connect.exit'; }
exit_code(){ docker exec $P-client cat /connect.exit 2>/dev/null | tr -d ' \r\n'; }
tunnelled(){ c curl -sS --max-time 8 http://app.gate.test:8000/ 2>&1; }
snapshot(){ c sh -c "ip rule; echo ---; ip -6 rule; echo ---; cat /etc/resolv.conf; echo ---; nft list tables" 2>&1; }
# profile, source file or empty, extra arguments. The answers are yes to everything it asks, the way a person at a terminal would type them.
connect(){ docker exec -d $P-client sh -c "rm -f /connect.exit; yes yes | veilway connect ${2:-} --profile $1 --data-dir ${DATA:-/data} ${3:-} >/connect.log 2>&1; echo \$? >/connect.exit"; }
start_dns_capture(){ docker exec -d $P-client sh -c "tcpdump -i eth0 -n -U -w /eth0.pcap 'port 53' >/dev/null 2>&1"; docker exec -d $P-client sh -c "tcpdump -i vw0 -n -U -w /vw0.pcap 'port 53' >/dev/null 2>&1"; sleep 1; }
packets(){ docker exec $P-client sh -c "tcpdump -nr /$1.pcap 2>/dev/null | wc -l" | tr -d ' \r'; }
stop_captures(){ docker exec $P-client sh -c 'kill $(pidof tcpdump)' >/dev/null 2>&1; sleep 1; }
# What the witness router saw on the client's network: the packets that match a filter, so a probe is counted where it would do harm.
seen(){ a=$(docker exec $P-r1 sh -c "tcpdump -nr /r.pcap '$1' 2>/dev/null | wc -l" | tr -d " \r"); b=$(docker exec $P-r2 sh -c "tcpdump -nr /r.pcap '$1' 2>/dev/null | wc -l" | tr -d " \r"); echo $((a + b)); }
# probe KIND ADDRESS PORT [options of probe.py]: sends one from the client and says how many such packets reached the wire.
probe(){
	kind=$1; addr=$2; port=$3; shift 3
	case "$addr" in *:*) f="ip6 and src host $CLIENT6 and dst host $addr and $kind dst port $port";; *) f="src host $CLIENT and dst host $addr and $kind dst port $port";; esac
	before=$(seen "$f"); q python3 /probe.py $kind $addr $port "$@"; sleep 1; after=$(seen "$f"); echo $((after - before))
}
# The kill switch alone: the blackhole routes taken away, so that nothing but the nftables chain stands between a probe and the network.
drop_blackholes(){ q ip route del blackhole default metric 1000 table 22103; [ $V6 = 1 ] && q ip -6 route del blackhole default metric 1000 table 22103; return 0; }
restore_blackholes(){ q ip route add blackhole default metric 1000 table 22103; [ $V6 = 1 ] && q ip -6 route add blackhole default metric 1000 table 22103; return 0; }
counters(){ c nft list table inet veilway_killswitch 2>&1 | grep counter | grep -vc "packets 0 "; }
# The probes of the kill switch, none of which may reach the wire: TCP and UDP and DNS bound to the physical interface, IPv6, and a socket with the engine's mark to an address that is no node's.
blocked_probes(){
	t4=$(probe tcp $R2A 8081 dev=eth0); u4=$(probe udp $R2A 5300 dev=eth0); d4=$(probe udp $R2A 53 dev=eth0); m4=$(probe udp $R2A 5300 dev=eth0 mark=0x5657); w4=$(probe udp $NODE 5002 mark=0x5657)
	t6=0; u6=0; if [ $V6 = 1 ]; then t6=$(probe tcp $R2A6 8081 dev=eth0); u6=$(probe udp $R2A6 5300 dev=eth0); fi
	[ "$t4$u4$d4$m4$w4$t6$u6" = 0000000 ]; check $? "$1" "packets on the wire: tcp $t4, udp $u4, dns $d4, marked to a non-node $m4, marked to the wrong port of the node $w4, ipv6 tcp $t6, ipv6 udp $u6 (nft counters that moved: $(counters))"
}
cleanup; trap '[ -n "${KEEP:-}" ] || cleanup' EXIT
docker run --rm -v $VOL:/t:ro rust:1 test -x $BIN/veilway -a -x $BIN/examples/gate_setup || { echo "SETUP FAILED: no binaries in the volume $VOL (see the header of this script)."; exit 2; }
docker network create --ipv6 --subnet $A.0/24 --subnet fd91::/64 $P-a >/dev/null 2>&1 && docker network create --ipv6 --subnet $I.0/24 --subnet fd93:1::/64 $P-i >/dev/null 2>&1 || { V6=0; docker network rm $P-a $P-i >/dev/null 2>&1; docker network create --subnet $A.0/24 $P-a >/dev/null && docker network create --subnet $I.0/24 $P-i >/dev/null || die "cannot create the networks $P-a and $P-i"; echo "note: this Docker has no IPv6 networks, the IPv6 checks are skipped"; }
docker network create --subnet $B.0/24 $P-b >/dev/null || die "cannot create the network $P-b ($B.0/24)"
LIMITS="--cpus 1 --memory 512m"
V6SYSCTL="--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0"
for r in r1 r2; do
	eval "RA=\$$(echo $r | tr a-z A-Z)A"
	if [ $V6 = 1 ]; then RA6="--ip6 fd91::${RA##*.}"; else RA6=; fi
	docker run -d --name $P-$r --network $P-a --ip $RA $RA6 $LIMITS --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 rust:1 sleep infinity >/dev/null || die "router $r"
done
docker network connect --ip $R1B $P-b $P-r1 && docker network connect --ip $R2B $P-b $P-r2 || die "router networks"
docker run -d --name $P-node --network $P-b --ip $NODE $LIMITS --cap-add NET_ADMIN -v $VOL:/t:ro rust:1 sleep infinity >/dev/null || die "node container"
if [ $V6 = 1 ]; then docker network connect --ip $NODEI --ip6 fd93:1::10 $P-i $P-node; else docker network connect --ip $NODEI $P-i $P-node; fi || die "node inner network"
if [ $V6 = 1 ]; then RESP6="--ip6 fd93:1::20"; else RESP6=; fi
docker run -d --name $P-resp --network $P-i --ip $RESP $RESP6 $LIMITS python:3-alpine sleep infinity >/dev/null || die "responder container"
if [ $V6 = 1 ]; then CLIENT6A="--ip6 $CLIENT6"; else CLIENT6A=; fi
docker run -d --name $P-client --network $P-a --ip $CLIENT $CLIENT6A $LIMITS --cap-add NET_ADMIN --device /dev/net/tun $V6SYSCTL -v $VOL:/t:ro rust:1 sleep infinity >/dev/null || die "client container"
for c in client node r1 r2; do (docker exec $P-$c sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iproute2 nftables curl tcpdump procps >/dev/null 2>&1 && ln -sf $BIN/veilway /usr/local/bin/veilway" || touch "/tmp/$P-failed.$$") & done
wait
if [ -e "/tmp/$P-failed.$$" ]; then rm -f "/tmp/$P-failed.$$"; die "package install failed"; fi
docker exec -i $P-resp sh -c "cat > /resp.py" <<"EOF"
# HTTP on 8000 that says who asked, and a DNS server that knows app.gate.test. Both log who asked.
import http.server, socket, struct, sys, threading
addr, wide = sys.argv[1], sys.argv[2] == "1"
def peer(a): return a[7:] if a.startswith("::ffff:") else a
class Server(http.server.ThreadingHTTPServer):
	address_family = socket.AF_INET6 if wide else socket.AF_INET
	def server_bind(self):
		if wide: self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
		super().server_bind()
class Handler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		body = ("hello-from-responder src=%s\n" % peer(self.client_address[0])).encode()
		self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
		print("http src=%s" % peer(self.client_address[0]), flush = True)
	def log_message(self, *a): pass
def dns():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 53))
	while True:
		q, who = s.recvfrom(1500)
		try:
			i, labels = 12, []
			while q[i]: labels.append(q[i + 1:i + 1 + q[i]].decode().lower()); i += q[i] + 1
			name, qtype = ".".join(labels), struct.unpack("!H", q[i + 1:i + 3])[0]
			hit = name == "app.gate.test"
			answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton(addr) if hit and qtype == 1 else b""
			s.sendto(q[:2] + struct.pack("!HHHHH", 0x8180 | (0 if hit else 3), 1, 1 if answer else 0, 0, 0) + q[12:i + 5] + answer, who)
			print("dns %s type=%d from=%s" % (name, qtype, who[0]), flush = True)
		except (IndexError, UnicodeDecodeError, struct.error): pass
threading.Thread(target = dns, daemon = True).start()
Server(("::" if wide else "0.0.0.0", 8000), Handler).serve_forever()
EOF
docker exec -i $P-client sh -c "cat > /probe.py" <<"EOF"
# probe.py tcp|udp ADDRESS PORT [mark=0x5657] [dev=eth0]: one connection attempt or datagram from a socket with the options given.
import socket, sys
kind, addr, port, opts = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
s = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM); s.settimeout(2)
for o in opts:
	if o.startswith("mark="): s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(o[5:], 0))
	if o.startswith("dev="): s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, o[4:].encode())
	if o.startswith("sport="): s.bind(("::" if ":" in addr else "0.0.0.0", int(o[6:])))
try:
	if kind == "tcp": s.connect((addr, port)); print("connected")
	else: s.sendto(b"gate", (addr, port)); print("sent")
except OSError as e: print("error", e.errno)
EOF
docker exec -d $P-resp sh -c "python -u /resp.py $RESP $V6 >/resp.log 2>&1"
if [ $V6 = 1 ]; then WEB="::"; else WEB=0.0.0.0; fi
for r in r1 r2; do docker exec -d $P-$r sh -c "python3 -m http.server 8081 --bind $WEB >/web.log 2>&1"; done
for r in r1 r2; do docker exec -d $P-$r sh -c "tcpdump -i eth0 -n -U -w /r.pcap >/dev/null 2>&1"; done
docker exec $P-node ip route add $A.0/24 via $R1B || die "node route"
c ip route replace default via $R1A dev eth0 || die "client route"
if [ $V6 = 1 ]; then SETUP="--v6"; else SETUP=; fi
docker exec $P-node $BIN/examples/gate_setup /gate $NODE $RESP $SETUP || die "gate_setup"
docker exec $P-node sh -c "mkdir -p /gate/site && echo decoy > /gate/site/index.html"
docker exec -d $P-node sh -c "cd /gate/site && python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1"
docker exec $P-node veilway check --config /gate/node/config.json >/dev/null 2>&1 || { docker exec $P-node veilway check --config /gate/node/config.json; die "veilway check refused the node config"; }
docker exec -d $P-node sh -c "cd /gate/node && veilway run --config config.json >/gate/node.log 2>&1"
wait_for 20 docker exec $P-node sh -c "ss -Hlun | grep -q :5001" || die "the node did not open its port within 20 seconds"
for f in subscription subscription-v4; do docker exec $P-node cat /gate/client/$f.vw | docker exec -i $P-client sh -c "cat > /$f.vw"; done
echo "== client gate, $(c veilway --version), node $NODE (not on the client's network $A.0/24), responder $RESP reachable only through the node, IPv6 $V6"
# Rules other programs made, at the client's own priorities: a connect and a disconnect must leave them alone.
c ip rule add priority 5100 to 192.0.2.97 lookup 779; c ip rule add priority 5120 from 192.0.2.99 lookup 777; c ip rule add priority 5130 from 192.0.2.98 lookup 778; c ip rule add priority 5125 from 192.0.2.96 lookup 780
BASE=$(snapshot)
# 0. What the probes see with nothing in force: they reach the wire, so that a count of zero later is the kill switch's.
T0=$(probe tcp $R2A 8081 dev=eth0); U0=$(probe udp $R2A 5300 dev=eth0); D0=$(probe udp $R2A 53 dev=eth0); M0=$(probe udp $R2A 5300 dev=eth0 mark=0x5657); H0=$(probe tcp 203.0.113.7 8000)
[ "$T0" -ge 1 ] && [ "$U0" -ge 1 ] && [ "$D0" -ge 1 ] && [ "$M0" -ge 1 ]; check $? "probes reach the wire with nothing in force" "tcp $T0, udp $U0, dns $D0, marked $M0 packets seen at the router, so a count of zero below is the kill switch's"
c ip route add 203.0.113.0/24 via $R2A dev eth0; H1=$(probe tcp 203.0.113.7 8000); c ip route del 203.0.113.0/24
[ "$H1" -ge 1 ]; check $? "a pushed route moves traffic with nothing in force" "a connection to 203.0.113.7 reached the wire through a route in the main table: $H1 packet(s)"
# 1. Connect over the obfuscated transport, importing the subscription with the answers typed. The node's first minute refuses proofs (its replay file is new), so the first connect may wait for it.
connect obfs /subscription.vw
wait_for 120 connected; check $? "connect" "$(c veilway status 2>&1 | sed -n '1p;2p' | tr '\n' ' ')"
IMPORT=$(c sh -c "grep -c 'Provider (its own claim): Gate provider' /connect.log"); ASKS=$(c sh -c "grep -c 'Type yes to continue' /connect.log"); [ "$IMPORT" = 1 ] && [ "$ASKS" -ge 3 ]; check $? "import with the user's yes" "the review showed the provider and the fingerprint, and $ASKS questions were asked before the tunnel started"
start_dns_capture
OUT=$(tunnelled)
[ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "http and dns through the tunnel" "curl app.gate.test:8000 said \"$OUT\" (the responder sees the node's address $NODEI, not the client's)"
SEEN=$(docker exec $P-resp grep -c "^dns app.gate.test type=1 from=$NODEI\$" /resp.log); [ "$SEEN" -ge 1 ]; check $? "the node resolved the name" "the DNS server saw $SEEN query(ies) from the node $NODEI"
RES=$(c cat /etc/resolv.conf | grep '^nameserver' | tr '\n' ' '); [ "$RES" = "nameserver 10.7.0.1 $(if [ $V6 = 1 ]; then echo 'nameserver fd07:7::1 '; fi)" ]; check $? "resolver pinned" "/etc/resolv.conf says: $RES"
sleep 1; ETH=$(packets eth0); VW=$(packets vw0); [ "$ETH" = 0 ] && [ "$VW" -ge 2 ]; check $? "dns only into the tunnel" "port 53 packets on eth0: $ETH, on the tunnel's device: $VW"
if [ $V6 = 1 ]; then OUT6=$(c curl -sS --max-time 8 "http://[fd93:1::20]:8000/" 2>&1); [ "$OUT6" = "hello-from-responder src=fd93:1::10" ]; check $? "IPv6 through the tunnel" "curl [fd93:1::20]:8000 said \"$OUT6\""; fi
c curl -sS --max-time 8 http://$R2A:8081/ >/dev/null 2>&1; SRC=$(docker exec $P-r2 sh -c "grep -c '$NODE - -' /web.log"); [ "$SRC" -ge 1 ]; check $? "the default route is the tunnel" "a plain connection from the client to the witness $R2A reached it from the node's address $NODE ($SRC time(s)), so it went through the tunnel"
KS=$(c nft list table inet veilway_killswitch 2>&1 | grep -c "meta mark"); RULES=$(c ip rule | grep -c "lookup 22103\|fwmark 0x5657"); [ "$KS" -ge 1 ] && [ "$RULES" -ge 2 ]; check $? "rules in force" "nft marked-socket rules: $KS, ip rules for the mark and the table: $RULES"
blocked_probes "kill switch, connected"
# A DHCP client's datagram (from port 68 to 67) is looked up in the main table and let out; any other datagram to port 67 is not.
P1=$(probe udp $R2A 67 sport=68); P2=$(probe udp $R2A 67); P3=$(probe udp $R2A 67 dev=eth0)
[ "$P1" -ge 1 ] && [ "$P2" = 0 ] && [ "$P3" = 0 ]; check $? "only a DHCP client's datagram leaves for port 67" "from port 68: $P1 packet(s) on the wire; from another port, unbound: $P2, bound to the interface: $P3"
c ip route add 203.0.113.0/24 via $R2A dev eth0; H2=$(probe tcp 203.0.113.7 8000); c ip route del 203.0.113.0/24
[ "$H2" = 0 ]; check $? "a route pushed after connect moves nothing" "a connection to 203.0.113.7 through a more specific route in the main table put $H2 packet(s) on the wire"
drop_blackholes; blocked_probes "kill switch alone, connected, blackhole routes removed"; restore_blackholes
# 2. The path to the node is cut: the client reconnects, and nothing leaks meanwhile, names included.
docker exec $P-r1 sh -c "nft add table ip gc && nft add chain ip gc cut '{ type filter hook forward priority 0; policy accept; }' && nft add rule ip gc cut ip saddr $CLIENT drop" || die "cannot cut the path on r1"
wait_for 150 lost; check $? "reconnecting" "the path to the node was cut and the state became: $(c veilway status 2>&1 | sed -n 2p)"
blocked_probes "kill switch, reconnecting"
OUT=$(tunnelled); case "$OUT" in *hello*) false;; *) true;; esac; check $? "nothing gets through meanwhile" "curl app.gate.test while reconnecting said: $(echo $OUT | cut -c1-90)"
sleep 1; ETH=$(packets eth0); [ "$ETH" = 0 ]; check $? "no dns on the wire while reconnecting" "port 53 packets on eth0: $ETH"
docker exec $P-r1 nft delete table ip gc
wait_for 150 connected; check $? "reconnected" "the path came back and the state became: $(c veilway status 2>&1 | sed -n 2p)"
OUT=$(tunnelled); [ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "traffic after the reconnect" "curl said \"$OUT\""
# 3. The device changes network: the default route moves to r2, r1 is gone.
docker exec $P-node ip route replace $A.0/24 via $R2B; c ip route replace default via $R2A dev eth0; docker exec $P-r1 sh -c "nft add table ip gone && nft add chain ip gone f '{ type filter hook forward priority 0; policy drop; }'"
wait_for 30 sh -c "docker exec $P-client grep -q 'the device.s networks changed' /connect.log"; check $? "network change seen" "$(c grep 'networks changed' /connect.log | tail -n 1 | cut -c1-160)"
wait_for 90 connected; OUT=$(tunnelled); [ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "traffic after the change" "curl said \"$OUT\" through the new gateway $R2A"
blocked_probes "kill switch after the change"
N1=$(probe udp $NODE 5001 mark=0x5657); [ "$N1" -ge 1 ]; check $? "a marked socket reaches the node's own port" "a marked datagram to $NODE:5001 put $N1 packet(s) on the wire (the kill switch's one way out)"
[ "${STOP_AFTER:-}" = roam ] && exit 0
stop_captures
# 4. The client process is killed: the kill switch stays, and `veilway disconnect` is what removes it.
c sh -c 'kill -9 $(pidof veilway)'; sleep 2
blocked_probes "kill switch after a crash"
OUT=$(tunnelled); case "$OUT" in *hello*) false;; *) true;; esac; check $? "no traffic after a crash" "curl app.gate.test said: $(echo $OUT | cut -c1-90)"
drop_blackholes; blocked_probes "kill switch alone after a crash, no device and no blackhole routes"
q curl -sS --max-time 3 http://$R2A:8081/; [ $? != 0 ]; check $? "plain traffic with nothing but the chain" "an unbound connection to the witness failed with the device gone and the blackhole routes removed"
ST=$(c veilway status 2>&1); echo "$ST" | grep -q "Not connected" && echo "$ST" | grep -q "kill switch is still in force"; check $? "status after a crash" "$(echo $ST | cut -c1-140)"
c test -e /var/lib/veilway/resolv.conf.saved && ! c test -e /run/veilway/resolv.conf.saved; check $? "the saved resolver file is where a reboot keeps it" "resolv.conf.saved is in /var/lib/veilway and not in /run/veilway"
DIS=$(c veilway disconnect 2>&1)
echo "$DIS" | grep -q "Put /etc/resolv.conf back as it was"; check $? "disconnect says what it restored" "$(echo $DIS | cut -c1-200)"
AFTER=$(snapshot); [ "$AFTER" = "$BASE" ]; check $? "disconnect after a crash" "$(echo $DIS | cut -c1-150); rules (other programs' included), resolver and tables are as before: $([ "$AFTER" = "$BASE" ] && echo yes || echo no)"
T9=$(probe tcp $R2A 8081 dev=eth0); [ "$T9" -ge 1 ]; check $? "direct again after disconnect" "a connection bound to the physical interface put $T9 packet(s) on the wire"
if c ip link show vw0 >/dev/null 2>&1; then check 1 "device removed" "vw0 is still there"; else check 0 "device removed" "vw0 is gone"; fi
# 5. A clean stop over the other transport (looks like a website): everything goes back, the kill switch last.
BASE=$(snapshot)
connect tls ""
wait_for 60 connected; check $? "connect over the second transport" "$(c veilway status 2>&1 | sed -n '1p;2p' | tr '\n' ' ')"
OUT=$(tunnelled); [ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "http and dns, second transport" "curl said \"$OUT\""
blocked_probes "kill switch, second transport"
DIS=$(c veilway disconnect 2>&1); sleep 1
EXIT=$(exit_code); AFTER=$(snapshot); T9=$(probe tcp $R2A 8081 dev=eth0)
[ "$EXIT" = 0 ] && [ "$AFTER" = "$BASE" ] && [ "$T9" -ge 1 ]; check $? "clean disconnect" "connect exited $EXIT, the kill switch, rules and resolver are gone ($([ "$AFTER" = "$BASE" ] && echo as before || echo DIFFERENT)), a direct probe put $T9 packet(s) on the wire: $(echo $DIS | cut -c1-90)"
# 6. The client fails: the device is deleted under it. It must say so, exit non-zero, and leave the kill switch in force.
connect tls ""
wait_for 60 connected; q ip link del vw0; wait_for 20 exited
EXIT=$(exit_code); LOG=$(c cat /connect.log | grep -c "kill switch is still in force")
[ -n "$EXIT" ] && [ "$EXIT" != 0 ] && [ "$LOG" -ge 1 ]; check $? "a failure of the client exits non-zero and says the kill switch stays" "connect exited with ${EXIT:-nothing}, and said so $LOG time(s): $(c tail -n 1 /connect.log | cut -c1-170)"
c nft list table inet veilway_killswitch >/dev/null 2>&1; check $? "the kill switch stays after a failure" "the table is still in the kernel"
blocked_probes "kill switch after a failure of the client"
drop_blackholes; blocked_probes "kill switch alone after a failure of the client"
ST=$(c veilway status 2>&1); echo "$ST" | grep -q "kill switch is still in force"; check $? "status after a failure" "$(echo $ST | cut -c1-120)"
c veilway disconnect >/dev/null 2>&1; AFTER=$(snapshot); [ "$AFTER" = "$BASE" ]; check $? "disconnect after a failure" "everything is as before: $([ "$AFTER" = "$BASE" ] && echo yes || echo no)"
# 7. Two clients, and disconnect during a start. The path to the node is cut, so the first stays connecting with everything in force.
docker exec $P-r2 sh -c "nft add table ip gc && nft add chain ip gc cut '{ type filter hook forward priority 0; policy accept; }' && nft add rule ip gc cut ip saddr $CLIENT drop" || die "cannot cut the path on r2"
connect tls ""
wait_for 30 docker exec $P-client sh -c "nft list table inet veilway_killswitch && ip rule | grep -q 22103"
BEFORE=$(c sh -c "nft list table inet veilway_killswitch | grep -v packets; ip rule; ip route show table 22103")
SECOND=$(c sh -c "VEILWAY_RUN_DIR=/tmp/elsewhere veilway connect --profile obfs --data-dir /data 2>&1 < /dev/null | tail -n 2"); SECOND_EXIT=$(c sh -c "VEILWAY_RUN_DIR=/tmp/elsewhere veilway connect --profile obfs --data-dir /data >/dev/null 2>&1 < /dev/null; echo \$?")
AFTER=$(c sh -c "nft list table inet veilway_killswitch | grep -v packets; ip rule; ip route show table 22103")
[ "$SECOND_EXIT" != 0 ] && echo "$SECOND" | grep -q "runs already" && [ "$BEFORE" = "$AFTER" ]; check $? "a second client, with another run directory in the environment, is refused and touches nothing" "it said: $(echo $SECOND | cut -c1-150); what is in force is unchanged: $([ "$BEFORE" = "$AFTER" ] && echo yes || echo no)"
c veilway status | grep -q "^State: " ; check $? "status while the first client starts" "$(c veilway status 2>&1 | sed -n 2p | cut -c1-100)"
DIS=$(c veilway disconnect 2>&1); EXIT=$(exit_code); AFTER=$(snapshot)
[ "$EXIT" = 0 ] && [ "$AFTER" = "$BASE" ]; check $? "disconnect stops a client that is still connecting, the clean way" "connect exited $EXIT, everything is as before: $([ "$AFTER" = "$BASE" ] && echo yes || echo no): $(echo $DIS | cut -c1-80)"
docker exec $P-r2 nft delete table ip gc
# 8. A question waits on the terminal: the kill switch is in force meanwhile, and a no, or Ctrl-C, takes it away.
docker exec -i $P-client sh -c "cat > /prompt.sh" <<"EOF"
# prompt.sh ANSWER: connect with a new data directory, answer the two questions of the import, wait at the third (the private address), record what is in force, and answer.
rm -rf /data5 /in /prompt.exit /prompt.nft /prompt.rules; mkfifo /in
veilway connect /subscription-v4.vw --profile obfs --data-dir /data5 < /in > /prompt.log 2>&1 &
pid=$!
exec 3> /in
printf 'yes\nyes\n' >&3
n=0; until grep -q "private address" /prompt.log; do n=$((n + 1)); [ $n -lt 100 ] || break; sleep 0.2; done
nft list table inet veilway_killswitch > /prompt.nft 2>&1
ip rule > /prompt.rules
case "$1" in int) kill -INT $pid;; hup) kill -HUP $pid;; *) printf 'no\n' >&3;; esac
wait $pid; echo $? > /prompt.exit
EOF
for answer in no int; do
	c sh /prompt.sh $answer; EXIT=$(c cat /prompt.exit); AFTER=$(snapshot)
	c grep -q "veilway_killswitch" /prompt.nft; WAITING=$?
	[ $WAITING = 0 ] && [ "$EXIT" != 0 ] && [ "$AFTER" = "$BASE" ]; check $? "a question waits with the kill switch in force ($answer)" "while it waited the table was in force: $([ $WAITING = 0 ] && echo yes || echo no); the answer ended it with status $EXIT and everything is as before: $([ "$AFTER" = "$BASE" ] && echo yes || echo no); it said: $(c tail -n 1 /prompt.log | cut -c1-100)"
done
# 8b. The terminal goes away (SIGHUP): at a question and while connected. That is no stop: the kill switch stays, the client says so and exits non-zero, and `disconnect` is what lifts it.
c sh /prompt.sh hup; EXIT=$(c cat /prompt.exit)
c nft list table inet veilway_killswitch >/dev/null 2>&1; KEPT=$?
[ "$KEPT" = 0 ] && [ "$EXIT" != 0 ] && c tail -n 1 /prompt.log | grep -q "kill switch is still in force"; check $? "SIGHUP at a question keeps the kill switch" "the table is still in force: $([ $KEPT = 0 ] && echo yes || echo no); exit status $EXIT; it said: $(c tail -n 1 /prompt.log | cut -c1-110)"
c veilway disconnect >/dev/null 2>&1; AFTER=$(snapshot); [ "$AFTER" = "$BASE" ]; check $? "disconnect after a hang-up at a question" "everything is as before: $([ "$AFTER" = "$BASE" ] && echo yes || echo no)"
connect tls ""
wait_for 60 connected; q sh -c 'kill -HUP $(pidof veilway)'; wait_for 20 exited
EXIT=$(exit_code); c nft list table inet veilway_killswitch >/dev/null 2>&1; KEPT=$?
[ -n "$EXIT" ] && [ "$EXIT" != 0 ] && [ $KEPT = 0 ] && c grep -q "kill switch is still in force" /connect.log; check $? "SIGHUP while connected keeps the kill switch" "exit status ${EXIT:-none}; the table is still in force: $([ $KEPT = 0 ] && echo yes || echo no); it said: $(c tail -n 1 /connect.log | cut -c1-110)"
blocked_probes "kill switch after a hang-up"
c veilway disconnect >/dev/null 2>&1; AFTER=$(snapshot); [ "$AFTER" = "$BASE" ]; check $? "disconnect after a hang-up" "everything is as before: $([ "$AFTER" = "$BASE" ] && echo yes || echo no)"
# 9. A split tunnel: only the responder's network goes into the tunnel, the rest leaves as it always did.
connect obfs "" "--route $I.0/24"
wait_for 60 connected; check $? "split tunnel connects" "$(c veilway status 2>&1 | sed -n '4,5p' | tr '\n' ' ')"
OUT=$(c curl -sS --max-time 8 http://$RESP:8000/ 2>&1); [ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "split: the network in the tunnel" "curl $RESP:8000 said \"$OUT\""
T9=$(probe tcp $R2A 8081 dev=eth0); [ "$T9" -ge 1 ]; check $? "split: the rest leaves as it did" "a direct connection to $R2A put $T9 packet(s) on the wire"
OUT=$(tunnelled); [ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "split: names still go to the tunnel's resolver" "curl app.gate.test said \"$OUT\""
ST=$(c veilway status 2>&1); echo "$ST" | grep -q "Kill switch: on for $I.0/24 only" && ! echo "$ST" | grep -q "Nothing leaves this device"; check $? "split: the status does not promise a full kill switch" "$(echo "$ST" | grep 'Kill switch')"
c veilway disconnect >/dev/null 2>&1
# 10. The LAN let through, with a tunnelled network inside its ranges ($I.0/24 is in 172.16.0.0/12): that network stays in the tunnel, and names are not asked on the LAN.
connect obfs "" "--route $I.0/24 --allow-lan"
wait_for 60 connected; check $? "split with the LAN connects" "$(c veilway status 2>&1 | sed -n '4,6p' | tr '\n' ' ' | cut -c1-200)"
H=$(probe tcp $RESP 8000); OUT=$(c curl -sS --max-time 8 http://$RESP:8000/ 2>&1)
[ "$OUT" = "hello-from-responder src=$NODEI" ] && [ "$H" = 0 ]; check $? "a tunnelled network inside the LAN's ranges stays in the tunnel" "curl $RESP:8000 said \"$OUT\", and a bound probe put $H packet(s) on the wire"
L1=$(probe udp $R2A 5300); [ "$L1" -ge 1 ]; check $? "the LAN is let through" "a datagram to the witness $R2A put $L1 packet(s) on the wire"
D1=$(probe udp $R2A 53); D2=$(probe udp 224.0.0.251 5353); D3=$(probe udp 224.0.0.252 5355); D4=$(probe tcp $R2A 53); D5=$(probe tcp $R2A 853)
[ "$D1$D2$D3$D4$D5" = 00000 ]; check $? "names are not asked on the LAN, mDNS and LLMNR included" "packets on the wire: dns udp $D1, mDNS $D2, LLMNR $D3, dns tcp $D4, DNS over TLS $D5 (nft counters that moved: $(counters))"
c veilway disconnect >/dev/null 2>&1
connect obfs "" "--allow-lan --local-names"
wait_for 60 connected; check $? "connect with local names allowed" "$(c veilway status 2>&1 | sed -n '2p')"
D2=$(probe udp 224.0.0.251 5353); D3=$(probe udp 224.0.0.252 5355); D1=$(probe udp $R2A 53)
[ "$D2" -ge 1 ] && [ "$D3" -ge 1 ] && [ "$D1" = 0 ]; check $? "local names are let through only when asked" "mDNS $D2 and LLMNR $D3 packet(s) on the wire with --local-names, ordinary DNS still $D1"
c veilway disconnect >/dev/null 2>&1
# 11. A profile with no IPv6 address: IPv6 is refused and IPv4 works.
DATA=/data4
connect obfs /subscription-v4.vw
wait_for 60 connected; check $? "connect with an IPv4-only profile" "$(c veilway status 2>&1 | sed -n '1p;2p' | tr '\n' ' ')"
OUT=$(tunnelled); [ "$OUT" = "hello-from-responder src=$NODEI" ]; check $? "IPv4 works" "curl said \"$OUT\""
R6=$(c ip -6 route show table 22103 2>&1 | tr '\n' ';'); c curl -sS --max-time 4 -g "http://[fd93:1::20]:8000/" >/dev/null 2>&1; [ $? != 0 ]; check $? "IPv6 refused" "curl over IPv6 failed at once; the tunnel's IPv6 table: $R6"
c veilway disconnect >/dev/null 2>&1; sleep 1
# 12. The vault holds no plain secret, and its key is in root's key file, which survives a restart, and not in the kernel keyring (the default seccomp profile of Docker does not allow that).
V=/data/vault; HEAD=$(c head -c 4 $V); TAG=$(c od -An -tu1 -j4 -N1 $V | tr -d ' '); PLAIN=$(c sh -c "grep -c 'Gate provider\|transport_secrets\|inbound_public_key' $V"); KEYMODE=$(c stat -c '%a %U' /var/lib/veilway/vault.key)
[ "$HEAD" = VWV1 ] && [ "$PLAIN" = 0 ] && [ "$TAG" = 4 ] && [ "$KEYMODE" = "600 root" ]; check $? "encrypted vault" "the vault file starts with $HEAD, names the key file (tag $TAG), holds $PLAIN plain strings of the subscription ($(c stat -c '%a %s bytes' $V)), the key file is $KEYMODE"
echo "== $FAILS failed"
[ $FAILS = 0 ]
