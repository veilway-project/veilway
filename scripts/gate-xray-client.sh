#!/bin/sh
# The client gate for legacy profiles ("Xray in the desktop apps", Tests and the gate): `veilway connect <link>` on a client container, with the pinned Xray-core as the client's add-on and the same release as the server. WRITTEN, NOT RUN: no part of it has been tried on a machine yet, expect to fix the first run.
# For each of VLESS over TLS, VLESS over Reality, VMess, Trojan over ws, Shadowsocks over tcp, and VLESS over grpc: a TCP fetch from a web server and a UDP echo, both through the tunnel, and a DNS query that reaches the resolver only through Xray. Then, on the first profile: a capture on the client's physical interface shows only the server's address and port, a ping of the gateway is answered and a ping of the web server is dropped and counted, `kill -9` of Xray leaves a window in which the capture is still clean and flows come back after the restart, a changed byte in the executable is refused and logged, a process of another user that connects to the SOCKS port without the login is refused, and the listening sockets of Xray's process are only the loopback SOCKS port.
# Not here, because the client downloads from github.com only and the gate has no way to stand in for it: an archive of another hash (the unit tests of `veilway/src/xray.rs` hold that), and the add-on's removal.
# One container is the server: Xray as the server of every profile, and the web server, the UDP echo and a DNS echo on addresses of its loopback device that stand for the internet (203.0.113.80 and 1.1.1.1). The other is the client. Both are on one Docker network, and the client reaches the server's own address only. A test CA signs the server certificate and is in the client's trust store, since the client always checks the chain.
# Needs the veilway binary built in the volume veilway-target-usage (cargo build -p veilway --bin veilway, CARGO_TARGET_DIR=/w/target/linux-client, as gate-client.sh), and the Xray-core release archive in the volume veilway-alpha-rel (gate-xray.sh puts it there). KEEP=1 keeps the containers. Exit status 0 only when every check passed.
set -u
P=veilway-gx
NET=172.31.95
SERVER=$NET.10; CLIENT=$NET.40
WEB=203.0.113.80; RESOLVER=1.1.1.1; GATEWAY=198.18.0.1
XRAY=v26.3.27
VOL=veilway-target-usage; REL=veilway-alpha-rel
BIN=/t/linux-client/debug
FAILS=0
cleanup(){ docker rm -f $P-server $P-client >/dev/null 2>&1; docker network rm $P-net >/dev/null 2>&1; return 0; }
die(){ echo "SETUP FAILED: $1"; exit 2; }
check(){ if [ "$1" = 0 ]; then echo "PASS  $2: $3"; else echo "FAIL  $2: $3"; FAILS=$((FAILS + 1)); fi; }
c(){ docker exec $P-client "$@"; }
s(){ docker exec $P-server "$@"; }
wait_for(){ n=$1; shift; while [ $n -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; n=$((n - 1)); done; return 1; }
connected(){ c veilway status 2>/dev/null | grep -q "^State: Connected"; }
fetch(){ c curl -sS --max-time 8 http://$WEB:8000/ 2>&1; }
# The UDP echo and the DNS echo both answer with what they were sent.
udp_echo(){ c python3 -c "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b'hello', ('$1', $2)); print(s.recvfrom(100)[0].decode())" 2>&1; }
# Packets of the capture on the client's physical interface that are not to or from the server: ARP and the container network's own chatter are not IP, so only IP counts.
strays(){ c sh -c "tcpdump -nr /eth0.pcap ip 2>/dev/null | grep -v '$SERVER' | wc -l" | tr -d ' \r'; }
capture(){ c sh -c 'rm -f /eth0.pcap'; docker exec -d $P-client sh -c 'tcpdump -i eth0 -n -U -w /eth0.pcap ip >/dev/null 2>&1'; sleep 1; }
stop_capture(){ c sh -c 'kill $(pidof tcpdump)' >/dev/null 2>&1; sleep 1; }
# connect LINK: the link goes in a file only root can read (the command line is refused), and yes to everything it asks, the way a person at a terminal would type.
connect(){ docker exec -d $P-client sh -c "rm -f /connect.exit; (umask 077; printf '%s' '$1' >/link); yes yes | veilway connect /link >/connect.log 2>&1; echo \$? >/connect.exit"; }
disconnect(){ c veilway disconnect >/dev/null 2>&1; wait_for 20 c sh -c 'test -s /connect.exit'; }
cleanup; trap '[ -n "${KEEP:-}" ] || cleanup' EXIT
docker run --rm -v $VOL:/t:ro rust:1 test -x $BIN/veilway || die "no veilway binary in the volume $VOL (see the header of this script)"
case "$(docker run --rm alpine:3.22 uname -m)" in x86_64) XARCH=linux-64 ;; *) XARCH=linux-arm64-v8a ;; esac
docker run --rm -v $REL:/rel:ro alpine:3.22 test -s /rel/Xray-$XARCH.zip || die "no Xray archive in the volume $REL (run scripts/gate-xray.sh once)"
docker network create --subnet $NET.0/24 $P-net >/dev/null || die "network"
docker run -d --name $P-server --network $P-net --ip $SERVER --cpus 1 --memory 512m --cap-add NET_ADMIN -v $REL:/rel:ro python:3-slim sleep infinity >/dev/null || die "server container"
docker run -d --name $P-client --network $P-net --ip $CLIENT --cpus 1 --memory 512m --cap-add NET_ADMIN --device /dev/net/tun -v $VOL:/t:ro -v $REL:/rel:ro rust:1 sleep infinity >/dev/null || die "client container"
(docker exec $P-client sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iproute2 nftables curl tcpdump procps python3 openssl iputils-ping >/dev/null 2>&1 && ln -sf $BIN/veilway /usr/local/bin/veilway") || die "client packages"
s sh -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iproute2 openssl >/dev/null 2>&1" || die "server packages"
# The pinned Xray, from the archive: the server runs it, and the client has the very file the pin names in the add-on folder (the client's own download needs github.com).
for x in server client; do docker exec $P-$x python3 -I -c "import zipfile; zipfile.ZipFile('/rel/Xray-$XARCH.zip').extract('xray', '/opt')" 2>/dev/null || docker exec $P-$x sh -c "apt-get install -y -qq python3 >/dev/null 2>&1 && python3 -I -c \"import zipfile; zipfile.ZipFile('/rel/Xray-$XARCH.zip').extract('xray', '/opt')\"" || die "unpacking Xray in $x"; done
c sh -c "mkdir -p /var/lib/veilway/client/addons/xray/$XRAY && install -m 755 -o root -g root /opt/xray /var/lib/veilway/client/addons/xray/$XRAY/xray && chmod 700 /var/lib/veilway /var/lib/veilway/client"
# The test CA, the server's certificate for node.gate.test, and the CA in the client's trust store.
s sh -c "mkdir -p /gx && cd /gx && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=gate-ca >/dev/null 2>&1 && openssl req -newkey rsa:2048 -nodes -keyout node.key -out node.csr -subj /CN=node.gate.test >/dev/null 2>&1 && printf 'subjectAltName=DNS:node.gate.test' >ext && openssl x509 -req -in node.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out node.pem -days 2 -extfile ext >/dev/null 2>&1" || die "certificates"
docker cp $P-server:/gx/ca.pem /tmp/$P-ca.pem && docker cp /tmp/$P-ca.pem $P-client:/usr/local/share/ca-certificates/gate-ca.crt && c update-ca-certificates >/dev/null 2>&1 || die "trusting the test CA"
c sh -c "echo '$SERVER node.gate.test' >>/etc/hosts"
# The services that stand for the internet, on loopback addresses of the server.
s sh -c "ip addr add $WEB/32 dev lo && ip addr add $RESOLVER/32 dev lo" || die "addresses of the server's loopback"
docker exec -i $P-server sh -c "cat > /gx/services.py" <<"EOF"
import http.server, socket, socketserver, struct, sys, threading
web, resolver = sys.argv[1], sys.argv[2]
class Web(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		body = b"gate web ok"
		self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
	def log_message(self, *a): pass
def udp(address):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(address)
	while True:
		data, who = s.recvfrom(4096); s.sendto(data, who)
class Dns(socketserver.StreamRequestHandler):
	def handle(self):
		while True:
			head = self.rfile.read(2)
			if len(head) < 2: return
			body = self.rfile.read(struct.unpack(">H", head)[0]); self.wfile.write(head + body)
class Tcp(socketserver.ThreadingTCPServer): allow_reuse_address = True
for target, args in ((udp, ((web, 5000),)), (udp, ((resolver, 53),)), (Tcp((resolver, 53), Dns).serve_forever, ()), (http.server.ThreadingHTTPServer((web, 8000), Web).serve_forever, ())):
	threading.Thread(target=target, args=args, daemon=True).start()
threading.Event().wait()
EOF
docker exec -d $P-server python3 -I /gx/services.py $WEB $RESOLVER
# Xray as the server of every profile. Reality needs a key pair, which the pinned binary makes.
ID=2f5d3b0e-6d0a-4f1d-9e4c-7a2b1c9d8e01; PASS=gatepassword
KEYS=$(s /opt/xray x25519 2>&1); PRIV=$(echo "$KEYS" | sed -n 's/^PrivateKey: *//p;s/^Private key: *//p' | head -1); PUB=$(echo "$KEYS" | sed -n 's/^Password.*: *//p;s/^PublicKey: *//p;s/^Public key: *//p' | head -1)
[ -n "$PRIV" ] && [ -n "$PUB" ] || die "no Reality keys from the pinned Xray"
SS_KEY=$(python3 -c "import base64; print(base64.b64encode(b'0123456789abcdef').decode())")
tls() { printf '"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/gx/node.pem","keyFile":"/gx/node.key"}]}'; }
docker exec -i $P-server sh -c "cat > /gx/server.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[
{"port":8001,"protocol":"vless","settings":{"clients":[{"id":"$ID"}],"decryption":"none"},"streamSettings":{"network":"tcp",$(tls)}},
{"port":8002,"protocol":"vless","settings":{"clients":[{"id":"$ID"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:8001","serverNames":["node.gate.test"],"privateKey":"$PRIV","shortIds":["0a1b"]}}},
{"port":8003,"protocol":"vmess","settings":{"clients":[{"id":"$ID"}]},"streamSettings":{"network":"tcp"}},
{"port":8004,"protocol":"trojan","settings":{"clients":[{"password":"$PASS"}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/ws"},$(tls)}},
{"port":8005,"protocol":"shadowsocks","settings":{"method":"aes-128-gcm","password":"$SS_KEY","network":"tcp,udp"}},
{"port":8006,"protocol":"vless","settings":{"clients":[{"id":"$ID"}],"decryption":"none"},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"gate"},$(tls)}}],
"outbounds":[{"protocol":"freedom"}]}
EOF
docker exec -d $P-server /opt/xray run -config /gx/server.json
wait_for 10 s sh -c 'ss -Hltn | grep -q ":8006"' || die "the server's Xray did not listen"
SS_USER=$(printf 'aes-128-gcm:%s' "$SS_KEY" | base64 | tr -d '=\n')
# profile NAME LINK: connects, carries a TCP fetch, a UDP echo and a DNS query, and disconnects.
carried(){
	name=$1; link=$2
	connect "$link"
	wait_for 40 connected; check $? "$name connects" "$(c head -c 300 /connect.log | tr '\n' ' ')"
	out=$(fetch); [ "$out" = "gate web ok" ]; check $? "$name TCP fetch through the tunnel" "$out"
	out=$(udp_echo $WEB 5000); [ "$out" = "hello" ]; check $? "$name UDP echo through the tunnel" "$out"
	out=$(c python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b'dnsquery', ('$GATEWAY', 53)); print(s.recvfrom(100)[0].decode())" 2>&1); [ "$out" = "dnsquery" ]; check $? "$name DNS query to the gateway reaches the resolver" "$out"
	[ "$name" = "$FIRST" ] || { disconnect; return 0; }
}
FIRST="vless tls"
VL="vless://$ID@node.gate.test:8001?security=tls&sni=node.gate.test&type=tcp#a"
carried "vless tls" "$VL"
# The checks that need a connection are made on the first profile, while it is up.
capture; fetch >/dev/null; udp_echo $WEB 5000 >/dev/null; sleep 2; stop_capture
n=$(strays); [ "$n" = 0 ]; check $? "only the server's address on the physical interface" "$n packets to or from anything else"
out=$(c ping -c 1 -W 3 $GATEWAY 2>&1); echo "$out" | grep -q "1 received"; check $? "a ping of the gateway is answered" ""
out=$(c ping -c 1 -W 2 $WEB 2>&1); echo "$out" | grep -q "0 received"; check $? "a ping of the web server is dropped" ""
sleep 2; c veilway status | grep -q "Not carried: [1-9][0-9]* packets"; check $? "the dropped ping is counted in the status" "$(c veilway status | grep 'Not carried')"
capture; c pkill -9 -u veilway-xray; sleep 1; probe=$(c curl -sS --max-time 4 http://$WEB:8000/ 2>&1); [ "$probe" != "gate web ok" ]; check $? "nothing is carried while Xray is down" "$probe"
n=$(c sh -c "tcpdump -nr /eth0.pcap ip 2>/dev/null | grep -v '$SERVER' | wc -l" | tr -d ' \r'); [ "$n" = 0 ]; check $? "nothing leaves the physical interface while Xray is down" "$n stray packets"
stop_capture
wait_for 30 sh -c "docker exec $P-client curl -sS --max-time 4 http://$WEB:8000/ | grep -q 'gate web ok'"; check $? "flows come back after the restart" "$(c veilway status | grep 'Add-on restarts')"
pid=$(c pgrep -u veilway-xray | head -1)
listening=$(c sh -c "ss -Hlntup | grep 'pid=$pid,' | awk '{print \$5}' | sort -u | tr '\n' ' '"); echo "$listening" | grep -Eq '^127\.0\.0\.1:[0-9]+ $'; check $? "Xray listens only on the loopback SOCKS port" "$listening"
port=$(echo "$listening" | sed 's/.*://;s/ //g')
out=$(c su -s /bin/sh nobody -c "python3 -c \"import socket; s=socket.create_connection(('127.0.0.1', $port), 5); s.sendall(bytes([5, 1, 0])); print(list(s.recv(2)))\"" 2>&1); [ "$out" = "[5, 255]" ]; check $? "a process of another user without the login is refused" "$out"
disconnect
n=$(c sh -c 'nft list tables | grep -c veilway'); [ "$n" = 0 ]; check $? "everything is removed on disconnect" "$(c nft list tables | tr '\n' ' ')"
# A changed byte in the executable is refused and logged.
c sh -c "printf x >>/var/lib/veilway/client/addons/xray/$XRAY/xray"
connect "$VL"; sleep 6
grep_out=$(c cat /connect.log); echo "$grep_out" | grep -q "xray_mismatch"; check $? "a changed executable is refused" "$(echo "$grep_out" | tail -2 | tr '\n' ' ')"
c sh -c "head -c -1 /var/lib/veilway/client/addons/xray/$XRAY/xray >/xray.fixed && install -m 755 /xray.fixed /var/lib/veilway/client/addons/xray/$XRAY/xray"
carried "vless reality" "vless://$ID@node.gate.test:8002?security=reality&sni=node.gate.test&pbk=$PUB&sid=0a1b&fp=chrome&type=tcp#b"
carried "vmess" "vmess://$(printf '{"v":"2","ps":"c","add":"node.gate.test","port":"8003","id":"%s","aid":"0","scy":"aes-128-gcm","net":"tcp","tls":""}' $ID | base64 | tr -d '\n')"
carried "trojan ws" "trojan://$PASS@node.gate.test:8004?security=tls&sni=node.gate.test&type=ws&path=%2Fws#d"
carried "shadowsocks" "ss://$SS_USER@node.gate.test:8005#e"
carried "vless grpc" "vless://$ID@node.gate.test:8006?security=tls&sni=node.gate.test&type=grpc&serviceName=gate#f"
echo; [ $FAILS = 0 ] && echo "ALL CHECKS PASSED" || echo "$FAILS CHECK(S) FAILED"
[ $FAILS = 0 ]
