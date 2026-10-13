#!/bin/sh
# Front gate: the proxy path of a `ws` and `fronted` listener between real web servers. nginx stands in front of the node as the operator's web server, and behind the node the decoy origin is nginx in the first run and HAProxy in the second.
# A run is the test crates/veilway-core/tests/front.rs with a node inside the test process: requests of strangers through the front with the node behind it and with the origin itself behind it, the same requests handed to the node and to the origin directly,
# a device over `ws` and one over `fronted` through the front, and the origin giving up the quiet connections the node kept. The front hands everything to the node, speaks HTTP/1.1 to it, keeps connections to it, and adds the visitor's address at the right end of X-Forwarded-For.
# The origins answer / with a page, /none with 204, /same with 304 and everything else as a web server does, and give a quiet connection up after IDLE seconds.
# Everything runs in containers on one private Docker network. Nothing is built here: the test binary must already be in the volume named by VEILWAY_TARGET, veilway-target when it is not set
# (docker run --rm -v "$PWD":/w -v veilway-target:/w/target -v veilway-cargo:/usr/local/cargo -w /w rust:1 cargo test --locked -p veilway-core --test front --no-run).
# The two servers get half a CPU and 256 MB each, and the container of the test 2 CPUs and 2 GB. Takes no argument. Exit status 0 only when both runs passed.
set -u
P=veilway-gate-front
VOLUME=${VEILWAY_TARGET:-veilway-target}
SUBNET=172.30.73
ORIGIN=$SUBNET.10; FRONT=$SUBNET.11; NODE=$SUBNET.12
IDLE=2
FAILS=0
cleanup(){ docker rm -f $P-front $P-origin $P-run >/dev/null 2>&1; docker network rm $P-net >/dev/null 2>&1; return 0; }
die(){ echo "SETUP FAILED: $1"; exit 2; }
server(){ docker rm -f $P-$1 >/dev/null 2>&1; docker run -d --name $P-$1 --network $P-net --ip $2 --cpus 0.5 --memory 256m $3 sleep infinity >/dev/null || die "the $1 container ($3)"; }
front(){
	server front $FRONT nginx:alpine
	docker exec -i $P-front sh -c "cat > /etc/nginx/nginx.conf" <<EOF
worker_processes 1;
events {worker_connections 256;}
http {
	access_log off;
	map \$http_upgrade \$connection_upgrade {default upgrade; "" "";}
	upstream node {server $NODE:8443; keepalive 4;}
	upstream origin {server $ORIGIN:8080; keepalive 4;}
	proxy_http_version 1.1;
	proxy_set_header Host \$host;
	proxy_set_header Upgrade \$http_upgrade;
	proxy_set_header Connection \$connection_upgrade;
	proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
	proxy_buffering off;
	server {listen 8080; location / {proxy_pass http://node;}}
	server {listen 8081; location / {proxy_pass http://origin;}}
}
EOF
	docker exec $P-front nginx -t -q && docker exec $P-front nginx || die "nginx in front did not start"
}
run(){ # what the origin is
	front
	echo "== $1 behind the node, nginx in front"
	docker run --rm --init --name $P-run --network $P-net --ip $NODE --cpus 2 --memory 2g -v "$VOLUME":/t:ro -e VEILWAY_TEST_FRONT=1 -e VEILWAY_TEST_FRONT_NODE=$NODE:8443 -e VEILWAY_TEST_FRONT_VIA=$FRONT:8080 -e VEILWAY_TEST_FRONT_BARE=$FRONT:8081 -e VEILWAY_TEST_FRONT_ORIGIN=$ORIGIN:8080 -e VEILWAY_TEST_FRONT_IDLE=$IDLE rust:1 timeout 300 "$BIN" --nocapture --test-threads 1
	if [ $? = 0 ]; then echo "PASS  $1 as the origin"; else echo "FAIL  $1 as the origin"; FAILS=$((FAILS + 1)); fi
}
cleanup; trap cleanup EXIT
BIN=$(docker run --rm --cpus 0.5 --memory 256m -v "$VOLUME":/t:ro rust:1 sh -c "ls -t /t/debug/deps/front-* 2>/dev/null | grep -v '[.]d\$' | head -n 1")
[ -n "$BIN" ] || { echo "SETUP FAILED: no test binary in the volume $VOLUME (debug/deps/front-*). Build it first, see the header of this script."; exit 2; }
docker network create --subnet $SUBNET.0/24 $P-net >/dev/null || die "cannot create the network $P-net ($SUBNET.0/24)"
server origin $ORIGIN nginx:alpine
docker exec -i $P-origin sh -c "cat > /etc/nginx/nginx.conf" <<EOF
worker_processes 1;
events {worker_connections 256;}
http {
	access_log off;
	keepalive_timeout ${IDLE}s;
	server {
		listen 8080;
		root /usr/share/nginx/html;
		location = /none {return 204;}
		location = /same {return 304;}
	}
}
EOF
docker exec $P-origin nginx -t -q && docker exec $P-origin nginx || die "nginx as the origin did not start"
run nginx
server origin $ORIGIN haproxy:lts-alpine
docker exec -i $P-origin sh -c "cat > /tmp/haproxy.cfg" <<EOF
global
	maxconn 256
defaults
	mode http
	timeout connect 2s
	timeout client 30s
	timeout server 30s
	timeout http-request 5s
	timeout http-keep-alive ${IDLE}s
frontend site
	bind :8080
	http-request return status 204 if { path /none }
	http-request return status 304 if { path /same }
	http-request return status 200 content-type text/html string "<html>the operator's own site</html>" if { path / }
	http-request return status 404 content-type text/plain string "nothing here"
EOF
docker exec $P-origin haproxy -c -q -f /tmp/haproxy.cfg || die "the HAProxy config was refused"
docker exec -d $P-origin haproxy -f /tmp/haproxy.cfg
sleep 1
run HAProxy
if [ $FAILS -gt 0 ]; then echo "GATE FAILED: $FAILS run(s)"; exit 1; fi
echo "GATE PASSED: both runs"
