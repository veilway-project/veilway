#!/bin/sh
# Starts a node from the release binary at $VEILWAY_BIN with a throwaway config, runs the test against its socket and stops the node.
# Needs node 20 or later and npm dependencies installed. The keys are made here and live only in a temporary directory.
set -eu
bin="${VEILWAY_BIN:-veilway}"
dir="$(mktemp -d)"
trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "$dir"' EXIT
server="$("$bin" genkey | sed -n 1p | awk '{print $NF}')"
device="$("$bin" genkey | sed -n 2p | awk '{print $NF}')"
native="$("$bin" genkey | sed -n 1p | awk '{print $NF}')"
secret="$("$bin" gensecret)"
umask 077
# The second inbound has a udp-obfs transport, so the node keeps a replay memory, which a test resets. Its replay file is made next to the config.
printf '{"version": 1, "dns": {"servers": ["1.1.1.1:53"], "hijack": true}, "inbounds": [{"tag": "in", "type": "wireguard", "private_key": "%s", "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "127.0.0.1:51820"}]}, {"tag": "native", "type": "veilway", "private_key": "%s", "address": ["10.8.0.1/24"], "transports": [{"type": "udp-obfs", "listen": "127.0.0.1:51821"}]}], "outbounds": [{"tag": "plain", "type": "direct"}], "exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}], "routing": {"default": "main", "rules": []}, "users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": "%s", "transport_secrets": ["%s"], "addresses": ["10.7.0.2", "10.8.0.2"]}]}]}\n' "$server" "$native" "$device" "$secret" > "$dir/config.json"
"$bin" check --config "$dir/config.json"
"$bin" run --config "$dir/config.json" --api "$dir/api.sock" > "$dir/node.log" 2>&1 &
pid=$!
for _ in $(seq 50); do [ -S "$dir/api.sock" ] && break; sleep 0.2; done
[ -S "$dir/api.sock" ] || { cat "$dir/node.log"; exit 1; }
# The command line talks to the same socket.
"$bin" usage reset --api "$dir/api.sock" --user alice --totals
VEILWAY_API_SOCKET="$dir/api.sock" npm test
