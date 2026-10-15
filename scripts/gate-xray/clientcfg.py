"""A stock Xray client config from a vless://, trojan:// or ss:// link, as a local SOCKS proxy. Run by scripts/gate-xray.sh on the host.
usage: clientcfg.py LINK PORT [--wrong]   --wrong changes the id, as a user the node does not know would"""
import json, sys, urllib.parse

link, port = urllib.parse.urlsplit(sys.argv[1]), int(sys.argv[2])
query = dict(urllib.parse.parse_qsl(link.query))
uuid = link.username
if "--wrong" in sys.argv:
	uuid = "00000000-0000-4000-8000-" + uuid[-12:]
tls = {"network": query.get("type", "tcp"), "security": query.get("security", "tls"), "tlsSettings": {"serverName": query.get("sni", link.hostname)}}
if link.scheme == "trojan":
	outbound = {"protocol": "trojan", "settings": {"servers": [{"address": link.hostname, "port": link.port, "password": uuid}]}, "streamSettings": tls}
elif link.scheme == "ss":
	password = urllib.parse.unquote(link.password)
	outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": link.hostname, "port": link.port, "method": link.username, "password": password}]}}
else:
	outbound = {"protocol": "vless", "settings": {"vnext": [{"address": link.hostname, "port": link.port, "users": [{"id": uuid, "encryption": query.get("encryption", "none")}]}]}, "streamSettings": tls}
print(json.dumps({
	"log": {"loglevel": "warning"},
	"inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
	"outbounds": [outbound],
}))
