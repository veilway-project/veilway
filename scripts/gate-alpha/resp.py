"""The test web server and DNS server of scripts/gate-alpha.sh. HTTP on 8000 says who asked, and DNS on 53 knows app.gate.test. Both log who asked, so the gate can tell the node's address from the client's.
usage: resp.py ADDRESS-APP-TEST-RESOLVES-TO"""
import http.server, socket, struct, sys, threading

address = sys.argv[1]


class Handler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		body = ("hello-from-responder src=%s\n" % self.client_address[0]).encode()
		self.send_response(200)
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)
		print("http src=%s" % self.client_address[0], flush=True)

	def log_message(self, *args):
		pass


def dns():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(("0.0.0.0", 53))
	while True:
		query, who = sock.recvfrom(1500)
		try:
			i, labels = 12, []
			while query[i]:
				labels.append(query[i + 1:i + 1 + query[i]].decode().lower())
				i += query[i] + 1
			name, kind = ".".join(labels), struct.unpack("!H", query[i + 1:i + 3])[0]
			hit = name == "app.gate.test"
			answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton(address) if hit and kind == 1 else b""
			sock.sendto(query[:2] + struct.pack("!HHHHH", 0x8180 | (0 if hit else 3), 1, 1 if answer else 0, 0, 0) + query[12:i + 5] + answer, who)
			print("dns %s type=%d from=%s" % (name, kind, who[0]), flush=True)
		except (IndexError, UnicodeDecodeError, struct.error):
			pass


threading.Thread(target=dns, daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
