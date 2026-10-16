"""A SOCKS5 UDP client for scripts/gate-xray.sh, run in the client container against the local SOCKS port of a stock Xray client.
usage: udp.py PORT echo HOST PORT        sends random bytes to a UDP echo server and expects them back
       udp.py PORT dns HOST PORT NAME    asks a DNS server for the A record of NAME and prints the address
Prints "ok ..." and exits 0 on an answer, prints "no answer" and exits 1 when none came. TRIES and WAIT (seconds) in the environment say how long to wait."""
import os, random, socket, struct, sys

port, mode, host, dport = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
tries, wait = int(os.environ.get("TRIES", "3")), float(os.environ.get("WAIT", "4"))


def take(sock, n):
	data = b""
	while len(data) < n:
		chunk = sock.recv(n - len(data))
		if not chunk:
			raise ConnectionError("closed")
		data += chunk
	return data


control = socket.create_connection(("127.0.0.1", port), 5)
control.sendall(b"\x05\x01\x00")
assert take(control, 2) == b"\x05\x00", "the proxy wants a login"
control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
head = take(control, 10)
assert head[1] == 0, "the proxy refused UDP ASSOCIATE"
relay = (socket.inet_ntoa(head[4:8]) if head[4:8] != b"\x00" * 4 else "127.0.0.1", struct.unpack("!H", head[8:10])[0])
if mode == "dns":
	ident = random.getrandbits(16)
	labels = b"".join(bytes([len(label)]) + label.encode() for label in sys.argv[5].split("."))
	payload = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"
else:
	payload = os.urandom(32)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(wait)
for _ in range(tries):
	sock.sendto(b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", dport) + payload, relay)
	try:
		data, _ = sock.recvfrom(65535)
	except socket.timeout:
		continue
	body = data[10:]
	if mode == "echo" and body == payload:
		print("ok echo")
		sys.exit(0)
	if mode == "dns" and body[:2] == payload[:2] and body[2] & 0x80 and body[3] & 0x0f == 0 and body[-4:]:
		print("ok " + socket.inet_ntoa(body[-4:]))
		sys.exit(0)
	print("unexpected answer %r" % body[:40])
	sys.exit(1)
print("no answer")
sys.exit(1)
