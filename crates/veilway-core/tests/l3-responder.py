"""The host on the other side of the kernel in tests/l3.rs, over IPv4 and IPv6: a greeting on TCP port 7000, an echo on UDP port 7001, and on UDP port 7003 the address a datagram came from.
Nothing listens on UDP port 7002, and the kernel of this host answers ping."""
import socket
import threading

GREETING = b"hello-from-responder"

def greet():
	listener = socket.create_server(("::", 7000), family=socket.AF_INET6, dualstack_ipv6=True)
	while True:
		connection, _ = listener.accept()
		with connection:
			connection.sendall(GREETING)

def answer(port, reply):
	sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
	sock.bind(("::", port))
	while True:
		datagram, sender = sock.recvfrom(2048)
		sock.sendto(reply(datagram, sender), sender)

threading.Thread(target=greet, daemon=True).start()
# An IPv4 sender shows on a socket of both families as an IPv4-mapped address.
threading.Thread(target=answer, args=(7003, lambda datagram, sender: b"from:" + sender[0].removeprefix("::ffff:").encode()), daemon=True).start()
answer(7001, lambda datagram, sender: b"echo:" + datagram)
