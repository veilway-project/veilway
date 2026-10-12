"""The host on the other side of the kernel in tests/l3.rs: a greeting on TCP port 7000 and an echo on UDP port 7001. Nothing listens on UDP port 7002, and the kernel of this host answers ping."""
import socket
import threading

GREETING = b"hello-from-responder"

def greet():
	listener = socket.create_server(("0.0.0.0", 7000))
	while True:
		connection, _ = listener.accept()
		with connection:
			connection.sendall(GREETING)

def echo():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(("0.0.0.0", 7001))
	while True:
		datagram, sender = sock.recvfrom(2048)
		sock.sendto(b"echo:" + datagram, sender)

threading.Thread(target=greet, daemon=True).start()
echo()
