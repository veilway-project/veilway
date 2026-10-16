"""A UDP echo server for scripts/gate-xray.sh, on port 7007. It logs who sent each datagram, so the gate can tell the node's address from the client's."""
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 7007))
while True:
	data, who = sock.recvfrom(65535)
	sock.sendto(data, who)
	print("echo src=%s" % who[0], flush=True)
