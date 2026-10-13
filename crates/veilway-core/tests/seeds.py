"""Writes the seed corpus of the `state` fuzz target, `fuzz/corpus/state`. Run from the repository root: python3 crates/veilway-core/tests/seeds.py

The first byte of a seed picks what the rest is, as the head of `fuzz/fuzz_targets/state.rs` says. Every address is a documentation or tunnel address and every key a fixed pattern. `tests/seeds.rs` fails when a seed no longer reads as its name says."""
import base64, json, os, struct

OUT = "fuzz/corpus/state"

def v4(total, flags=0, ihl=5):
    options = b"\x01" * ((ihl - 5) * 4)
    head = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 0x1234, flags, 64, 17, 0, bytes([93, 184, 216, 34]), bytes([10, 7, 0, 2])) + options
    body = total - len(head)
    return head + struct.pack("!HHHH", 9000, 40000, body, 0) + bytes(i & 0xff for i in range(body - 8))

def v6(total, first=17):
    body = total - 40
    return struct.pack("!IHBB16s16s", 0x60000000, body, first, 64, b"\x20" * 16, b"\xfd" * 16) + struct.pack("!HHHH", 9000, 40000, body, 0) + bytes(i & 0xff for i in range(body - 8))

ENTRY = {"used_bytes": 7, "period_start": 5, "up_bytes": 4, "up_packets": 1, "down_bytes": 3, "down_packets": 1}
SEEDS = {
    # Forwarded IPv4 that may and may not be fragmented, then packets the node sends itself: plain, with options, and one that is a fragment already.
    "v4-forwarded": b"\x01" + v4(1400),
    "v4-forwarded-df": b"\x01" + v4(1400, 0x4000),
    "v4-sent": b"\x03" + v4(4000),
    "v4-sent-options": b"\x03" + v4(1500, 0, 7),
    "v4-sent-fragment": b"\x03" + v4(1400, 0x2000),
    "v4-sent-fits": b"\x03" + v4(256),
    "v4-sent-largest-mtu": b"\xff" + v4(2000),
    # IPv6 that is forwarded, sent, and sent with a header that belongs before a fragment header.
    "v6-forwarded": b"\x01" + v6(1400),
    "v6-sent": b"\x03" + v6(4000),
    "v6-sent-hop-by-hop": b"\x03" + v6(1400, 0),
    "v6-sent-largest-mtu": b"\xff" + v6(2000),
    # State files: users and a device's exit, and one whose counts and entries are not to be trusted.
    "state-devices": b"\x00" + json.dumps({"version": 1, "users": {"a": ENTRY}, "devices": {base64.b64encode(b"\x21" * 32).decode(): {"exit": "alt"}}}).encode(),
    "state-untrusted": b"\x00" + json.dumps({"version": 1, "users": {"a": dict(ENTRY, used_bytes=2**64 - 1, period_start=-5), "b": 0}, "devices": {"no key": {"exit": "alt"}, base64.b64encode(b"\x22" * 32).decode(): {"exit": "USER"}}}).encode(),
}
os.makedirs(OUT, exist_ok=True)
for name, data in SEEDS.items():
    open(os.path.join(OUT, name), "wb").write(data)
