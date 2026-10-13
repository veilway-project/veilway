# Where the expected bytes in this crate's tests come from: HKDF and HMAC from Python's standard library, and ChaCha20-Poly1305 written out from RFC 8439, each checked against a published vector before it is used. Nothing here shares code with the crate.
# Prints the vectors. With a directory as its argument it also writes the seed corpus of the fuzz targets there:
#   docker run --rm -v "$PWD":/w -w /w python:3 python -I crates/veilway-proto/tests/vectors.py fuzz/corpus
import hmac, hashlib, struct, sys, os

def extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def expand(prk, info, n):
    out, block, i = b"", b"", 1
    while len(out) < n:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:n]
def rotl(v, c): return ((v << c) & 0xffffffff) | (v >> (32 - c))
def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)
def block(key, counter, nonce):
    init = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    s = init[:]
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(s, init)])
def xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)
def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")
def pad16(b): return b"\x00" * (-len(b) % 16)
def seal(key, nonce, aad, pt):
    otk = block(key, 0, nonce)[:32]
    ct = xor(key, 1, nonce, pt)
    return ct + poly1305(otk, aad + pad16(aad) + ct + pad16(ct) + struct.pack("<QQ", len(aad), len(ct)))
def h(text): return bytes.fromhex(text.replace(" ", ""))

# Self checks against published vectors: RFC 8439 section 2.8.2 and RFC 5869 test case 1.
rfc = seal(bytes(range(0x80, 0xa0)), h("070000004041424344454647"), h("50515253c0c1c2c3c4c5c6c7"), b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
assert rfc[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691" and rfc[:8].hex() == "d31a8d34648e60db", rfc.hex()
assert expand(extract(bytes(range(13)), b"\x0b" * 22), bytes(range(0xf0, 0xfa)), 42).hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

secret, inbound, device = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
prk = extract(b"veilway v1 device secret\0", secret)
k_ctl = expand(prk, b"veilway v1 control\0" + inbound + device, 32)
preface = h("00565743544c0000")
hello = h("00220101") + b"\xc1" * 32
reply = h("00228101") + b"\x4e" * 32
transcript = b"veilway v1 control auth\0" + preface + hello + reply
client_mac = hmac.new(k_ctl, b"\x01" + transcript, hashlib.sha256).digest()
node_mac = hmac.new(k_ctl, b"\x02" + transcript, hashlib.sha256).digest()
print("k_ctl", k_ctl.hex())
print("mac_of_abc", hmac.new(k_ctl, b"abc", hashlib.sha256).hexdigest())
print("client_mac", client_mac.hex())
print("node_mac", node_mac.hex())
key = bytes(range(32))
item1, item2 = bytes([4, 0, 0, 0]) + bytes(range(28)), bytes(range(100, 148))
plain0 = struct.pack(">H", len(item1)) + item1 + struct.pack(">H", len(item2)) + item2 + b"\x00" * 15
chunk0 = seal(key, b"\x00" * 4 + struct.pack("<Q", 0), b"", plain0)
chunk1 = seal(key, b"\x00" * 4 + struct.pack("<Q", 1), b"", b"\x00" * 5)
chunk_high = seal(key, b"\x00" * 4 + struct.pack("<Q", 0x0102030405060708), b"", b"\x00\x20" + item1 + b"\x00" * 7)
print("chunk0", len(chunk0), chunk0.hex())
print("chunk1", len(chunk1), chunk1.hex())
print("chunk_high", len(chunk_high), chunk_high.hex())
if len(sys.argv) > 1:
    root = sys.argv[1]
    auth = h("002102") + client_mac
    requests = h("000110 000411026465 000112 00061303056e9c40 0003140500 00021100")
    snapshot = h("003890000000006553f100056e02040a070002040a07000106fd00000000000000000000000000000206fd000000000000000000000000000001 00129101010264650006426572 6c696e44450b02 0032930102030405060708000000000000000003000000006553f10000000000000000000000000000000002000000000000000300079401010002686900069502 00010203")
    answers = h("00059200026465 000b96a0a1a2a3a4a5a6a7056e 00049703056e 0003980500 00039f0111 00029901")
    # The first bytes of each seed are what its fuzz target reads as its settings, see the head of each file in fuzz/fuzz_targets.
    files = {
        "chunk/plain-two-items": b"\x00" + plain0,
        "chunk/plain-padding-only": b"\x00" + b"\x00" * 5,
        "chunk/plain-item-too-short": b"\x00" + h("001f") + b"\x07" * 31,
        "chunk/plain-length-past-end": b"\x00" + h("0040") + b"\x07" * 40,
        "chunk/plain-length-over-limit": b"\x00" + h("0641") + b"\x07" * 1601,
        "chunk/sealed-two-items": b"\x01" + chunk0,
        "chunk/items-to-seal": b"\x02" + h("0020") + item1 + h("0030") + item2,
        "chunk/items-one-too-short": b"\x06" + h("0020") + item1 + h("0003aabbcc"),
        "chunk/written-two-items": b"\x03" + plain0,
        "control_stream/client-requests": b"\x06" + requests,
        "control_stream/node-snapshot": b"\x05" + snapshot,
        "control_stream/node-answers": b"\x07" + answers,
        "fuzz_control_server/opens-then-requests": h("00 00 00 00 00 01 01 07") + requests,
        "fuzz_control_server/second-key-in-pieces": h("00 09 01 00 00 02 03 21") + requests,
        "fuzz_control_server/wrong-secret": h("00 00 02 00 00 01 01 07"),
        "fuzz_control_server/changed-hello": h("00 00 00 0b 01 01 01 07"),
        "fuzz_control_server/changed-mac": h("00 00 00 40 80 01 01 07"),
        "fuzz_control_server/late-auth": h("00 00 00 00 00 64 64 07"),
        "fuzz_control_server/raw-opening": b"\x01\x09" + preface + hello + auth,
        "fuzz_control_server/raw-version-zero": b"\x01\x00" + preface + h("00220100") + b"\xc1" * 32,
        "fuzz_control_server/raw-auth-first": b"\x01\x00" + preface + auth,
        "fuzz_control_server/raw-http": b"\x01\x00GET / HTTP/1.1\r\nHost: gateway\r\n\r\n",
        "fuzz_control_client/opens-then-snapshot": h("00 00 00 00 00 01 01 07") + snapshot,
        "fuzz_control_client/opens-then-answers": h("00 05 00 00 00 02 03 21") + answers,
        "fuzz_control_client/impostor": h("00 00 01 00 00 01 01 07") + b"\x5a" * 32,
        "fuzz_control_client/changed-reply": h("00 00 00 03 03 01 01 07"),
        "fuzz_control_client/changed-mac": h("00 00 00 30 80 01 01 07"),
        "fuzz_control_client/late-auth-ok": h("00 00 00 00 00 64 64 07"),
        "fuzz_control_client/raw-opening": b"\x01\x09" + reply + h("002182") + node_mac,
        "fuzz_control_client/raw-bye-first": b"\x01\x00" + h("00029904"),
    }
    for name, data in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, name)), exist_ok=True)
        open(os.path.join(root, name), "wb").write(data)
