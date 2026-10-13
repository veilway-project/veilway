# Where the expected bytes in this crate's tests come from: HKDF and HMAC from Python's standard library, and ChaCha20-Poly1305 written out from RFC 8439, each checked against a published vector before it is used. Nothing here shares code with the crate.
# Prints the vectors. With a directory as its argument it also writes the seed corpus of the fuzz targets there:
#   docker run --rm -v "$PWD":/w -w /w python:3 python -I crates/veilway-proto/tests/vectors.py fuzz/corpus
import hmac, hashlib, struct, sys, os, base64, json

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

# X25519 from RFC 7748 and HPKE base mode from RFC 9180 with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20Poly1305, written out here and checked against the vectors of both RFCs (RFC 7748 section 6.1, RFC 9180 appendix A.2.1) before they are used.
P = 2 ** 255 - 19
BASE = b"\x09" + b"\x00" * 31
def x25519(k, u):
    k = int.from_bytes(k, "little") & ~7 & ((1 << 254) - 1) | (1 << 254)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        if swap ^ bit: x2, z2, x3, z3 = x3, z3, x2, z2
        swap = bit
        a, b, c, d = (x2 + z2) % P, (x2 - z2) % P, (x3 + z3) % P, (x3 - z3) % P
        aa, bb, da, cb = a * a % P, b * b % P, d * a % P, c * b % P
        e = (aa - bb) % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap: x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")
KEM, SUITE = b"KEM" + struct.pack(">H", 0x20), b"HPKE" + struct.pack(">HHH", 0x20, 1, 3)
def lextract(suite, salt, label, ikm): return extract(salt, b"HPKE-v1" + suite + label + ikm)
def lexpand(suite, key, label, info, n): return expand(key, struct.pack(">H", n) + b"HPKE-v1" + suite + label + info, n)
def keypair(ikm):
    sk = lexpand(KEM, lextract(KEM, b"", b"dkp_prk", ikm), b"sk", b"", 32)
    return sk, x25519(sk, BASE)
def schedule(dh, enc, pk, info):
    shared = lexpand(KEM, lextract(KEM, b"", b"eae_prk", dh), b"shared_secret", enc + pk, 32)
    context = b"\x00" + lextract(SUITE, b"", b"psk_id_hash", b"") + lextract(SUITE, b"", b"info_hash", info)
    secret = lextract(SUITE, shared, b"secret", b"")
    return shared, lexpand(SUITE, secret, b"key", context, 32), lexpand(SUITE, secret, b"base_nonce", context, 12), lexpand(SUITE, secret, b"exp", context, 32)
def sender(pk, info, ikm):
    sk_e, enc = keypair(ikm)
    return (enc,) + schedule(x25519(sk_e, pk), enc, pk, info)
def export(exporter, context, n): return lexpand(SUITE, exporter, b"sec", context, n)

alice, bob = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
assert x25519(alice, BASE).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
assert x25519(alice, x25519(bob, BASE)).hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
rfc_ikm_e, rfc_ikm_r, rfc_info = h("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"), h("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df"), b"Ode on a Grecian Urn"
rfc_sk_r, rfc_pk_r = keypair(rfc_ikm_r)
assert (rfc_sk_r.hex(), rfc_pk_r.hex()) == ("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb", "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
rfc_enc, rfc_shared, rfc_key, rfc_nonce, rfc_exporter = sender(rfc_pk_r, rfc_info, rfc_ikm_e)
assert rfc_enc.hex() == "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
assert rfc_shared.hex() == "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"
assert (rfc_key.hex(), rfc_nonce.hex()) == ("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91", "5c4d98150661b848853b547f")
assert rfc_exporter.hex() == "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922"
assert schedule(x25519(rfc_sk_r, rfc_enc), rfc_enc, rfc_pk_r, rfc_info)[1] == rfc_key
assert seal(rfc_key, rfc_nonce, b"Count-0", b"Beauty is truth, truth beauty").hex() == "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
assert export(rfc_exporter, b"", 32).hex() == "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"
assert export(rfc_exporter, b"\x00", 32).hex() == "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69"
assert export(rfc_exporter, b"TestContext", 32).hex() == "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53"
# The points of small order, in each encoding of 255 bits: X25519 gives zero for them under any private key. proof.rs holds the same list.
small_order = [bytes(32), b"\x01" + bytes(31), h("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"), h("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"), (P - 1).to_bytes(32, "little"), P.to_bytes(32, "little"), (P + 1).to_bytes(32, "little")]
assert all(x25519(sk, point) == bytes(32) for point in small_order for sk in (alice, bob)) and x25519(alice, BASE) != bytes(32)

# The keys of "Keys derived from the device transport secret" and of "udp-obfs", each shown by something it computes.
def mac(key, message): return hmac.new(key, message, hashlib.sha256).digest()
def b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=")
k_tag = expand(prk, b"veilway v1 tag\0" + inbound, 32)
k_bind = expand(prk, b"veilway v1 proof binder\0" + inbound + device, 32)
k_obfs = expand(prk, b"veilway v1 udp-obfs\0" + inbound, 32)
k_mask = expand(extract(b"veilway v1 udp-obfs mask\0", inbound), b"", 32)
device_tag = mac(k_tag, b"veilway v1 device tag\0")[:16]
def epoch_tag(e): return mac(k_tag, b"veilway v1 epoch tag\0" + struct.pack(">Q", e))[:16]
def obfs_keys(salt): return [expand(extract(salt, k_obfs), b"veilway v1 udp-obfs " + name + b"\0", 32) for name in (b"open", b"c2s", b"s2c")]
print("device_tag", device_tag.hex())
print("epoch_tag", epoch_tag(0x0102030405060708).hex())
print("binder_mac_of_abc", mac(k_bind, b"abc").hex())
print("mask", mac(k_mask, b"\xa5" * 32)[:16].hex())
print("obfs_open_c2s_s2c", [seal(k, bytes(12), b"", b"abc").hex() for k in obfs_keys(b"\xa5" * 32)])

# The stream proof: a node transport key of 60..7f, an ephemeral key from the 32 bytes 80..9f, the timestamp 1,700,000,000 and 5 bytes of padding, for `tls`.
node_sk, timestamp = bytes(range(0x60, 0x80)), 1_700_000_000
node_pk = x25519(node_sk, BASE)
def token(pk, name, head, padding, ikm, binder=None):
    enc, _, hpke_key, hpke_nonce, exporter = sender(pk, b"veilway v1 proof\0" + name + b"\0" + inbound, ikm)
    binder = binder or mac(k_bind, export(exporter, b"veilway v1 binder\0", 32) + head)
    return enc + seal(hpke_key, hpke_nonce, b"", head + binder + padding), exporter
head = b"\x01\x00\x00\x00" + struct.pack(">Q", timestamp) + device_tag
proof, proof_exporter = token(node_pk, b"tls", head, bytes(5), bytes(range(0x80, 0xa0)))
print("node_pk", node_pk.hex())
print("token", len(proof), b64(proof).decode())
print("session_c2s_s2c", [seal(export(proof_exporter, b"veilway v1 " + name + b"\0" + device, 32), bytes(12), b"", b"abc").hex() for name in (b"c2s", b"s2c")])
print("sid", export(proof_exporter, b"veilway v1 sid\0" + device, 16).hex())

# udp-obfs: an opening packet with a salt of a5 bytes that holds item1 and 15 bytes of padding, and a data packet with the nonce b0..bb that holds the same.
salt, data_nonce = b"\xa5" * 32, bytes(range(0xb0, 0xbc))
k_open, k_c2s, k_s2c = obfs_keys(salt)
def opening(e, header, plaintext, salt=salt):
    front = bytes(a ^ b for a, b in zip(epoch_tag(e), mac(k_mask, salt)[:16])) + salt
    return front + seal(obfs_keys(salt)[0], bytes(12), front, header + plaintext)
obfs_plain = b"\x00\x20" + item1 + b"\x00" * 15
obfs_opening = opening(timestamp // 120, b"\x01\x00\x00\x00" + struct.pack(">Q", timestamp), obfs_plain)
obfs_data = data_nonce + seal(k_c2s, data_nonce, b"", obfs_plain)
print("obfs_opening", len(obfs_opening), obfs_opening.hex())
print("obfs_data", len(obfs_data), obfs_data.hex())

# The replay file: a floor, a limit 20 s above it and two entries after a clean stop (the `enc` of a stream proof, kind 1, and the salt of an opening packet, kind 2), and the same without entries while the node runs.
def replay_file(floor, limit, entries=None, version=1, mark=None):
    body = b"VWREPLAY" + struct.pack(">IB3xQQI", version, (entries is not None) if mark is None else mark, floor, limit, len(entries or []))
    body += b"".join(bytes([kind]) + k + struct.pack(">Q", t) for kind, k, t in entries or [])
    return body + hashlib.sha256(body).digest()
replay_entries = [(1, b"\x11" * 32, timestamp + 1), (2, b"\x22" * 32, timestamp + 5)]
replay_clean, replay_running = replay_file(timestamp, timestamp + 20, replay_entries), replay_file(timestamp, timestamp + 20)
print("replay_clean", len(replay_clean), replay_clean.hex())
print("replay_running", len(replay_running), replay_running.hex())

# A fronted body of the two chunks above, and the query of a later request.
body = struct.pack(">H", len(chunk0)) + chunk0 + struct.pack(">H", len(chunk1)) + chunk1
print("fronted_body", len(body), body.hex())
print("later_query", (b64(bytes(range(16))) + b".7").decode())

# The subscription format. Ed25519 is written out from RFC 8032 over affine coordinates, slow and plain, and checked against tests 1 and 2 of its section 7.1 before it is used.
D, L = -121665 * pow(121666, P - 2, P) % P, 2 ** 252 + 27742317777372353535851937790883648493
def xrecover(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P: x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - xx) % P: return None
    return (P - x) % P if x & 1 != sign else x
def add(a, b):
    t = D * a[0] * b[0] * a[1] * b[1] % P
    return ((a[0] * b[1] + b[0] * a[1]) * pow(1 + t, P - 2, P) % P, (a[1] * b[1] + a[0] * b[0]) * pow(1 - t, P - 2, P) % P)
def mul(k, p):
    q = (0, 1)
    while k:
        if k & 1: q = add(q, p)
        p, k = add(p, p), k >> 1
    return q
def enc(p): return (p[1] | (p[0] & 1) << 255).to_bytes(32, "little")
# Decodes as a lax verifier does: a y of p or more is taken less p, and a sign bit on an x of 0 is ignored.
def dec(b):
    n = int.from_bytes(b, "little")
    y = (n & ((1 << 255) - 1)) % P
    x = xrecover(y, n >> 255)
    return None if x is None else (x, y)
G = dec((4 * pow(5, P - 2, P) % P).to_bytes(32, "little"))
def hint(m): return int.from_bytes(hashlib.sha512(m).digest(), "little")
def ed_public(seed):
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little") & ~7 & ((1 << 254) - 1) | (1 << 254)
    return a, enc(mul(a, G))
def ed_sign(seed, m):
    a, pk = ed_public(seed)
    r = hint(hashlib.sha512(seed).digest()[32:] + m) % L
    R = enc(mul(r, G))
    return R + ((r + hint(R + pk + m) * a) % L).to_bytes(32, "little")
# The verifier the strict rule is written against: it reduces what it decodes, compares points and not bytes, and checks neither the range of S nor the order of the key.
def ed_lax(pk, m, sig):
    A, R = dec(pk), dec(sig[:32])
    return A is not None and R is not None and mul(int.from_bytes(sig[32:], "little"), G) == add(R, mul(hint(sig[:32] + pk + m) % L, A))
assert ed_public(h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))[1].hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
assert ed_sign(h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"), b"").hex() == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
assert ed_public(h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))[1].hex() == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
assert ed_sign(h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"), b"\x72").hex() == "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
# The five y coordinates of the points of small order, as envelope.rs lists them: each decodes with either sign bit, and eight times the point is the neutral element. No other y below p gives such a point, since the group has eight of them: one with y = 1, one with y = p - 1, two with y = 0 and four of order 8.
small_y = [0, 1, P - 1, int.from_bytes(h("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"), int.from_bytes(h("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little")]
assert all(mul(8, dec((y | sign << 255).to_bytes(32, "little"))) == (0, 1) for y in small_y for sign in (0, 1))
assert len({dec((y | sign << 255).to_bytes(32, "little")) for y in small_y for sign in (0, 1)}) == 8 and mul(8, G) != (0, 1) and mul(L, G) == (0, 1)

# Two provider keys from the seeds 11..11 and 22..22, a third that no client holds from 99..99, a device key 33..33 with the device secret 44..44, and the token 55..55.
seed1, seed2, seed3, device_private, device_secret, link_token = b"\x11" * 32, b"\x22" * 32, b"\x99" * 32, b"\x33" * 32, b"\x44" * 16, b"\x55" * 16
(scalar1, sub_pk1), (_, sub_pk2), (_, sub_pk3), device_public = ed_public(seed1), ed_public(seed2), ed_public(seed3), x25519(device_private, BASE)
def key64(data): return base64.b64encode(data).decode()
def kid(pk): return b64(hashlib.sha256(pk).digest()[:8])
def jws_header(pk): return b'{"alg":"EdDSA","typ":"veilway-sub+jws","kid":"' + kid(pk) + b'"}'
def jws(seed, payload, header=None):
    signed = b64(header or jws_header(ed_public(seed)[1])) + b"." + b64(payload)
    return signed + b"." + b64(ed_sign(seed, signed))
issued = 1_700_000_000
# A document of one profile with one datagram and one stream transport. With `private` the provider issued the device's key, which is what a whole document in a link carries.
def payload(serial, keys, private=False, at=issued, of_profile=None, **more):
    keys_of_device = {"public_key": key64(device_public), "addresses": ["10.7.0.2", "fd00::2"], "transport_secrets": [key64(secret)]}
    if private: keys_of_device["private_key"] = key64(device_private)
    profile = {"id": "main", "name": "Example", "type": "veilway", "inbound_public_key": key64(inbound), "device": keys_of_device, "gateways": ["10.7.0.1", "fd00::1"], "mtu": 1420, "transport_public_key": key64(node_pk), "transports": [{"type": "udp-obfs", "endpoints": ["192.0.2.10:51820", "[2001:db8::10]:51820"]}, {"type": "tls", "path": "/a-path-of-a-transport", "candidates": [{"address": "192.0.2.10:443", "sni": "node.example.com", "host": "node.example.com", "pins": [key64(hashlib.sha256(b"pin").digest())]}]}], "exits": [{"tag": "de", "name": "Berlin", "country": "DE", "full_ip": True}]}
    document = {"v": 1, "subscription_id": "example-account-0001", "serial": serial, "issued_at": at, "expires_at": at + 30 * 86400, "signing_keys": [key64(key) for key in keys], "provider": {"name": "Example Provider"}, "profiles": [profile], "devices": [{"name": "phone", "enrolled_at": at, "this": True}]}
    profile.update(of_profile or {})
    document.update(more)
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode()
# Texts in several languages ("Text in several languages"): English as `default`, Persian with the zero width non-joiner (U+200C) that its spelling needs, German, and Chinese under a tag of three parts. The notice of the profile is what its node sends on the control channel, and the first exit has the name its node sends.
def said(default, **others): return {"default": default, **{tag.replace("_", "-"): text for tag, text in others.items()}}
languages = dict(
    provider={"name": said("Example Provider", fa="ارائه\N{ZERO WIDTH NON-JOINER}دهنده نمونه", de="Beispielanbieter")},
    of_profile={"name": said("Example", fa="نمونه"), "exits": [{"tag": "de", "name": said("Frankfurt", fa="فرانکفورت", de="Frankfurt am Main", zh_Hant_TW="法蘭克福"), "country": "DE", "full_ip": True}, {"tag": "nl", "name": "Amsterdam"}], "notices": [{"severity": "info", "text": said("Maintenance tonight", fa="امشب سرور به\N{ZERO WIDTH NON-JOINER}روزرسانی می\N{ZERO WIDTH NON-JOINER}شود")}]},
    support=[{"label": said("Help", fa="راهنما"), "url": "https://example.com/help"}],
    cards=[{"type": "stat", "label": said("Plan", fa="طرح"), "value": said("Basic", fa="پایه"), "unit": said("GB", fa="گیگابایت")}, {"type": "notice", "severity": "info", "text": said("Hello", fa="سلام")}, {"type": "link", "label": said("Site", fa="وب\N{ZERO WIDTH NON-JOINER}سایت"), "url": "https://example.com/"}],
    notices=[{"severity": "warning", "text": said("Welcome", fa_Arab_IR="خوش آمدید", fa="خوش آمدید", en_GB="Welcome back")}],
)
payload_first, payload_carried = payload(1, [sub_pk1]), payload(1, [sub_pk1], private=True)
payload_both, payload_second = payload(2, [sub_pk1, sub_pk2]), payload(3, [sub_pk2])
payload_refusal = json.dumps({"v": 1, "subscription_id": "example-account-0001", "issued_at": issued, "refusal": "device_limit"}, separators=(",", ":")).encode()
document_first, document_carried, document_refusal = jws(seed1, payload_first), jws(seed1, payload_carried), jws(seed1, payload_refusal)
fragment = b"#v1." + b64(sub_pk1) + b"." + b64(link_token)
link_veilway, link_https = b"veilway://sub/sub.example.com/s" + fragment, b"https://sub.example.com/s" + fragment
link_file = b"v1." + b64(sub_pk1) + b"." + document_carried
def request(op, name=None):
    body = {"v": 1, "token": b64(link_token).decode(), "kids": [kid(sub_pk1).decode()], "device_public_key": key64(device_public), "device_secret": b64(device_secret).decode(), "op": op}
    if name is not None: body["device_name"] = name
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
fingerprint = hashlib.sha256(sub_pk1).hexdigest()[:32]
print("sub_key", sub_pk1.hex(), kid(sub_pk1).decode(), " ".join(fingerprint[i:i + 4] for i in range(0, 32, 4)))
print("sub_header", jws_header(sub_pk1).decode())
print("sub_document", len(document_first), hashlib.sha256(document_first).hexdigest())
print("sub_link", link_veilway.decode())
print("sub_request", request("fetch").decode())

# Signatures that the lax verifier above accepts and the strict rule refuses, each over the message "veilway": S with the group order added, the neutral element as the key in three encodings, and a real key with the neutral element as R in an encoding of p + 1.
edge_message, edge_signature = b"veilway", ed_sign(seed1, b"veilway")
edge_high_s = edge_signature[:32] + (int.from_bytes(edge_signature[32:], "little") + L).to_bytes(32, "little")
edge_neutral = enc(mul(7, G)) + (7).to_bytes(32, "little")
neutral_keys = [(1).to_bytes(32, "little"), (P + 1).to_bytes(32, "little"), (1 | 1 << 255).to_bytes(32, "little")]
neutral_r = (P + 1).to_bytes(32, "little")
edge_neutral_r = neutral_r + (hint(neutral_r + sub_pk1 + edge_message) % L * scalar1 % L).to_bytes(32, "little")
assert ed_lax(sub_pk1, edge_message, edge_signature) and ed_lax(sub_pk1, edge_message, edge_high_s) and ed_lax(sub_pk1, edge_message, edge_neutral_r) and all(ed_lax(key, edge_message, edge_neutral) for key in neutral_keys)
print("edge_signature", edge_signature.hex())
print("edge_high_s", edge_high_s.hex())
print("edge_neutral", edge_neutral.hex(), [key.hex() for key in neutral_keys])
print("edge_neutral_r", edge_neutral_r.hex())
# The same two faults in the signature of a whole document, so that they reach the verifier of the envelope.
signed_first = document_first.rsplit(b".", 1)[0]
signature_first = ed_sign(seed1, signed_first)
document_high_s = signed_first + b"." + b64(signature_first[:32] + (int.from_bytes(signature_first[32:], "little") + L).to_bytes(32, "little"))
document_neutral_r = signed_first + b"." + b64(neutral_r + (hint(neutral_r + sub_pk1 + signed_first) % L * scalar1 % L).to_bytes(32, "little"))
assert all(ed_lax(sub_pk1, signed_first, base64.urlsafe_b64decode(document.rsplit(b".", 1)[1] + b"==")) for document in (document_first, document_high_s, document_neutral_r))
subscription_seeds = {
    "fuzz_sub_envelope/high-s": b"\x00" + document_high_s,
    "fuzz_sub_envelope/neutral-r": b"\x00" + document_neutral_r,
    "fuzz_sub_envelope/document": b"\x00" + document_first,
    "fuzz_sub_envelope/carried": b"\x00" + document_carried,
    "fuzz_sub_envelope/refusal": b"\x00" + document_refusal,
    "fuzz_sub_envelope/two-keys": b"\x00" + jws(seed1, payload_both),
    "fuzz_sub_envelope/second-key": b"\x00" + jws(seed2, payload_second),
    "fuzz_sub_envelope/key-not-held": b"\x00" + jws(seed3, payload(4, [sub_pk3])),
    "fuzz_sub_envelope/other-algorithm": b"\x00" + jws(seed1, payload_first, jws_header(sub_pk1).replace(b"EdDSA", b"ES256")),
    "fuzz_sub_envelope/unchanged": b"\x01",
    "fuzz_sub_envelope/one-bit": b"\x01\x00\x40\x01",
    "fuzz_subscription/import": b"\x01" + payload_carried,
    "fuzz_subscription/refresh": b"\x00" + payload(2, [sub_pk1], private=True, at=issued + 60),
    "fuzz_subscription/rotation": b"\x00" + payload(2, [sub_pk1, sub_pk2], private=True, at=issued + 60),
    "fuzz_subscription/refusal": b"\x00" + payload_refusal,
    "fuzz_subscription/refresh-with-link": b"\x04" + payload(2, [sub_pk1], at=issued + 60, refresh_urls=["https://mirror.example.net/s", "https://sub.example.com/other", "https://sub.example.com:8443/s"]),
    "fuzz_subscription/rotation-with-link": b"\x04" + payload(2, [sub_pk1, sub_pk2], at=issued + 60),
    "fuzz_subscription/refusal-with-link": b"\x04" + payload_refusal,
    "fuzz_subscription/import-content": b"\x01" + payload(5, [sub_pk1], private=True, refresh_urls=["https://mirror.example.net/s"], support=[{"label": "Help", "url": "https://example.com/help"}]),
    "fuzz_subscription/content": b"\x00" + payload(5, [sub_pk1], private=True, update_interval=7200, refresh_urls=["https://mirror.example.net/s"], usage={"used_bytes": 1, "quota_bytes": 2, "period": "monthly", "period_start": issued, "expires_at": 0, "device_limit": 3}, support=[{"label": "Help", "url": "https://example.com/help"}], cards=[{"type": "stat", "label": "Plan", "value": "Basic", "unit": "GB"}, {"type": "progress", "label": "Used", "used": 1, "total": 2}, {"type": "notice", "severity": "info", "text": "Hello"}, {"type": "link", "label": "Site", "url": "https://example.com/"}], logo={"type": "png", "data": key64(b"\x89PNG")}, accent="#3366cc", notices=[{"severity": "warning", "text": "Maintenance"}]),
    "fuzz_subscription/languages": b"\x00" + payload(6, [sub_pk1], private=True, at=issued + 60, **languages),
    "fuzz_subscription/import-languages": b"\x01" + payload(6, [sub_pk1], private=True, **languages),
    "fuzz_deeplink/native-veilway": link_veilway,
    "fuzz_deeplink/native-https": link_https,
    "fuzz_deeplink/document": b"veilway://doc#" + link_file,
    "fuzz_deeplink/file": link_file,
    "fuzz_deeplink/legacy": b"https://sub.example.com/list?token=abc#name",
    "fuzz_sub_request/fetch": request("fetch"),
    "fuzz_sub_request/confirm": request("confirm", "phone"),
    "fuzz_sub_request/release": request("release"),
    "fuzz_links/plain": b"\x00vless://00000000-0000-0000-0000-000000000000@node.example.com:443?security=tls&type=ws&sni=node.example.com&path=%2Fws#One\ntrojan://password@192.0.2.10:443#Two\nss://" + b64(b"aes-256-gcm:password") + b"@node.example.com:8388#Three\nvmess://" + base64.b64encode(json.dumps({"v": "2", "ps": "Four", "add": "node.example.com", "port": "443", "id": "00000000-0000-0000-0000-000000000000", "scy": "auto", "net": "ws", "tls": "tls"}).encode()) + b"\nhttp://example.com/\n",
    "fuzz_links/packed": b"\x00" + base64.b64encode(b"trojan://password@node.example.com:443?allowInsecure=1#One\nss://" + b64(b"rc4-md5:password@192.0.2.10:8388") + b"#Two\n"),
    "fuzz_links/native": b"\x00" + document_first,
    "fuzz_links/headers": b"\x01subscription-userinfo: upload=1; download=2; total=3; expire=1700000000\nprofile-title: Example\nprofile-update-interval: 12\nsupport-url: https://example.com/help\n",
}

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
    # The transports' targets make their own keys, so most of their seeds are settings alone. A hello or an opening packet that a seed spells out leaves the tag to the target (bit 2 of the first byte of stream_proof).
    stamp, sized = struct.pack(">Q", timestamp), lambda plain: struct.pack(">H", len(plain)) + plain
    hello_head, obfs_head = b"\x01\x00\x00\x00" + stamp + bytes(16), b"\x01\x00\x00\x00" + stamp
    clean_body, text = replay_clean[:-32], b64(proof)
    files.update({
        "stream_proof/opens": h("00 00 00 00 00 00 00 07"),
        "stream_proof/second-secret-second-key": h("00 01 02 01 01 00 00 21"),
        "stream_proof/fronted": h("00 00 01 02 02 00 00 4e"),
        "stream_proof/unknown-device": h("00 02 00 00 00 00 00 07"),
        "stream_proof/unknown-key": h("00 00 03 00 00 00 00 07"),
        "stream_proof/other-transport": h("00 00 00 00 01 00 00 07"),
        "stream_proof/no-transport": h("00 00 00 00 03 00 00 07"),
        "stream_proof/changed": h("00 00 00 00 00 40 01 07"),
        "stream_proof/raw-token": h("01 00 00 00 00 00 00 00") + text,
        "stream_proof/raw-short": h("01 00 00 00 00 00 00 00") + text[:100],
        "stream_proof/fixed-token": h("09 00 00 00 00 00 00 00"),
        "stream_proof/fixed-token-two-keys": h("09 00 01 00 00 00 00 00"),
        "stream_proof/fixed-token-changed": h("09 00 00 00 00 00 00 00 00 05 01"),
        "stream_proof/fixed-token-changed-back": h("09 00 00 00 00 00 00 00 00 05 01 00 05 01"),
        "stream_proof/fixed-token-other-transport": h("09 00 00 00 01 00 00 00"),
        "stream_proof/forged-epoch-tag": h("12 00 00 00 00 00 00 07") + hello_head + bytes(9),
        "stream_proof/forged-good":h("06 00 00 00 00 00 00 07") + hello_head + bytes(9),
        "stream_proof/forged-version-2": h("06 00 00 00 00 00 00 07") + b"\x02" + hello_head[1:],
        "stream_proof/forged-zero-set": h("06 00 00 00 00 00 00 07") + b"\x01\x00\x01\x00" + hello_head[4:],
        "stream_proof/forged-padding-set": h("06 00 00 00 00 00 00 07") + hello_head + bytes(8) + b"\x01",
        "stream_proof/forged-no-tag": h("02 00 00 00 00 00 00 07") + hello_head,
        "stream_proof/forged-binder": h("07 00 00 00 00 00 00 07") + hello_head + b"\x5a" * 32 + bytes(4),
        "udp_obfs/opens": h("00 00 02 00 00 37 00 07") + item1,
        "udp_obfs/second-secret-epoch-ahead": h("04 01 03 00 00 00 00 21") + item2,
        "udp_obfs/epoch-behind": h("00 00 01 00 00 37 00 07"),
        "udp_obfs/epoch-too-far": h("00 00 04 00 00 37 00 07"),
        "udp_obfs/unknown-device": h("00 02 02 00 00 37 00 07"),
        "udp_obfs/changed": h("00 00 02 10 01 37 00 07"),
        "udp_obfs/raw-opening": h("01 00 00 00 00 00 00 00") + obfs_opening,
        "udp_obfs/raw-data": h("01 00 00 00 00 00 00 00") + obfs_data,
        "udp_obfs/forged-good": h("02 00 02 00 00 37 00 07") + obfs_head + obfs_plain,
        "udp_obfs/forged-version-2": h("02 00 02 00 00 37 00 07") + b"\x02" + obfs_head[1:] + obfs_plain,
        "udp_obfs/forged-no-datagram": h("02 00 02 00 00 37 00 07") + obfs_head + bytes(20),
        "udp_obfs/forged-two-datagrams": h("02 00 02 00 00 37 00 07") + obfs_head + sized(item1) + sized(item2),
        "udp_obfs/data-one": h("03 00 00 00 00 00 00 00") + data_nonce + obfs_plain,
        "udp_obfs/data-padding-only": h("03 00 00 00 00 00 00 00") + data_nonce + bytes(7),
        "udp_obfs/data-two": h("03 00 00 00 00 00 00 00") + data_nonce + sized(item1) + sized(item2),
        "replay_file/clean": b"\x00" + replay_clean,
        "replay_file/running": b"\x00" + replay_running,
        "replay_file/body-clean": b"\x01" + clean_body,
        "replay_file/body-running": b"\x01" + replay_running[:-32],
        "replay_file/body-version-2": b"\x01" + replay_file(timestamp, timestamp + 20, version=2)[:-32],
        "replay_file/body-entries-without-mark": b"\x01" + replay_file(timestamp, timestamp + 20, replay_entries, mark=0)[:-32],
        "replay_file/body-count-too-high": b"\x01" + clean_body[:35] + b"\x03" + clean_body[36:],
        "replay_file/events": b"\x02" + h("00 01 00  00 01 00  00 02 05  08 00 10  09 00 00  00 01 00  0a 00 00  00 02 05  0c 00 00  00 03 14  08 00 7f  0e 00 00  00 01 00  0f 00 00  00 41 00  0b 00 00  00 81 00"),
        "replay_file/events-with-a-timer": b"\x06" + h("00 01 00  08 00 05  00 02 00  0c 00 00  08 00 05  00 03 00  08 01 7f  0c 00 00  08 01 81  00 04 00  0f 00 00  08 00 7f  00 05 00"),
        "replay_file/events-with-failed-writes": b"\x02" + h("00 11 3c  00 19 3c  00 02 3c  0f 18 00  0c 00 00  00 02 3c  0f 10 00  0a 18 00  0c 00 00  0e 10 00  0c 10 00  09 18 00  09 10 00  00 03 00"),
        "replay_file/a-clock-fault-and-back": b"\x02" + h("09 00 00  08 01 7f  09 00 00  08 01 81  09 18 00  09 00 00  0c 00 00  00 01 00"),
        "request_line/get-token": b"\x07GET /a-path-of-a-transport?" + text + b" HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n",
        "request_line/post-later": b"\x03POST /a-path-of-a-transport?" + b64(bytes(range(16))) + b".7 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "request_line/post-opening": b"\xffPOST /a-path-of-a-transport?" + text + b" HTTP/1.1\r\n",
        "request_line/no-query": b"\x01GET / HTTP/1.1\r\n",
        "request_line/http-1-0": b"\x01GET / HTTP/1.0\r\n",
        "request_line/head": b"\x01HEAD / HTTP/1.1\r\n",
        "request_line/bare-newline": b"\x05GET /index.html HTTP/1.1\n",
        "request_line/space-in-target": b"\x05GET /a b HTTP/1.1\r\n",
        "request_line/tls-hello": b"\x10" + h("16 03 01 02 00 01 00 01 fc 03 03"),
        "fronted_body/two-chunks": h("00 00 00 00") + sized(plain0) + sized(bytes(5)),
        "fronted_body/after-three": h("00 03 00 00") + sized(sized(item1)),
        "fronted_body/misplaced": h("02 00 01 00") + sized(plain0) + sized(bytes(5)),
        "fronted_body/cut": h("04 00 00 05") + sized(plain0) + sized(bytes(5)),
        "fronted_body/cut-on-a-chunk": h("04 00 00 17") + sized(plain0) + sized(bytes(5)),
        "fronted_body/invalid-item": h("00 02 00 00") + sized(bytes(3)) + sized(h("000901")),
        # Never a body sealed under the target's own key: the target takes this mode as bytes no client made.
        "fronted_body/stranger": h("01 00 00 00") + sized(b"\x5a" * 21) + sized(b"\xa5" * 16),
        "fronted_body/stranger-short": h("01 01 00 00") + b"\x00\x10" + bytes(15),
    })
    for name, data in {**files, **subscription_seeds}.items():
        os.makedirs(os.path.dirname(os.path.join(root, name)), exist_ok=True)
        open(os.path.join(root, name), "wb").write(data)
