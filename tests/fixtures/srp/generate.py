"""Offline fixture provenance: Python cryptography 41.0.7, independent DNS encoder.
Tests read committed bytes and never invoke Python/OpenSSL or install dependencies.
ECDSA uses public test scalars 1; Edwards seeds are fixed public test values.
ECDSA signing is randomized, so regeneration creates different valid signatures.
"""
from pathlib import Path
from struct import pack
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, utils
OUT = Path(__file__).parent
NOW = 1789473600
ZONE = [b'default', b'service', b'arpa']
HOST = [b'Host'] + ZONE
INSTANCE = [b'My Printer', b'_http', b'_tcp'] + ZONE

def name(labels):
    return b''.join(bytes([len(x)]) + x for x in labels) + b'\0'

def rr(owner, kind, cls, ttl, data):
    return owner + pack('!HHIH', kind, cls, ttl, len(data)) + data

def generate(alg, variant=''):
    if alg in (13, 14):
        n = 32 if alg == 13 else 48
        key = ec.derive_private_key(1, ec.SECP256R1() if alg == 13 else ec.SECP384R1())
        public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
        def sign(data):
            r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256() if alg == 13 else hashes.SHA384())))
            return r.to_bytes(n, 'big') + s.to_bytes(n, 'big')
    else:
        key = (ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))) if alg == 15 else
               ed448.Ed448PrivateKey.from_private_bytes(bytes(range(57))))
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sign = key.sign
    flags = 65535 if variant == 'flags' else 0
    keydata = pack('!HBB', flags, 3, alg) + public
    tag = sum(x << (8 if i % 2 == 0 else 0) for i, x in enumerate(keydata))
    tag = (tag + (tag >> 16)) & 65535
    zone = name(ZONE)
    question = zone + pack('!HH', 6, 1)
    host_at = 12 + len(question)
    host = b'\x04Host\xc0\x0c'
    hostptr = pack('!H', 0xc000 | host_at)
    instance = name(INSTANCE)
    updates = [rr(host, 255, 255, 0, b'')]
    if variant != 'remove':
        updates.append(rr(hostptr, 25, 1, 120, keydata))
    deleting = variant in ('remove', 'delete_key')
    if not deleting:
        updates.append(rr(hostptr, 28, 1, 120, bytes.fromhex('fd000000000000000000000000000001')))
    if variant not in ('remove', 'delete_key', 'host_only'):
        updates += [rr(instance, 255, 255, 0, b''),
                    rr(instance, 33, 1, 120, pack('!HHH', 0, 0, 8080) + hostptr),
                    rr(instance, 16, 1, 120, b'\x03k=v'),
                    rr(name([b'_http', b'_tcp'] + ZONE), 12, 1, 120, instance),
                    rr(name([b'_color', b'_sub', b'_http', b'_tcp'] + ZONE), 12, 1, 120, instance)]
    lease = pack('!II', 0 if deleting else 7200, 1209600)
    if variant == 'short_lease': lease = pack('!I', 7200)
    opt = rr(b'\0', 41, 4096, 0, pack('!HH', 2, len(lease)) + lease)
    unsigned = pack('!HHHHHH', 0x1234, 0x2800, 1, 0, len(updates), 1) + question + b''.join(updates) + opt
    expiration, inception = (0, 0) if variant == 'zero_time' else (NOW + 300, NOW - 300)
    sigmeta = pack('!HBBIIIH', 0, alg, 0, 0, expiration, inception, tag) + name([x.lower() for x in HOST])
    sig = sign(sigmeta + unsigned)
    sigrr = rr(b'\0', 24, 255, 0, sigmeta + sig)
    message = bytearray(unsigned + sigrr)
    message[10:12] = pack('!H', 2)
    (OUT / f'alg{alg}{"-" + variant if variant else ""}.bin').write_bytes(message)

for a in [13, 14, 15, 16]: generate(a)
for v in ['flags', 'remove', 'delete_key', 'host_only', 'short_lease', 'zero_time']: generate(13, v)
