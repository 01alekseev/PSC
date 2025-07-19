import time
import struct

def read_expiration(psc_bytes):
    offset = 0
    count = struct.unpack_from(">I", psc_bytes, offset)[0]
    offset += 4
    for _ in range(count):
        key_len = struct.unpack_from(">H", psc_bytes, offset)[0]
        offset += 2 + key_len
    expires_at = struct.unpack_from(">Q", psc_bytes, offset)[0]
    return expires_at

def is_expired(psc_bytes):
    expires_at = read_expiration(psc_bytes)
    return int(time.time()) > expires_at

def seconds_remaining(psc_bytes):
    expires_at = read_expiration(psc_bytes)
    return max(0, expires_at - int(time.time()))

