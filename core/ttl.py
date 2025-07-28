import time
import struct
import hmac
from Crypto.Hash import SHA512
from argon2.low_level import hash_secret_raw, Type

SALT_SIZE = 16
HMAC_SIZE = 64
KEY_SIZE = 32

def _derive_hmac_key(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=2**18,
        parallelism=4,
        hash_len=KEY_SIZE,
        type=Type.ID
    )

def read_expiration_and_offset(psc_bytes):
    offset = 0
    count = struct.unpack_from(">I", psc_bytes, offset)[0]
    offset += 4
    for _ in range(count):
        key_len = struct.unpack_from(">H", psc_bytes, offset)[0]
        offset += 2 + key_len

    expires_at = struct.unpack_from(">Q", psc_bytes, offset)[0]
    offset += 8
    offset_ms = struct.unpack_from(">Q", psc_bytes, offset)[0]
    offset += 8

    hash_len = struct.unpack_from(">H", psc_bytes, offset)[0]
    offset += 2 + hash_len

    salt = psc_bytes[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    received_hmac = psc_bytes[offset:offset + HMAC_SIZE]

    data_for_hmac = psc_bytes[:offset]
    password = b'psc-integrity'
    hmac_key = _derive_hmac_key(password, salt)
    calc_hmac = hmac.new(hmac_key, data_for_hmac, SHA512).digest()

    if not hmac.compare_digest(calc_hmac, received_hmac):
        raise ValueError("HMAC verification failed in TTL")

    return expires_at, offset_ms

def is_expired(psc_bytes):
    expires_at, offset_ms = read_expiration_and_offset(psc_bytes)
    estimated_time = time.monotonic() - (offset_ms / 1000.0)
    return estimated_time > expires_at

def seconds_remaining(psc_bytes):
    expires_at, offset_ms = read_expiration_and_offset(psc_bytes)
    estimated_time = time.monotonic() - (offset_ms / 1000.0)
    return max(0, int(expires_at - estimated_time))
