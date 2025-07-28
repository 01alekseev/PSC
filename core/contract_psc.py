import os
import time
import struct
import hmac
from utils.structs import hash_file
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

def create_psc(document_path: str, pubkey_paths: list[str], ttl_seconds: int) -> bytes:
    pubkeys = []
    for path in pubkey_paths:
        with open(path, "rb") as f:
            pubkeys.append(f.read())

    doc_hash = hash_file(document_path)

    now_time = time.time()
    now_monotonic = time.monotonic()
    offset = now_monotonic - now_time
    offset_ms = int(offset * 1000)

    if offset_ms < 0:
        offset_ms = 0
    elif offset_ms > 2**63 - 1:
        offset_ms = 2**63 - 1

    expires_at = int(now_time + ttl_seconds)

    salt = os.urandom(SALT_SIZE)
    password = b'psc-integrity'
    hmac_key = _derive_hmac_key(password, salt)

    data = b''
    data += struct.pack(">I", len(pubkeys))
    for key in pubkeys:
        data += struct.pack(">H", len(key)) + key
    data += struct.pack(">Q", expires_at)
    data += struct.pack(">Q", offset_ms)
    data += struct.pack(">H", len(doc_hash)) + doc_hash
    data += salt

    tag = hmac.new(hmac_key, data, SHA512).digest()
    data += tag
    data += b'\x00'

    return data

def save_psc(psc_bytes: bytes, path: str):
    with open(path, "wb") as f:
        f.write(psc_bytes)

def load_psc_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
