import os
import struct
import hmac
from core.signer_psc import verify_psc
from core.contract_psc import load_psc_bytes
from core.ttl import is_expired, seconds_remaining
from Crypto.Hash import SHA512
from argon2.low_level import hash_secret_raw, Type

EXECUTED_FLAG_OFFSET = -1
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

def is_executed(psc_bytes):
    return psc_bytes[EXECUTED_FLAG_OFFSET] == 1

def verify_integrity(psc_bytes) -> bool:
    try:
        offset = 0
        count = struct.unpack_from(">I", psc_bytes, offset)[0]
        offset += 4
        for _ in range(count):
            key_len = struct.unpack_from(">H", psc_bytes, offset)[0]
            offset += 2 + key_len

        offset += 8
        offset += 8

        hash_len = struct.unpack_from(">H", psc_bytes, offset)[0]
        offset += 2 + hash_len

        salt = psc_bytes[offset:offset + SALT_SIZE]
        offset += SALT_SIZE

        received_hmac = psc_bytes[offset:offset + HMAC_SIZE]
        offset += HMAC_SIZE

        data_for_hmac = psc_bytes[:offset - HMAC_SIZE]
        password = b'psc-integrity'
        hmac_key = _derive_hmac_key(password, salt)
        calc_hmac = hmac.new(hmac_key, data_for_hmac, SHA512).digest()

        return hmac.compare_digest(calc_hmac, received_hmac)
    except Exception:
        return False

def mark_executed(path):
    with open(path, 'rb+') as f:
        f.seek(-1, os.SEEK_END)
        f.write(b'\x01')

def burn_contract(path):
    os.remove(path)
    print(f"Contract {path} burned")

def verify_all(psc_path, sig_paths, pub_paths):
    if len(sig_paths) != len(pub_paths):
        return False
    for sig, pub in zip(sig_paths, pub_paths):
        if not verify_psc(psc_path, sig, pub):
            return False
    return True

def execute(psc_path, sig_paths, pub_paths):
    with open(psc_path, 'rb') as f:
        psc = f.read()

    if not verify_integrity(psc):
        print("HMAC verification failed")
        return

    if is_executed(psc):
        print("Contract already executed")
        return

    if is_expired(psc):
        print("Contract expired")
        return

    if not verify_all(psc_path, sig_paths, pub_paths):
        print("Signature verification failed")
        return

    mark_executed(psc_path)
    print("Contract executed successfully")
