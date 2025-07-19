import time
import struct
from utils.structs import hash_file

#[count:4][key_len:2][key][...][expires_at:8][hash_len:2][hash][executed:1]
def create_psc(document_path: str, pubkey_paths: list[str], ttl_seconds: int) -> bytes:
    pubkeys = []
    for path in pubkey_paths:
        with open(path, "rb") as f:
            pubkeys.append(f.read())
    doc_hash = hash_file(document_path)
    expires_at = int(time.time()) + ttl_seconds

    data = b''
    data += struct.pack(">I", len(pubkeys))
    for key in pubkeys:
        data += struct.pack(">H", len(key)) + key
    data += struct.pack(">Q", expires_at)
    data += struct.pack(">H", len(doc_hash)) + doc_hash
    data += b'\x00'  # executed flag = not executed

    return data

def save_psc(psc_bytes: bytes, path: str):
    with open(path, "wb") as f:
        f.write(psc_bytes)

def load_psc_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

