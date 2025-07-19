import struct
import hashlib

def pack_contract(document_hash: bytes, expires_at_unix: int, pubkeys: list[bytes]) -> bytes:
    data = b''
    data += struct.pack(">I", len(pubkeys))
    for key in pubkeys:
        data += struct.pack(">H", len(key)) + key
    data += struct.pack(">Q", expires_at_unix)
    data += struct.pack(">H", len(document_hash)) + document_hash
    data += b'\x00'
    return data

def unpack_contract(data: bytes):
    offset = 0
    count = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    pubkeys = []
    for _ in range(count):
        key_len = struct.unpack_from(">H", data, offset)[0]
        offset += 2
        pub = data[offset:offset + key_len]
        pubkeys.append(pub)
        offset += key_len
    expires_at = struct.unpack_from(">Q", data, offset)[0]
    offset += 8
    hash_len = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    document_hash = data[offset:offset + hash_len]
    return {
        "pubkeys": pubkeys,
        "expires_at": expires_at,
        "document_hash": document_hash
    }

def hash_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).digest()

