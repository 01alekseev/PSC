import hashlib
from crypto.signer_ed25519 import sign_data, verify_signature

def hash_psc(psc_bytes: bytes) -> bytes:
    return hashlib.sha256(psc_bytes).digest()

def sign_psc(psc_path: str, private_key_path: str, output_sig_path: str):
    with open(psc_path, "rb") as f:
        psc_bytes = f.read()
    digest = hash_psc(psc_bytes)
    signature = sign_data(private_key_path, digest)
    with open(output_sig_path, "wb") as f:
        f.write(signature)

def verify_psc(psc_path: str, signature_path: str, public_key_path: str) -> bool:
    with open(psc_path, "rb") as f:
        psc_bytes = f.read()
    digest = hash_psc(psc_bytes)
    with open(signature_path, "rb") as f:
        sig = f.read()
    return verify_signature(public_key_path, digest, sig)

