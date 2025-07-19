from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder

def generate_keypair(priv_path, pub_path):
    sk = SigningKey.generate()
    pk = sk.verify_key
    with open(priv_path, "wb") as f:
        f.write(sk.encode(encoder=RawEncoder))
    with open(pub_path, "wb") as f:
        f.write(pk.encode(encoder=RawEncoder))

def sign_data(private_key_path, data: bytes) -> bytes:
    with open(private_key_path, "rb") as f:
        sk = SigningKey(f.read(), encoder=RawEncoder)
    return sk.sign(data).signature

def verify_signature(public_key_path, data: bytes, sig: bytes) -> bool:
    with open(public_key_path, "rb") as f:
        vk = VerifyKey(f.read(), encoder=RawEncoder)
    try:
        vk.verify(data, sig)
        return True
    except Exception:
        return False

