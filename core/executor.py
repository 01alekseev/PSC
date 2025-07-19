import os
import struct
from core.signer_psc import verify_psc
from core.contract_psc import load_psc_bytes
from core.ttl import is_expired, seconds_remaining

EXECUTED_FLAG_OFFSET = -1

def is_executed(psc_bytes):
    return psc_bytes[EXECUTED_FLAG_OFFSET] == 1

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

