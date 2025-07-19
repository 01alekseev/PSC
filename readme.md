Petoron Seal Contracts (PSC)

PSC is an irreversible, binary, offline system of digital agreements without code execution.  
Each contract is a fixed cryptographic promise, signed by the participants and time limited (TTL).  
PSC does not require a blockchain, API or internet. It works like a seal: once and. forever.

---

Key features

- Binary format only (no JSON, YAML or text declarations)
- TTL (time to live) is embedded in the file
- Participant signatures (Ed25519)
- executed - flag protects against reuse
- Signatures are external (.sig), not embedded.
- Support for manual deletion (burn)
- Full compatibility with PTBC (ability to encrypt PSC)

---

CLI commands :))

Generate keys:
python3 cli/psc_cli.py genkey --output userA

Create contract:
python3 cli/psc_cli.py create contract.txt --pubkeys userA.pub --ttl 3600 --output contract.psc

Sign:
python3 cli/psc_cli.py sign contract.psc --private userA.priv --output userA.sig

Verify signature:
python3 cli/psc_cli.py verify contract.psc --sig userA.sig --public userA.pub

Verify all signatures: 
python3 cli/psc_cli.py verify-all contract.psc --sigs userA.sig --pubs userA.pub

Check status:
python3 cli/psc_cli.py status contract.psc

Execute contract:
python3 cli/psc_cli.py execute contract.psc --sigs userA.sig --pubs userA.pub

Delete contract:
python3 cli/psc_cli.py burn contract.psc

*PSC can be encrypted with the Petoron Time Burn Cipher for complete privacy:
python3 python3 ptbc_cli.py encrypt contract.psc contract.ptbc --ttl 600 

Dependencies:
Python 3.7+ 
PyNaCl (pip install pynacl)

That's kind of it, I give it to you :))
