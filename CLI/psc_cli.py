import argparse
from core.contract_psc import create_psc, save_psc, load_psc_bytes
from core.signer_psc import sign_psc, verify_psc
from crypto.signer_ed25519 import generate_keypair
from core.executor import execute, burn_contract, verify_all
from core.ttl import is_expired, seconds_remaining
from core.executor import is_executed

def main():
    parser = argparse.ArgumentParser(description="Petoron Seal Contract CLI")
    sub = parser.add_subparsers(dest="cmd")

    c = sub.add_parser("create")
    c.add_argument("document")
    c.add_argument("--pubkeys", required=True, help="Comma-separated list of .pub files")
    c.add_argument("--ttl", type=int, required=True)
    c.add_argument("--output", default="contract.psc")

    s = sub.add_parser("sign")
    s.add_argument("psc")
    s.add_argument("--private", required=True)
    s.add_argument("--output", default="contract.sig")

    v = sub.add_parser("verify")
    v.add_argument("psc")
    v.add_argument("--sig", required=True)
    v.add_argument("--public", required=True)

    va = sub.add_parser("verify-all")
    va.add_argument("psc")
    va.add_argument("--sigs", required=True, help="Comma-separated list of .sig files")
    va.add_argument("--pubs", required=True, help="Comma-separated list of .pub files")

    e = sub.add_parser("execute")
    e.add_argument("psc")
    e.add_argument("--sigs", required=True)
    e.add_argument("--pubs", required=True)

    b = sub.add_parser("burn")
    b.add_argument("psc")

    st = sub.add_parser("status")
    st.add_argument("psc")

    g = sub.add_parser("genkey")
    g.add_argument("--output", required=True)

    args = parser.parse_args()

    if args.cmd == "create":
        pubkey_paths = [x.strip() for x in args.pubkeys.split(",")]
        psc_bytes = create_psc(args.document, pubkey_paths, args.ttl)
        save_psc(psc_bytes, args.output)
        print(f"Contract written to {args.output}")

    elif args.cmd == "sign":
        sign_psc(args.psc, args.private, args.output)
        print(f"Signature saved to {args.output}")

    elif args.cmd == "verify":
        valid = verify_psc(args.psc, args.sig, args.public)
        print("Valid" if valid else "Invalid")

    elif args.cmd == "verify-all":
        sigs = [x.strip() for x in args.sigs.split(",")]
        pubs = [x.strip() for x in args.pubs.split(",")]
        if verify_all(args.psc, sigs, pubs):
            print("All signatures valid")
        else:
            print("Some signatures invalid")

    elif args.cmd == "execute":
        sigs = [x.strip() for x in args.sigs.split(",")]
        pubs = [x.strip() for x in args.pubs.split(",")]
        execute(args.psc, sigs, pubs)

    elif args.cmd == "burn":
        burn_contract(args.psc)

    elif args.cmd == "status":
        data = load_psc_bytes(args.psc)
        if is_executed(data):
            print("Status: executed")
        elif is_expired(data):
            print("Status: expired")
        else:
            print(f"Status: valid ({seconds_remaining(data)} seconds left)")

    elif args.cmd == "genkey":
        priv = args.output + ".priv"
        pub = args.output + ".pub"
        generate_keypair(priv, pub)
        print(f"Keypair saved: {priv}, {pub}")

if __name__ == "__main__":
    main()

