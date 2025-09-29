# cli.py
"""
Minimal CLI: send and recv commands.
Usage:
  python cli.py send --cipher aes --in samples/msg1.txt --out message.json
  python cli.py recv --in message.json --out recovered.txt
"""

import argparse
import json
import os
import sys
import getpass
from crypto import derive_master_key, encrypt_aes, decrypt_aes, encrypt_des, decrypt_des
from crypto import hmac_hex
from envelope import build_envelope, verify_envelope_and_extract
from Crypto.Random import get_random_bytes


def send_command(args):
    # read plaintext file
    if not os.path.exists(args.infile):
        print("Input file not found:", args.infile)
        sys.exit(1)
    with open(args.infile, "rb") as f:
        plaintext = f.read()

    passphrase = getpass.getpass("Enter passphrase (used to derive keys): ").strip()
    if not passphrase:
        print("Passphrase required.")
        sys.exit(1)

    # generate salt
    salt = get_random_bytes(16)  # store with envelope
    # derive master key then split
    master = derive_master_key(passphrase, salt, dklen=64)
    cipher_name = args.cipher.lower()
    if cipher_name == "aes":
        enc_key = master[:32]   # AES-256
        mac_key = master[32:64]
        iv, ciphertext = encrypt_aes(plaintext, enc_key)
        env = build_envelope("AES-CBC", iv, salt, ciphertext, mac_key)
    elif cipher_name == "des":
        enc_key = master[:8]    # DES key (8 bytes)
        mac_key = master[8:40]
        iv, ciphertext = encrypt_des(plaintext, enc_key)
        env = build_envelope("DES-CBC", iv, salt, ciphertext, mac_key)
    else:
        print("Unsupported cipher. Use 'aes' or 'des'.")
        sys.exit(1)

    # write envelope
    with open(args.outfile, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)
    print(f"Message written to {args.outfile}")


def recv_command(args):
    # load envelope
    if not os.path.exists(args.infile):
        print("Envelope file not found:", args.infile)
        sys.exit(1)
    with open(args.infile, "r", encoding="utf-8") as f:
        env = json.load(f)

    passphrase = getpass.getpass("Enter passphrase used at send time: ").strip()
    if not passphrase:
        print("Passphrase required.")
        sys.exit(1)

    try:
        extracted = verify_envelope_and_extract(env, passphrase)
    except Exception as e:
        print("Verification failed:", str(e))
        sys.exit(1)

    cipher_name = extracted["cipher"]
    iv = extracted["iv"]
    ct = extracted["ciphertext"]
    enc_key = extracted["enc_key"]

    try:
        if cipher_name.startswith("AES"):
            pt = decrypt_aes(ct, enc_key, iv)
        elif cipher_name.startswith("DES"):
            pt = decrypt_des(ct, enc_key, iv)
        else:
            raise ValueError("Unsupported cipher in envelope.")
    except Exception as e:
        print("Decryption failed:", str(e))
        sys.exit(1)

    # write output
    with open(args.outfile, "wb") as f:
        f.write(pt)
    print(f"Recovered plaintext written to {args.outfile}")


def make_parser():
    p = argparse.ArgumentParser(description="securemsg CLI (Phase 2 - AES/DES + HMAC-SHA256)")
    sub = p.add_subparsers(dest="cmd")
    p_send = sub.add_parser("send", help="Encrypt and create envelope JSON")
    p_send.add_argument("--cipher", choices=["aes", "des"], default="aes")
    p_send.add_argument("--in", dest="infile", required=True, help="Input plaintext file")
    p_send.add_argument("--out", dest="outfile", required=True, help="Output envelope JSON file")

    p_recv = sub.add_parser("recv", help="Verify envelope and decrypt")
    p_recv.add_argument("--in", dest="infile", required=True, help="Input envelope JSON file")
    p_recv.add_argument("--out", dest="outfile", required=True, help="Output plaintext file")

    return p


def main():
    parser = make_parser()
    args = parser.parse_args()
    if args.cmd == "send":
        send_command(args)
    elif args.cmd == "recv":
        recv_command(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
