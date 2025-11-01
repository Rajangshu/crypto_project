# chat_cli.py
"""
SecureTalk CLI – offline encrypted messenger supporting:
 - AES/DES encryption
 - HMAC-SHA256 integrity
 - Time-lock (unlock_in / expire_in)
 - File and text message support
"""

import argparse
import json
import os
import sys
import getpass
from timed_lock import compute_time_window, format_ts
from file_envelope import encrypt_file, decrypt_file_envelope
from envelope import build_envelope, verify_envelope_and_extract
from crypto import derive_master_key, encrypt_aes, decrypt_aes
from Crypto.Random import get_random_bytes


def send_text(args):
    """Encrypt and store a text message."""
    msg = args.message
    if not msg and args.infile:
        with open(args.infile, "r", encoding="utf-8") as f:
            msg = f.read()

    if not msg:
        print("No message provided.")
        sys.exit(1)

    passphrase = getpass.getpass("Enter passphrase: ").strip()
    if not passphrase:
        print("Passphrase required.")
        sys.exit(1)

    unlock_after, expires_at = compute_time_window(args.unlock_in, args.expire_in)
    salt = get_random_bytes(16)
    master = derive_master_key(passphrase, salt, dklen=64)
    enc_key = master[:32]
    mac_key = master[32:64]
    iv, ct = encrypt_aes(msg.encode(), enc_key)

    env = build_envelope("AES-CBC", iv, salt, ct, mac_key,
                         unlock_after=unlock_after, expires_at=expires_at)
    env["type"] = "text"
    env["length"] = len(msg)
    env["created_at"] = int(os.path.getmtime(args.infile)) if args.infile else int(os.path.getmtime(__file__))
    
    # Recalculate MAC after adding extra fields
    from envelope import canonical_bytes
    from crypto import hmac_hex
    env_no_mac = {k: v for k, v in env.items() if k != "mac"}
    env["mac"] = hmac_hex(mac_key, canonical_bytes(env_no_mac))

    with open(args.outfile, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)
    print(f"Encrypted message saved to {args.outfile}")
    if unlock_after or expires_at:
        print("Unlock:", format_ts(unlock_after), "| Expire:", format_ts(expires_at))


def recv_message(args):
    """Verify + decrypt envelope (text or file)."""
    if not os.path.exists(args.infile):
        print("File not found:", args.infile)
        sys.exit(1)

    with open(args.infile, "r", encoding="utf-8") as f:
        env = json.load(f)

    passphrase = getpass.getpass("Enter passphrase used for encryption: ").strip()

    if env.get("type") == "file":
        out_path = decrypt_file_envelope(env, passphrase, out_dir=args.outdir)
        print(f"File decrypted successfully → {out_path}")
    else:
        extracted = verify_envelope_and_extract(env, passphrase)
        iv = extracted["iv"]
        ct = extracted["ciphertext"]
        enc_key = extracted["enc_key"]
        pt = decrypt_aes(ct, enc_key, iv)
        out_path = args.outfile or "recovered.txt"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(pt.decode())
        print(f"Message decrypted → {out_path}")


def send_file(args):
    """Encrypt and store a file envelope."""
    passphrase = getpass.getpass("Enter passphrase: ").strip()
    if not passphrase:
        print("Passphrase required.")
        sys.exit(1)

    unlock_after, expires_at = compute_time_window(args.unlock_in, args.expire_in)
    env = encrypt_file(args.filepath, passphrase, cipher_name=args.cipher,
                       unlock_after=unlock_after, expires_at=expires_at)
    with open(args.outfile, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)
    print(f"Encrypted file saved → {args.outfile}")
    if unlock_after or expires_at:
        print("Unlock:", format_ts(unlock_after), "| Expire:", format_ts(expires_at))


def make_parser():
    p = argparse.ArgumentParser(description="SecureTalk: Offline Encrypted Messenger")
    sub = p.add_subparsers(dest="cmd")

    s1 = sub.add_parser("send-text", help="Encrypt text message")
    s1.add_argument("--message", help="Message to encrypt")
    s1.add_argument("--infile", help="Read message from file")
    s1.add_argument("--outfile", required=True)
    s1.add_argument("--unlock-in", help="Delay before unlock (e.g. 5m, 1h)")
    s1.add_argument("--expire-in", help="Expiry duration (e.g. 2h, 1d)")
    s1.set_defaults(func=send_text)

    s2 = sub.add_parser("recv", help="Decrypt an envelope")
    s2.add_argument("--infile", required=True)
    s2.add_argument("--outfile", help="Output text file")
    s2.add_argument("--outdir", default=".", help="Output directory for files")
    s2.set_defaults(func=recv_message)

    s3 = sub.add_parser("send-file", help="Encrypt a file")
    s3.add_argument("--filepath", required=True)
    s3.add_argument("--outfile", required=True)
    s3.add_argument("--cipher", choices=["aes", "des"], default="aes")
    s3.add_argument("--unlock-in", help="Delay before unlock (e.g. 5m, 1h)")
    s3.add_argument("--expire-in", help="Expiry duration (e.g. 2h, 1d)")
    s3.set_defaults(func=send_file)

    return p


def main():
    parser = make_parser()
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
