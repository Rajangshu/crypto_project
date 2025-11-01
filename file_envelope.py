# file_envelope.py
"""
Handles secure file encryption and decryption envelopes.
Similar to envelope.py but adds filename and file_size metadata.
"""

import os
import json
import time
from typing import Dict, Any
from crypto import derive_master_key, encrypt_aes, decrypt_aes, encrypt_des, decrypt_des
from envelope import build_envelope, verify_envelope_and_extract
from Crypto.Random import get_random_bytes


def encrypt_file(filepath: str, passphrase: str, cipher_name: str = "aes",
                 unlock_after=None, expires_at=None) -> Dict[str, Any]:
    """Encrypt a file and return envelope dict."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(filepath)

    with open(filepath, "rb") as f:
        data = f.read()

    salt = get_random_bytes(16)
    master = derive_master_key(passphrase, salt, dklen=64)

    if cipher_name.lower() == "aes":
        enc_key = master[:32]
        mac_key = master[32:64]
        iv, ciphertext = encrypt_aes(data, enc_key)
        cipher = "AES-CBC"
    elif cipher_name.lower() == "des":
        enc_key = master[:8]
        mac_key = master[8:40]
        iv, ciphertext = encrypt_des(data, enc_key)
        cipher = "DES-CBC"
    else:
        raise ValueError("Unsupported cipher")

    env = build_envelope(cipher, iv, salt, ciphertext, mac_key,
                         unlock_after=unlock_after, expires_at=expires_at)
    env["filename"] = os.path.basename(filepath)
    env["file_size"] = len(data)
    env["type"] = "file"
    env["created_at"] = int(time.time())
    
    # Recalculate MAC after adding extra fields
    from envelope import canonical_bytes
    from crypto import hmac_hex
    env_no_mac = {k: v for k, v in env.items() if k != "mac"}
    env["mac"] = hmac_hex(mac_key, canonical_bytes(env_no_mac))
    
    return env


def decrypt_file_envelope(env: Dict[str, Any], passphrase: str, out_dir: str = ".") -> str:
    """Verify + decrypt file envelope. Returns path to recovered file."""
    extracted = verify_envelope_and_extract(env, passphrase)
    iv = extracted["iv"]
    ct = extracted["ciphertext"]
    enc_key = extracted["enc_key"]
    cipher_name = extracted["cipher"]

    if cipher_name.startswith("AES"):
        pt = decrypt_aes(ct, enc_key, iv)
    elif cipher_name.startswith("DES"):
        pt = decrypt_des(ct, enc_key, iv)
    else:
        raise ValueError("Unsupported cipher")

    filename = env.get("filename", "recovered.bin")
    out_path = os.path.join(out_dir, filename)
    with open(out_path, "wb") as f:
        f.write(pt)
    return out_path
