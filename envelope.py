# envelope.py
"""
Envelope building/verification. JSON message carrying:
  - version, cipher, ts, salt_b64, iv_b64, ct_b64, mac_alg, mac
MAC is HMAC-SHA256 over canonical JSON of the envelope WITHOUT the 'mac' field.
"""

import base64
import json
import time
from typing import Dict, Any
from crypto import derive_master_key, hmac_hex, verify_hmac


# helpers
def b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64dec(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canonical_bytes(obj: Dict[str, Any]) -> bytes:
    """
    Canonical JSON: sort_keys=True and no extra spaces. This ensures consistent MAC.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_envelope(cipher_name: str, iv: bytes, salt: bytes, ciphertext: bytes, mac_key: bytes) -> Dict[str, Any]:
    """
    Build envelope dict and compute mac (HMAC-SHA256).
    Returns the envelope (with 'mac' included).
    """
    env = {
        "v": 1,
        "cipher": cipher_name,
        "ts": int(time.time()),
        "salt_b64": b64enc(salt),
        "iv_b64": b64enc(iv),
        "ct_b64": b64enc(ciphertext),
        "mac_alg": "HMAC-SHA256",
    }
    # compute mac over canonical JSON of env (without mac)
    mac = hmac_hex(mac_key, canonical_bytes(env))
    env["mac"] = mac
    return env


def verify_envelope_and_extract(env: Dict[str, Any], passphrase: str) -> Dict[str, bytes]:
    """
    Given envelope dict and passphrase, verify MAC, derive keys, and return dict with iv and ciphertext bytes.
    Raises ValueError on any verification failure.
    Returned dict: {'iv': bytes, 'ciphertext': bytes, 'enc_key': bytes, 'mac_key': bytes, 'cipher': str}
    """
    # basic field checks
    required = {"v", "cipher", "ts", "salt_b64", "iv_b64", "ct_b64", "mac_alg", "mac"}
    if not required.issubset(set(env.keys())):
        missing = required - set(env.keys())
        raise ValueError(f"Envelope is missing fields: {missing}")

    # decode salt and iv and ct
    try:
        salt = b64dec(env["salt_b64"])
        iv = b64dec(env["iv_b64"])
        ct = b64dec(env["ct_b64"])
    except Exception as e:
        raise ValueError("Invalid base64 in envelope fields") from e

    # derive master key then split into enc_key and mac_key consistently
    # we derive 64 bytes and split: first N for enc (depending on cipher), next 32 for mac
    master = derive_master_key(passphrase, salt, dklen=64)
    # choose enc key length based on cipher
    cipher_name = env["cipher"].upper()
    if cipher_name.startswith("AES"):
        enc_len = 32  # AES-256
    elif cipher_name.startswith("DES"):
        enc_len = 8   # DES key
    else:
        raise ValueError(f"Unsupported cipher in envelope: {env['cipher']}")
    enc_key = master[:enc_len]
    mac_key = master[enc_len:enc_len + 32]

    # verify mac
    # recompute MAC over canonical JSON of env without the mac field
    env_no_mac = {k: v for k, v in env.items() if k != "mac"}
    computed_mac = hmac_hex(mac_key, canonical_bytes(env_no_mac))
    if not verify_hmac(mac_key, canonical_bytes(env_no_mac), env["mac"]):
        raise ValueError("MAC verification failed - message integrity check failed")

    return {"iv": iv, "ciphertext": ct, "enc_key": enc_key, "mac_key": mac_key, "cipher": cipher_name}
