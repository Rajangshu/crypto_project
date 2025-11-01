# crypto.py
"""
Crypto helpers: AES-CBC, optional DES-CBC, PBKDF2 key derivation and HMAC-SHA256.
"""

import hashlib
import hmac
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from typing import Tuple


# ---------- Key derivation ----------
def derive_master_key(passphrase: str, salt: bytes, dklen: int = 64, iterations: int = 200_000) -> bytes:
    """
    Derive a master key from passphrase and salt using PBKDF2-HMAC-SHA256.
    Returns dklen bytes.
    """
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=dklen)


# ---------- HMAC ----------
def hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, "sha256").hexdigest()


def verify_hmac(key: bytes, data: bytes, mac_hex: str) -> bool:
    return hmac.compare_digest(hmac_hex(key, data), mac_hex)


# ---------- AES (CBC, PKCS7) ----------
def encrypt_aes(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt with AES-CBC. key must be 16/24/32 bytes. Returns (iv, ciphertext).
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ct


def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt


# ---------- DES (CBC, PKCS7) - optional for comparison ----------
def encrypt_des(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt with DES-CBC. key must be exactly 8 bytes.
    Returns (iv, ciphertext).
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, DES.block_size))
    return iv, ct


def decrypt_des(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return pt
