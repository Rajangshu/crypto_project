Secure Text Messaging using AES/DES and SHA-256 Integrity Check
 Overview

This project implements a secure text messaging system where:

Messages are encrypted with AES-256 (CBC) or DES (CBC).

Integrity is ensured using HMAC-SHA256 with a passphrase-derived key (PBKDF2).

A simple CLI allows sending and receiving encrypted JSON message files.

This is the Phase 2 partial implementation (20–30% of the final project).

Encrypt & Send:
python cli.py send --cipher aes --in samples/msg1.txt --out message.json

Receive & Decrypt:
python cli.py recv --in message.json --out recovered.txt

Example Output

Success:

Message written to message.json
Recovered plaintext written to recovered.txt


Tampered message:

Verification failed: MAC verification failed - message integrity check failed


FILE STRUCTURE:
cli.py          # CLI commands (send/recv)
crypto.py       # AES, PBKDF2, HMAC
envelope.py     # JSON envelope build/verify
samples/msg1.txt
README.md
PROGRESS_REPORT_PHASE2.md
