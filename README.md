# Secure Text Messaging using AES/DES and SHA-256

## Overview

This project implements a secure text messaging system designed to provide both **confidentiality** and **integrity** for messages. It uses modern, standard cryptographic primitives to protect data, which is then wrapped in a simple JSON envelope for transmission.

This repository contains the **Phase 2 partial implementation**, representing 20–30% of the final project functionality. The core cryptographic engine and the command-line interface are complete.

---

## Features ✨

* **Confidentiality:** Messages are encrypted using strong symmetric ciphers.
    * AES-256 in CBC (Cipher Block Chaining) mode.
    * DES in CBC mode (included for academic comparison).
* **Integrity & Authenticity:** A **HMAC-SHA256** tag is generated to ensure that messages have not been tampered with.
* **Secure Key Derivation:** A user-provided passphrase is used to generate a secure encryption key via **PBKDF2** (Password-Based Key Derivation Function 2), which protects against brute-force attacks.
* **Simple CLI:** A straightforward command-line interface allows for easy encryption and decryption of message files.

---

## Phase 2 Status

* **Objective:** Build the foundational cryptographic core and a basic CLI.
* **Completed Tasks:**
    * ✅ Modular code for encryption, hashing, and key derivation (`crypto.py`).
    * ✅ Basic CLI for `send` and `recv` commands (`cli.py`).
    * ✅ JSON envelope structure for transmitting data (`envelope.py`).
    * ✅ Testing with sample input and output files.

---

## File Structure:

├── cli.py                     # CLI commands (send/recv)
├── crypto.py                  # AES, DES, PBKDF2, HMAC logic
├── envelope.py                # JSON envelope build/verify functions
├── samples/
│   └── msg1.txt               # Sample plaintext message
├── README.md                  # This README file
└── PROGRESS_REPORT_PHASE2.md  # Project progress report


---

## Installation & Usage

### Prerequisites

* Python 3.6+
* `pycryptodome` library

### Installation

1.  Clone the repository to your local machine:
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```
2.  Install the required Python library:
    ```bash
    pip install pycryptodome
    ```

### Usage

The application is controlled via `cli.py` and requires a user-provided passphrase for key generation, which you will be prompted to enter securely.

#### 1. Encrypt & Send a Message

This command reads a plaintext file, encrypts it, generates an integrity check (HMAC), and bundles everything into a single JSON output file.

* **Command:**
    ```bash
    python cli.py send --cipher aes --in samples/msg1.txt --out message.json
    ```
* **Arguments:**
    * `--cipher`: The encryption algorithm to use (`aes` or `des`).
    * `--in`: The path to the input plaintext file.
    * `--out`: The path for the output JSON file.

#### 2. Receive & Decrypt a Message

This command reads the JSON file, verifies the message integrity using the HMAC tag, and if successful, decrypts the ciphertext and writes it to an output file.

* **Command:**
    ```bash
    python cli.py recv --in message.json --out recovered.txt
    ```
* **Arguments:**
    * `--in`: The path to the input JSON message file.
    * `--out`: The path to write the recovered plaintext.

---

## Example Output

#### Successful Run

When the passphrase is correct and the message has not been altered:

* **On Send:**
    ```
    Enter passphrase: 
    Success: Message written to message.json
    ```
* **On Receive:**
    ```
    Enter passphrase: 
    Success: Recovered plaintext written to recovered.txt
    ```

#### Tampered Message

If the `message.json` file is modified in any way after creation, the integrity check will fail:

* **On Receive:**
    ```
    Enter passphrase: 
    Error: Verification failed: MAC verification failed - message integrity check failed
    ```
