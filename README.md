# 🔒 SecureTalk - Offline Encrypted Messenger

SecureTalk is a high-security offline messenger and file encryption tool built with Python and Streamlit. It allows you to encrypt text messages and files with strong, modern cryptography, wrap them in a secure JSON "envelope," and decrypt them later.

The application works 100% offline and can be run locally or deployed as a web app. It includes features for time-locking messages (setting unlock and expiration dates) and passphrase recovery via security questions.

[![Deploy to Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io/Rajangshu/crypto_project/main/app.py)

---

## 🌟 Core Features

* **Web & Command-Line Interfaces:** Use the friendly Streamlit web UI (`app.py`) or the fast command-line tool (`cli.py`).
* **Strong Encryption:** Choose between industry-standard **AES-256-CBC** or legacy **DES-CBC** for encryption.
* **Secure Key Derivation:** Passphrases are securely converted into encryption keys using **PBKDF2-HMAC-SHA256** with 200,000 iterations and a random salt.
* **Data Integrity (MAC):** All encrypted data is protected by an **HMAC-SHA256** (Hashed Message Authentication Code) to prevent tampering. Any modification to the encrypted file will cause decryption to fail.
* **Time-Locks:** Set an **unlock time** (message can't be decrypted before) or an **expiration time** (message can't be decrypted after).
* **File & Text Support:** Encrypt any file (images, documents, etc.) or just plain text messages.
* **Passphrase Recovery:** Optionally add a security question to your encrypted message, which allows you to recover the stored passphrase if you forget it.

---

## 🛠️ How to Use (Web App)

The easiest way to use SecureTalk is with the Streamlit web interface.

### 1. Installation

1.  Clone this repository:
    ```bash
    git clone [https://github.com/Rajangshu/crypto_project.git](https://github.com/Rajangshu/crypto_project.git)
    cd crypto_project
    ```

2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### 2. Run the App

1.  Launch the Streamlit app from your terminal:
    ```bash
    streamlit run app.py
    ```

2.  Your browser will automatically open to the application, where you can:
    * **Encrypt Text:** Write a message, set a passphrase, and (optionally) add time-locks or recovery questions.
    * **Encrypt File:** Upload any file, set a passphrase, and apply settings.
    * **Decrypt:** Upload an encrypted `.json` envelope, provide the passphrase (or use the recovery question), and securely view the original message or download the file.

---

## ⌨️ How to Use (Command-Line)

You can also use the `cli.py` script for encryption and decryption directly in your terminal.

### Encrypt a File (Send)

Use the `send` command to encrypt a file. You will be prompted for a passphrase.

```bash
# Usage: python cli.py send --in <input_file> --out <output_envelope.json> --cipher <aes|des>

# Example using AES (recommended)
python cli.py send --in samples/msg1.txt --out message.json --cipher aes

# Example using DES
python cli.py send --in photo.jpg --out photo.json --cipher des
