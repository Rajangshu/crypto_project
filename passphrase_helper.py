# passphrase_helper.py
"""
Recovery questions system for passphrase recovery.
Stores security questions and answers (hashed with SHA256 for privacy).
"""

import json
import os
import hashlib
import base64
from typing import Optional, Dict, Tuple
from Crypto.Random import get_random_bytes
from crypto import encrypt_aes, decrypt_aes, derive_master_key


RECOVERY_FILE = "data/recovery.json"


def _ensure_dir():
    os.makedirs(os.path.dirname(RECOVERY_FILE), exist_ok=True)
    if not os.path.exists(RECOVERY_FILE):
        with open(RECOVERY_FILE, "w") as f:
            json.dump({}, f)


def get_recovery_questions() -> Dict[str, str]:
    """Return list of common recovery questions."""
    return {
        "What was the name of your first pet?": "What was the name of your first pet?",
        "What city were you born in?": "What city were you born in?",
        "What is your mother's maiden name?": "What is your mother's maiden name?",
        "What was the name of your elementary school?": "What was the name of your elementary school?",
        "What is your favorite color?": "What is your favorite color?",
        "What was your childhood nickname?": "What was your childhood nickname?",
        "What is the name of your best friend from childhood?": "What is the name of your best friend from childhood?",
        "What street did you grow up on?": "What street did you grow up on?",
        "What was your favorite food as a child?": "What was your favorite food as a child?",
        "What is the make of your first car?": "What is the make of your first car?",
        "What was your favorite teacher's name?": "What was your favorite teacher's name?",
        "What is your favorite movie?": "What is your favorite movie?",
        "Custom Question": "Custom Question"  # Special case for custom question
    }


def add_recovery_question(envelope_id: str, question: str, answer: str, passphrase: str = None):
    """
    Store a recovery question-answer pair for an envelope.
    If passphrase is provided, encrypt and store it using the recovery answer as the key.
    """
    _ensure_dir()
    with open(RECOVERY_FILE, "r") as f:
        data = json.load(f)
    
    if envelope_id not in data:
        data[envelope_id] = {}
    
    # Hash the answer for verification
    answer_normalized = answer.encode().lower().strip()
    data[envelope_id][question] = hashlib.sha256(answer_normalized).hexdigest()
    
    # If passphrase is provided, encrypt and store it
    if passphrase:
        # Derive encryption key from recovery answer
        salt = get_random_bytes(16)
        key = derive_master_key(answer_normalized.decode('utf-8'), salt, dklen=32)
        
        # Encrypt the passphrase
        iv, encrypted_passphrase = encrypt_aes(passphrase.encode('utf-8'), key)
        
        # Store encrypted passphrase along with salt and IV
        data[envelope_id][f"{question}_encrypted_passphrase"] = {
            "salt_b64": base64.b64encode(salt).decode('ascii'),
            "iv_b64": base64.b64encode(iv).decode('ascii'),
            "ct_b64": base64.b64encode(encrypted_passphrase).decode('ascii')
        }
    
    with open(RECOVERY_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Recovery question saved for envelope: {envelope_id}")


def verify_recovery_answer(envelope_id: str, question: str, answer: str) -> Tuple[bool, Optional[str]]:
    """
    Verify if the answer to a recovery question is correct.
    Returns (is_correct, recovered_passphrase) tuple.
    If correct and passphrase was stored, returns the decrypted passphrase.
    """
    _ensure_dir()
    try:
        with open(RECOVERY_FILE, "r") as f:
            data = json.load(f)
        
        envelope_data = data.get(envelope_id)
        if not envelope_data:
            print(f"No recovery questions found for envelope: {envelope_id}")
            return False, None
        
        stored_hash = envelope_data.get(question)
        if not stored_hash:
            print(f"Question not found for this envelope: {question}")
            return False, None
        
        answer_normalized = answer.encode().lower().strip()
        answer_hash = hashlib.sha256(answer_normalized).hexdigest()
        
        if answer_hash == stored_hash:
            print("Correct recovery answer!")
            
            # Try to decrypt and return stored passphrase
            encrypted_key = f"{question}_encrypted_passphrase"
            if encrypted_key in envelope_data:
                try:
                    encrypted_data = envelope_data[encrypted_key]
                    salt = base64.b64decode(encrypted_data["salt_b64"])
                    iv = base64.b64decode(encrypted_data["iv_b64"])
                    ct = base64.b64decode(encrypted_data["ct_b64"])
                    
                    # Derive key from recovery answer (same as during encryption)
                    key = derive_master_key(answer_normalized.decode('utf-8'), salt, dklen=32)
                    
                    # Decrypt passphrase
                    passphrase_bytes = decrypt_aes(ct, key, iv)
                    recovered_passphrase = passphrase_bytes.decode('utf-8')
                    
                    return True, recovered_passphrase
                except Exception as e:
                    print(f"Error decrypting passphrase: {str(e)}")
                    return True, None  # Answer correct but couldn't decrypt
            
            return True, None  # Answer correct but no passphrase stored
        
        print("Incorrect recovery answer.")
        return False, None
    except Exception as e:
        print(f"Error verifying recovery answer: {str(e)}")
        return False, None


def get_recovery_questions_for_envelope(envelope_id: str) -> Optional[Dict[str, str]]:
    """Get all recovery questions for an envelope."""
    _ensure_dir()
    try:
        with open(RECOVERY_FILE, "r") as f:
            data = json.load(f)
        return data.get(envelope_id, None)
    except Exception:
        return None


# Backward compatibility aliases
def add_hint(username: str, hint: str):
    """Deprecated: Use add_recovery_question instead."""
    add_recovery_question(username, "Hint", hint)


def check_hint(username: str, guess: str) -> bool:
    """Deprecated: Use verify_recovery_answer instead."""
    return verify_recovery_answer(username, "Hint", guess)
