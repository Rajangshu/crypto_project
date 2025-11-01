"""
SecureTalk - Streamlit GUI
Offline Encrypted Messenger with Web Interface
"""

import streamlit as st
import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple

# Import existing modules
from timed_lock import compute_time_window, format_ts
from file_envelope import encrypt_file, decrypt_file_envelope
from envelope import build_envelope, verify_envelope_and_extract
from crypto import derive_master_key, encrypt_aes, decrypt_aes, encrypt_des, decrypt_des
from passphrase_helper import (
    get_recovery_questions, 
    add_recovery_question, 
    verify_recovery_answer,
    get_recovery_questions_for_envelope
)
from Crypto.Random import get_random_bytes

# Page config
st.set_page_config(
    page_title="SecureTalk - Encrypted Messenger",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional CSS styling
st.markdown("""
    <style>
    /* Import Google Font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Main container */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1200px;
    }
    
    /* Header styling */
    .main-header {
        font-family: 'Inter', sans-serif;
        font-size: 2.8rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        padding: 1.5rem 0;
        margin-bottom: 0.5rem;
        letter-spacing: -0.02em;
    }
    
    /* Section headers */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 600;
        color: #2d3748;
        letter-spacing: -0.01em;
    }
    
    /* Cards and boxes */
    .success-box {
        padding: 1.25rem;
        border-radius: 12px;
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        border: 2px solid #28a745;
        color: #155724;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(40, 167, 69, 0.15);
        font-family: 'Inter', sans-serif;
    }
    
    .error-box {
        padding: 1.25rem;
        border-radius: 12px;
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        border: 2px solid #dc3545;
        color: #721c24;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(220, 53, 69, 0.15);
        font-family: 'Inter', sans-serif;
    }
    
    .info-box {
        padding: 1.25rem;
        border-radius: 12px;
        background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
        border: 2px solid #17a2b8;
        color: #0c5460;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(23, 162, 184, 0.15);
        font-family: 'Inter', sans-serif;
    }
    
    .warning-box {
        padding: 1.25rem;
        border-radius: 12px;
        background: linear-gradient(135deg, #fff3cd 0%, #ffeeba 100%);
        border: 2px solid #ffc107;
        color: #856404;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(255, 193, 7, 0.15);
        font-family: 'Inter', sans-serif;
    }
    
    /* Input fields */
    .stTextInput > div > div > input, .stTextArea > div > div > textarea {
        border-radius: 8px;
        border: 2px solid #e2e8f0;
        transition: all 0.3s ease;
    }
    
    .stTextInput > div > div > input:focus, .stTextArea > div > div > textarea:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        font-family: 'Inter', sans-serif;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    }
    
    /* Selectbox */
    .stSelectbox > div > div {
        border-radius: 8px;
        border: 2px solid #e2e8f0;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #f7fafc 0%, #edf2f7 100%);
    }
    
    [data-testid="stSidebar"] > div:first-child {
        padding-top: 2rem;
    }
    
    /* Code blocks */
    code {
        font-family: 'Fira Code', 'Consolas', monospace;
        background: #f7fafc;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.9em;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        font-family: 'Inter', sans-serif;
        font-weight: 600;
        color: #2d3748;
    }
    
    /* Divider */
    hr {
        border: none;
        height: 2px;
        background: linear-gradient(90deg, transparent, #e2e8f0, transparent);
        margin: 2rem 0;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables"""
    
    desktop_path = Path.home() / "Desktop"

    envelopes_dir_path = desktop_path / "securetalk_envelopes"
    decrypted_dir_path = desktop_path / "securetalk_decrypted"
    
    if 'envelopes_dir' not in st.session_state:
        st.session_state.envelopes_dir = str(envelopes_dir_path)
        envelopes_dir_path.mkdir(parents=True, exist_ok=True)
    
    if 'decrypted_dir' not in st.session_state:
        st.session_state.decrypted_dir = str(decrypted_dir_path)
        decrypted_dir_path.mkdir(parents=True, exist_ok=True)


def display_header():
    """Display app header"""
    st.markdown("""
    <div style="text-align: center; padding: 2rem 0;">
        <h1 class="main-header">🔒 SecureTalk</h1>
        <p style="font-family: 'Inter', sans-serif; color: #718096; font-size: 1.1rem; margin-top: -0.5rem;">
            Offline Encrypted Messenger • Enterprise-Grade Security
        </p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")


def send_text_ui():
    """UI for encrypting text messages"""
    st.markdown("### 📝 Encrypt Text Message")
    st.markdown("Encrypt your sensitive text messages with industry-standard encryption algorithms.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        message = st.text_area(
            "Enter your message",
            height=200,
            placeholder="Type your secret message here..."
        )
        
        upload_file = st.file_uploader(
            "Or upload a text file",
            type=['txt', 'md'],
            help="Upload a text file to encrypt its contents"
        )
        
        if upload_file:
            message = upload_file.read().decode('utf-8')
            st.text_area("Message from file", value=message, height=100, disabled=True)
    
    with col2:
        st.subheader("🔐 Encryption Settings")
        cipher_choice_text = st.selectbox(
            "Encryption Algorithm",
            ["aes", "des"],
            index=0,
            key="text_cipher_choice",
            help="AES (recommended): More secure, stronger encryption. DES: Legacy option, weaker security."
        )
        
        if cipher_choice_text == "aes":
            st.info("✅ **AES-256-CBC**: Industry-standard, highly secure encryption")
        else:
            st.warning("⚠️ **DES-CBC**: Legacy encryption, less secure. Use only for compatibility.")
        
        st.markdown("---")
        st.subheader("⏰ Time-Lock Settings")
        unlock_in = st.text_input(
            "Unlock in (e.g., 5m, 1h, 1d)",
            key="text_unlock_in",
            help="Message will be decryptable after this duration"
        )
        expire_in = st.text_input(
            "Expire in (e.g., 2h, 1d)",
            key="text_expire_in",
            help="Message will expire after this duration"
        )
        
        if unlock_in or expire_in:
            try:
                unlock_after, expires_at = compute_time_window(unlock_in, expire_in)
                if unlock_after:
                    st.info(f"🔓 Unlock: {format_ts(unlock_after)}")
                if expires_at:
                    st.info(f"⏱️ Expire: {format_ts(expires_at)}")
            except ValueError as e:
                st.error(str(e))
    
    passphrase_text = st.text_input(
        "Enter passphrase",
        type="password",
        key="send_text_passphrase",
        help="This passphrase will be used to encrypt your message"
    )
    
    # Recovery questions section
    st.markdown("### 🔐 Recovery Questions (Optional but Recommended)")
    st.info("Set up a security question to help recover your passphrase if you forget it.")
    
    recovery_questions = get_recovery_questions()
    selected_question = st.selectbox(
        "Select a security question",
        [""] + list(recovery_questions.keys()),
        key="text_recovery_question",
        help="Choose a question you'll remember the answer to"
    )
    
    custom_question = None
    if selected_question == "Custom Question":
        custom_question = st.text_input(
            "Enter your custom question",
            key="text_custom_question",
            placeholder="e.g., What is your favorite book?"
        )
        if not custom_question:
            st.warning("⚠️ Please enter a custom question")
        else:
            selected_question = custom_question
    
    recovery_answer_text = st.text_input(
        "Answer to security question",
        type="password",
        key="text_recovery_answer",
        help="Your answer (will be hashed for security)",
        disabled=not selected_question
    )
    
    if st.button("🔐 Encrypt Message", type="primary", use_container_width=True):
        if not message:
            st.error("Please enter a message or upload a file")
            return
        
        if not passphrase_text:
            st.warning("Please enter a passphrase")
            return
        
        # Clean passphrase (strip whitespace)
        passphrase_text = passphrase_text.strip()
        
        try:
            with st.spinner("Encrypting message..."):
                # Compute time window
                unlock_after, expires_at = compute_time_window(unlock_in, expire_in)
                
                # Derive keys
                salt = get_random_bytes(16)
                master = derive_master_key(passphrase_text, salt, dklen=64)
                
                # Choose encryption method based on selection
                if cipher_choice_text == "aes":
                    enc_key = master[:32]  # AES-256
                    mac_key = master[32:64]
                    iv, ct = encrypt_aes(message.encode(), enc_key)
                    cipher_name = "AES-CBC"
                else:  # des
                    enc_key = master[:8]  # DES key (8 bytes)
                    mac_key = master[8:40]
                    iv, ct = encrypt_des(message.encode(), enc_key)
                    cipher_name = "DES-CBC"
                
                # Build envelope
                env = build_envelope(cipher_name, iv, salt, ct, mac_key,
                                   unlock_after=unlock_after, expires_at=expires_at)
                env["type"] = "text"
                env["length"] = len(message)
                env["created_at"] = int(time.time())
                
                # Recalculate MAC after adding extra fields
                from envelope import canonical_bytes
                from crypto import hmac_hex
                env_no_mac = {k: v for k, v in env.items() if k != "mac"}
                env["mac"] = hmac_hex(mac_key, canonical_bytes(env_no_mac))
                
                # Save envelope
                filename = f"message_{int(time.time())}.json"
                filepath = os.path.join(st.session_state.envelopes_dir, filename)
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(env, f, indent=2)
                
                st.success(f"✅ Message encrypted successfully!")
                st.warning("⚠️ **Important**: Files stored on Streamlit Cloud are temporary. Always download your encrypted envelope!")
                st.markdown(f'<div class="success-box"><strong>Envelope saved temporarily:</strong> {filepath}</div>', unsafe_allow_html=True)
                
                if unlock_after or expires_at:
                    st.info(f"🔓 Unlock: {format_ts(unlock_after)} | ⏱️ Expire: {format_ts(expires_at)}")
                
                # Save recovery question if provided (with encrypted passphrase)
                if selected_question and recovery_answer_text:
                    try:
                        # Use filename as envelope ID
                        envelope_id = filename.replace('.json', '')
                        question_to_save = custom_question if custom_question else selected_question
                        add_recovery_question(envelope_id, question_to_save, recovery_answer_text, passphrase_text)
                        st.success(f"🔐 Recovery question saved! Your passphrase is encrypted and can be recovered if you answer the question correctly.")
                        
                        # For cloud deployment: Offer to download recovery data
                        recovery_data = get_recovery_questions_for_envelope(envelope_id)
                        if recovery_data:
                            recovery_json = json.dumps({envelope_id: recovery_data}, indent=2)
                            st.download_button(
                                label="📥 Download Recovery Data (Optional)",
                                data=recovery_json,
                                file_name=f"recovery_{envelope_id}.json",
                                mime="application/json",
                                help="Download this to store recovery questions locally (for Streamlit Cloud)"
                            )
                    except Exception as e:
                        st.warning(f"⚠️ Recovery question could not be saved: {str(e)}")
                
                # Download button
                with open(filepath, "rb") as f:
                    st.download_button(
                        label="📥 Download Encrypted Envelope",
                        data=json.dumps(env, indent=2),
                        file_name=filename,
                        mime="application/json"
                    )
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")


def send_file_ui():
    """UI for encrypting files"""
    st.markdown("### 📁 Encrypt File")
    st.markdown("Protect any file type with strong encryption and optional time-lock features.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        uploaded_file = st.file_uploader(
            "Choose a file to encrypt",
            type=None,
            help="Upload any file type to encrypt"
        )
        
        if uploaded_file:
            file_details = {
                "Filename": uploaded_file.name,
                "FileType": uploaded_file.type,
                "FileSize": f"{uploaded_file.size / 1024:.2f} KB"
            }
            st.json(file_details)
            
            # Save uploaded file temporarily
            temp_path = os.path.join(st.session_state.envelopes_dir, f"temp_{uploaded_file.name}")
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            st.session_state.temp_file_path = temp_path
    
    with col2:
        st.subheader("⏰ Time-Lock Settings")
        unlock_in = st.text_input(
            "Unlock in",
            key="file_unlock_in",
            help="e.g., 5m, 1h, 1d"
        )
        expire_in = st.text_input(
            "Expire in",
            key="file_expire_in",
            help="e.g., 2h, 1d"
        )
        
        cipher_choice = st.selectbox(
            "Encryption Algorithm",
            ["aes", "des"],
            help="AES is more secure (recommended)"
        )
        
        if unlock_in or expire_in:
            try:
                unlock_after, expires_at = compute_time_window(unlock_in, expire_in)
                if unlock_after:
                    st.info(f"🔓 Unlock: {format_ts(unlock_after)}")
                if expires_at:
                    st.info(f"⏱️ Expire: {format_ts(expires_at)}")
            except ValueError as e:
                st.error(str(e))
    
    passphrase_file = st.text_input(
        "Enter passphrase",
        type="password",
        key="send_file_passphrase",
        help="This passphrase will be used to encrypt your file"
    )
    
    # Recovery questions section
    st.markdown("### 🔐 Recovery Questions (Optional but Recommended)")
    st.info("Set up a security question to help recover your passphrase if you forget it.")
    
    recovery_questions_file = get_recovery_questions()
    selected_question_file = st.selectbox(
        "Select a security question",
        [""] + list(recovery_questions_file.keys()),
        key="file_recovery_question",
        help="Choose a question you'll remember the answer to"
    )
    
    custom_question_file = None
    if selected_question_file == "Custom Question":
        custom_question_file = st.text_input(
            "Enter your custom question",
            key="file_custom_question",
            placeholder="e.g., What is your favorite book?"
        )
        if not custom_question_file:
            st.warning("⚠️ Please enter a custom question")
        else:
            selected_question_file = custom_question_file
    
    recovery_answer_file = st.text_input(
        "Answer to security question",
        type="password",
        key="file_recovery_answer",
        help="Your answer (will be hashed for security)",
        disabled=not selected_question_file
    )
    
    if st.button("🔐 Encrypt File", type="primary", use_container_width=True):
        if 'temp_file_path' not in st.session_state or not os.path.exists(st.session_state.temp_file_path):
            st.error("Please upload a file first")
            return
        
        if not passphrase_file:
            st.warning("Please enter a passphrase")
            return
        
        # Clean passphrase (strip whitespace)
        passphrase_file = passphrase_file.strip()
        
        try:
            with st.spinner("Encrypting file..."):
                unlock_after, expires_at = compute_time_window(unlock_in, expire_in)
                
                env = encrypt_file(
                    st.session_state.temp_file_path,
                    passphrase_file,
                    cipher_name=cipher_choice,
                    unlock_after=unlock_after,
                    expires_at=expires_at
                )
                
                # Save envelope
                filename = f"file_{int(time.time())}.json"
                filepath = os.path.join(st.session_state.envelopes_dir, filename)
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(env, f, indent=2)
                
                # Clean up temp file
                if os.path.exists(st.session_state.temp_file_path):
                    os.remove(st.session_state.temp_file_path)
                del st.session_state.temp_file_path
                
                st.success(f"✅ File encrypted successfully!")
                st.warning("⚠️ **Important**: Files stored on Streamlit Cloud are temporary. Always download your encrypted envelope!")
                st.markdown(f'<div class="success-box"><strong>Envelope saved temporarily:</strong> {filepath}</div>', unsafe_allow_html=True)
                
                if unlock_after or expires_at:
                    st.info(f"🔓 Unlock: {format_ts(unlock_after)} | ⏱️ Expire: {format_ts(expires_at)}")
                
                # Save recovery question if provided (with encrypted passphrase)
                if selected_question_file and recovery_answer_file:
                    try:
                        # Use filename as envelope ID
                        envelope_id = filename.replace('.json', '')
                        question_to_save = custom_question_file if custom_question_file else selected_question_file
                        add_recovery_question(envelope_id, question_to_save, recovery_answer_file, passphrase_file)
                        st.success(f"🔐 Recovery question saved! Your passphrase is encrypted and can be recovered if you answer the question correctly.")
                        
                        # For cloud deployment: Offer to download recovery data
                        recovery_data = get_recovery_questions_for_envelope(envelope_id)
                        if recovery_data:
                            recovery_json = json.dumps({envelope_id: recovery_data}, indent=2)
                            st.download_button(
                                label="📥 Download Recovery Data (Optional)",
                                data=recovery_json,
                                file_name=f"recovery_{envelope_id}.json",
                                mime="application/json",
                                help="Download this to store recovery questions locally (for Streamlit Cloud)"
                            )
                    except Exception as e:
                        st.warning(f"⚠️ Recovery question could not be saved: {str(e)}")
                
                # Download button
                with open(filepath, "rb") as f:
                    st.download_button(
                        label="📥 Download Encrypted Envelope",
                        data=json.dumps(env, indent=2),
                        file_name=filename,
                        mime="application/json"
                    )
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")
            if 'temp_file_path' in st.session_state and os.path.exists(st.session_state.temp_file_path):
                os.remove(st.session_state.temp_file_path)


def recv_ui():
    """UI for decrypting envelopes"""
    st.markdown("### 🔓 Decrypt Message/File")
    st.markdown("Recover your encrypted messages and files using your passphrase or security question.")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        uploaded_envelope = st.file_uploader(
            "Upload encrypted envelope (JSON)",
            type=['json'],
            help="Upload a .json file containing an encrypted envelope"
        )
        
        # Also allow browsing local envelopes
        if os.path.exists(st.session_state.envelopes_dir):
            envelope_files = [f for f in os.listdir(st.session_state.envelopes_dir) if f.endswith('.json')]
            if envelope_files:
                st.subheader("Or select from saved envelopes:")
                selected_envelope = st.selectbox("Select envelope", [""] + envelope_files, key="selected_envelope")
            else:
                selected_envelope = ""
        else:
            selected_envelope = ""
    
    with col2:
        st.info("""
        **Instructions:**
        1. Upload an encrypted envelope JSON file
        2. Enter the passphrase used for encryption
        3. (Optional) If you forgot the passphrase, expand "Forgot your passphrase?" to answer your security question
        4. Click decrypt to recover the message/file
        """)
        
        # Show cipher info if envelope is selected
        cipher_info = None
        if uploaded_envelope:
            try:
                uploaded_envelope.seek(0)
                file_bytes = uploaded_envelope.read()
                temp_env = json.loads(file_bytes.decode('utf-8'))
                cipher_info = temp_env.get("cipher", "Unknown")
                uploaded_envelope.seek(0)  # Reset for later use
            except:
                pass
        elif st.session_state.get('selected_envelope') and st.session_state.selected_envelope:
            envelope_path = os.path.join(st.session_state.envelopes_dir, st.session_state.selected_envelope)
            try:
                with open(envelope_path, "r", encoding="utf-8") as f:
                    temp_env = json.load(f)
                    cipher_info = temp_env.get("cipher", "Unknown")
            except:
                pass
        
        if cipher_info:
            if "AES" in cipher_info.upper():
                st.success(f"🔐 **Encryption Algorithm:** {cipher_info} (Secure)")
            elif "DES" in cipher_info.upper():
                st.warning(f"🔐 **Encryption Algorithm:** {cipher_info} (Legacy)")
            else:
                st.info(f"🔐 **Encryption Algorithm:** {cipher_info}")
        
        # Allow uploading recovery data if not found
        st.markdown("---")
        st.markdown("**💾 Upload Recovery Data (Optional)**")
        st.caption("If you downloaded recovery data when encrypting, upload it here to enable recovery questions.")
        uploaded_recovery = st.file_uploader(
            "Upload recovery JSON file",
            type=['json'],
            key="upload_recovery_data",
            help="Upload the recovery JSON file you downloaded during encryption"
        )
        
        if uploaded_recovery:
            try:
                uploaded_recovery.seek(0)
                recovery_data_content = json.loads(uploaded_recovery.read().decode('utf-8'))
                
                # Load recovery data into the system
                from passphrase_helper import RECOVERY_FILE, _ensure_dir
                import json as json_module
                _ensure_dir()
                
                with open(RECOVERY_FILE, "r") as f:
                    existing_data = json_module.load(f)
                
                # Merge uploaded recovery data
                for env_id, rec_data in recovery_data_content.items():
                    if env_id not in existing_data:
                        existing_data[env_id] = {}
                    existing_data[env_id].update(rec_data)
                
                # Save merged data
                with open(RECOVERY_FILE, "w") as f:
                    json_module.dump(existing_data, f, indent=2)
                
                st.success(f"✅ Recovery data loaded successfully! Recovery questions are now available.")
            except Exception as e:
                st.error(f"Error loading recovery data: {str(e)}")
    
    # Show recovered passphrase if available
    recovered_pass = st.session_state.get('recovered_passphrase', '')
    if recovered_pass:
        st.info("💡 **Recovered passphrase available** - Fill it in the field below:")
    
    passphrase_recv = st.text_input(
        "Enter passphrase",
        type="password",
        key="recv_passphrase",
        help="Enter the passphrase used to encrypt this envelope",
        value=recovered_pass if recovered_pass else ""
    )
    
    # Clear recovered passphrase from session after showing once
    if recovered_pass and passphrase_recv != recovered_pass:
        st.session_state['recovered_passphrase'] = ''
    
    # Recovery questions section (if user forgot passphrase)
    with st.expander("🔐 Forgot your passphrase? Answer your security question", expanded=False):
        st.markdown("**If you set up a security question during encryption, answer it here to help remember your passphrase.**")
        
        # Try to get recovery questions for selected/uploaded envelope
        recovery_question_for_envelope = None
        envelope_id_for_recovery = None
        
        # Determine envelope ID from uploaded file or selected envelope
        if uploaded_envelope:
            envelope_id_for_recovery = uploaded_envelope.name.replace('.json', '') if uploaded_envelope.name else None
        elif st.session_state.get('selected_envelope') and st.session_state.selected_envelope:
            envelope_id_for_recovery = st.session_state.selected_envelope.replace('.json', '')
        
        if envelope_id_for_recovery:
            recovery_data = get_recovery_questions_for_envelope(envelope_id_for_recovery)
            if recovery_data and len(recovery_data) > 0:
                recovery_question_for_envelope = list(recovery_data.keys())[0]
                st.info(f"**Your security question:** {recovery_question_for_envelope}")
            else:
                st.info("ℹ️ No recovery question found for this envelope. If you set one up during encryption, make sure you're using the same envelope file.")
        else:
            st.info("ℹ️ Please upload or select an envelope first to see if a recovery question is available.")
        
        if recovery_question_for_envelope:
            recovery_answer_input = st.text_input(
                "Your answer",
                type="password",
                key="decrypt_recovery_answer",
                help="Enter the answer to your security question"
            )
            if st.button("🔍 Verify Answer", key="verify_recovery_decrypt"):
                if recovery_answer_input and envelope_id_for_recovery:
                    try:
                        is_correct, recovered_passphrase = verify_recovery_answer(envelope_id_for_recovery, recovery_question_for_envelope, recovery_answer_input)
                        if is_correct:
                            if recovered_passphrase:
                                st.success("✅ **Correct answer! Your passphrase has been recovered:**")
                                st.markdown(f'<div class="success-box"><strong>🔑 Your Passphrase:</strong><br><code style="font-size: 1.2em; background: #f0f0f0; padding: 0.5em; border-radius: 5px;">{recovered_passphrase}</code></div>', unsafe_allow_html=True)
                                st.info("💡 **Copy this passphrase and paste it in the passphrase field above to decrypt your message.**")
                                
                                # Auto-fill passphrase in session state for convenience
                                st.session_state['recovered_passphrase'] = recovered_passphrase
                            else:
                                st.warning("✅ Answer is correct, but no passphrase was stored for recovery. You'll need to remember your passphrase.")
                        else:
                            st.error("❌ Incorrect answer. Double-check your answer.")
                    except Exception as e:
                        st.error(f"Error verifying answer: {str(e)}")
                else:
                    st.warning("Please enter an answer")
    
    if st.button("🔓 Decrypt", type="primary", use_container_width=True):
        # Determine which envelope to use
        env_data = None
        envelope_name = None
        
        if uploaded_envelope:
            try:
                # Streamlit file uploader returns BytesIO - need to read and decode
                uploaded_envelope.seek(0)  # Reset to beginning
                file_bytes = uploaded_envelope.read()
                env_data = json.loads(file_bytes.decode('utf-8'))
                envelope_name = uploaded_envelope.name
            except Exception as e:
                st.error(f"Invalid JSON file: {str(e)}")
                return
        elif st.session_state.get('selected_envelope') and st.session_state.selected_envelope:
            envelope_path = os.path.join(st.session_state.envelopes_dir, st.session_state.selected_envelope)
            try:
                with open(envelope_path, "r", encoding="utf-8") as f:
                    env_data = json.load(f)
                envelope_name = st.session_state.selected_envelope
            except Exception as e:
                st.error(f"Error reading envelope: {str(e)}")
                return
        else:
            st.error("Please upload or select an envelope")
            return
        
        if not passphrase_recv:
            st.warning("Please enter the passphrase")
            return
        
        # Clean passphrase (strip whitespace)
        passphrase_recv = passphrase_recv.strip()
        
        try:
            with st.spinner("Decrypting..."):
                if env_data.get("type") == "file":
                    # Decrypt file
                    out_path = decrypt_file_envelope(
                        env_data,
                        passphrase_recv,
                        out_dir=st.session_state.decrypted_dir
                    )
                    st.success(f"✅ File decrypted successfully!")
                    # Clear recovered passphrase after successful decryption
                    if 'recovered_passphrase' in st.session_state:
                        del st.session_state['recovered_passphrase']
                    st.markdown(f'<div class="success-box"><strong>File saved:</strong> {out_path}</div>', unsafe_allow_html=True)
                    
                    # Download button for decrypted file
                    with open(out_path, "rb") as f:
                        file_data = f.read()
                        st.download_button(
                            label="📥 Download Decrypted File",
                            data=file_data,
                            file_name=os.path.basename(out_path),
                            mime="application/octet-stream"
                        )
                else:
                    # Decrypt text message
                    extracted = verify_envelope_and_extract(env_data, passphrase_recv)
                    iv = extracted["iv"]
                    ct = extracted["ciphertext"]
                    enc_key = extracted["enc_key"]
                    cipher_name = extracted["cipher"]
                    
                    # Use the cipher specified in the envelope
                    if cipher_name.startswith("AES"):
                        pt = decrypt_aes(ct, enc_key, iv)
                    elif cipher_name.startswith("DES"):
                        pt = decrypt_des(ct, enc_key, iv)
                    else:
                        raise ValueError(f"Unsupported cipher: {cipher_name}")
                    
                    message = pt.decode()
                    
                    st.success(f"✅ Message decrypted successfully!")
                    # Clear recovered passphrase after successful decryption
                    if 'recovered_passphrase' in st.session_state:
                        del st.session_state['recovered_passphrase']
                    st.markdown(f'<div class="success-box"><strong>Message:</strong></div>', unsafe_allow_html=True)
                    st.text_area("Decrypted message", value=message, height=200, disabled=False)
                    
                    # Download button
                    st.download_button(
                        label="📥 Download Decrypted Message",
                        data=message,
                        file_name="decrypted_message.txt",
                        mime="text/plain"
                    )
        except ValueError as e:
            error_msg = str(e)
            if "not yet available" in error_msg.lower():
                st.warning(f"⏰ {error_msg}")
            elif "expired" in error_msg.lower():
                st.warning(f"⏰ {error_msg}")
            elif "mac verification failed" in error_msg.lower():
                st.error(f"🔒 Security Error: {error_msg}")
                st.info("💡 **Troubleshooting Tips:**\n- Double-check the passphrase is correct\n- Ensure the envelope file wasn't modified or corrupted\n- Try re-encrypting with the same passphrase to verify")
            elif "missing fields" in error_msg.lower():
                st.error(f"❌ Invalid Envelope: {error_msg}")
                st.info("💡 The envelope file appears to be incomplete or corrupted.")
            else:
                st.error(f"❌ Decryption failed: {error_msg}")
        except Exception as e:
            st.error(f"❌ Decryption failed: {str(e)}")
            st.exception(e)  # Show full traceback for debugging


def about_ui():
    """About page"""
    st.header("ℹ️ About SecureTalk")
    
    st.markdown("""
    ### Features
    
    - **🔐 Strong Encryption**: AES-256-CBC and DES-CBC encryption
    - **🛡️ Integrity Protection**: HMAC-SHA256 verification
    - **⏰ Time-Lock**: Control when messages can be decrypted (times displayed in IST - Indian Standard Time)
    - **📁 File Support**: Encrypt any file type
    - **🔐 Recovery Questions**: Set up security questions to help recover forgotten passphrases
    - **🌐 Offline**: Works completely offline, no internet required
    
    ### Security
    
    - Passphrase-based key derivation (PBKDF2-HMAC-SHA256, 200,000 iterations)
    - HMAC-SHA256 for message integrity
    - Time-lock prevents decryption before/after specified times
    - All encryption happens locally in your browser
    
    ### How It Works
    
    1. **Encrypt**: Enter a message or upload a file, set a passphrase, optionally set time-locks
    2. **Share**: Send the encrypted envelope JSON file to your recipient
    3. **Decrypt**: Recipient uploads the envelope and enters the passphrase
    4. **Access**: Messages/files are decrypted only when time-lock conditions are met
    
    ### Use Cases
    
    - Secure file sharing
    - Time-delayed message delivery
    - Self-destructing messages (via expiration)
    - Offline encrypted communication
    """)


def main():
    """Main application"""
    init_session_state()
    display_header()
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0;">
            <h2 style="font-family: 'Inter', sans-serif; font-weight: 700; color: #2d3748; margin: 0;">
                🔒 SecureTalk
            </h2>
            <p style="font-family: 'Inter', sans-serif; color: #718096; font-size: 0.85rem; margin-top: 0.25rem;">
                Encrypted Messenger
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")
        
        st.markdown("### 📋 Navigation")
        page = st.radio(
            "Navigation",
            ["📝 Encrypt Text", "📁 Encrypt File", "🔓 Decrypt", "ℹ️ About"],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        st.markdown("### ⚙️ Settings")
       
        
        # Show current directories (read-only info)
        st.text(f"Envelopes: {st.session_state.envelopes_dir}")
        st.text(f"Decrypted: {st.session_state.decrypted_dir}")
        
        # Ensure directories exist
        os.makedirs(st.session_state.envelopes_dir, exist_ok=True)
        os.makedirs(st.session_state.decrypted_dir, exist_ok=True)
    
    # Route to appropriate page
    if page == "📝 Encrypt Text":
        send_text_ui()
    elif page == "📁 Encrypt File":
        send_file_ui()
    elif page == "🔓 Decrypt":
        recv_ui()
    elif page == "ℹ️ About":
        about_ui()


if __name__ == "__main__":
    main()

