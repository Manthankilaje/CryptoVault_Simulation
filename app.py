import streamlit as st

# Ensure cryptography is installed
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    import time
    CRYPTO_AVAILABLE = True
except ImportError as e:
    CRYPTO_AVAILABLE = False
    IMPORT_ERROR = str(e)

st.set_page_config(
    page_title="Vault — Hybrid Cryptography Simulation",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 Vault — Secure Hybrid Cryptography System")
st.caption("Interactive Web Simulation: Streamed AES-256-GCM Payload Encryption & RSA-2048 Key Wrapping")

if not CRYPTO_AVAILABLE:
    st.error("❌ Cryptography library missing!")
    st.warning(f"Error details: {IMPORT_ERROR}")
    st.info("Please make sure your GitHub repository has a `requirements.txt` file containing:\n\n```text\nstreamlit\ncryptography\n```")
    st.stop()

# Initialize Session State
if "private_key" not in st.session_state:
    st.session_state.private_key = None
if "public_key" not in st.session_state:
    st.session_state.public_key = None

# Sidebar Key Management
st.sidebar.header("🔑 Key Management Panel")
if st.sidebar.button("Generate RSA-2048 Key Pair", type="primary"):
    with st.spinner("Generating 2048-bit RSA key pair..."):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        st.session_state.private_key = private_key
        st.session_state.public_key = private_key.public_key()
        st.sidebar.success("RSA Key Pair Generated!")

if st.session_state.public_key:
    st.sidebar.success("Status: Key Pair Active")
else:
    st.sidebar.info("Status: No Key Pair Loaded")

# Main Interface
tab1, tab2 = st.tabs(["🔒 File Encryption", "🔓 File Decryption"])

with tab1:
    st.subheader("Encrypt & Wrap Payload")
    uploaded_file = st.file_uploader("Select File to Encrypt", key="enc_file")
    
    if st.button("Start Encryption Process"):
        if not uploaded_file:
            st.warning("Please upload a file first.")
        elif not st.session_state.public_key:
            st.warning("Please generate an RSA Key Pair in the sidebar first.")
        else:
            progress = st.progress(0)
            status = st.empty()
            
            status.info("1/4 Generating 256-bit AES Session Key & IV...")
            time.sleep(0.3)
            session_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(session_key)
            iv = os.urandom(12)
            progress.progress(25)
            
            status.info("2/4 Wrapping AES Key with RSA-2048 (OAEP Padding)...")
            time.sleep(0.3)
            wrapped_key = st.session_state.public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            progress.progress(50)
            
            status.info("3/4 Encrypting payload with AES-256-GCM...")
            file_bytes = uploaded_file.read()
            time.sleep(0.3)
            ciphertext = aesgcm.encrypt(iv, file_bytes, None)
            progress.progress(85)
            
            status.info("4/4 Assembling .vault container file...")
            time.sleep(0.2)
            vault_container = wrapped_key + iv + ciphertext
            progress.progress(100)
            status.success("✅ Encryption Complete!")
            
            st.download_button(
                label="Download .vault Container",
                data=vault_container,
                file_name=f"{uploaded_file.name}.vault",
                mime="application/octet-stream"
            )

with tab2:
    st.subheader("Unwrap & Decrypt Archive")
    vault_file = st.file_uploader("Select .vault File to Decrypt", key="dec_file")
    
    if st.button("Start Decryption Process"):
        if not vault_file:
            st.warning("Please upload a .vault container first.")
        elif not st.session_state.private_key:
            st.warning("Please generate an RSA Key Pair in the sidebar first.")
        else:
            try:
                progress = st.progress(0)
                status = st.empty()
                
                status.info("1/3 Parsing container header...")
                container_data = vault_file.read()
                time.sleep(0.3)
                
                wrapped_key = container_data[:256]
                iv = container_data[256:268]
                ciphertext = container_data[268:]
                progress.progress(35)
                
                status.info("2/3 Unwrapping AES Session Key using RSA Private Key...")
                time.sleep(0.3)
                unwrapped_session_key = st.session_state.private_key.decrypt(
                    wrapped_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                progress.progress(70)
                
                status.info("3/3 Decrypting payload & verifying tag...")
                time.sleep(0.3)
                aesgcm = AESGCM(unwrapped_session_key)
                restored_plaintext = aesgcm.decrypt(iv, ciphertext, None)
                progress.progress(100)
                status.success("✅ Decryption & Tag Verification Successful!")
                
                restored_name = vault_file.name.replace(".vault", "")
                st.download_button(
                    label="Download Decrypted File",
                    data=restored_plaintext,
                    file_name=restored_name,
                    mime="application/octet-stream"
                )
            except Exception:
                st.error("❌ Decryption Failed: Authentication tag mismatch or invalid key!")
