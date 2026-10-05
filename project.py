import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Set Up Asymmetric Keys (RSA)
def generate_user_keys():
    # Generate RSA Private & Public key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

def store_file_securely(input_file_path, public_key):
    # Generate temporary random 256-bit AES Key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    
    # Read original file contents
    with open(input_file_path, "rb") as f:
        file_data = f.read()
    
    # Encrypt file payload using AES Key
    nonce = os.urandom(12)
    encrypted_file_data = aesgcm.encrypt(nonce, file_data, associated_data=None)
    
    # Encrypt AES Key using RSA Public Key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Save the combined encrypted bundle to disk
    output_bundle_path = input_file_path + ".bundle"
    with open(output_bundle_path, "wb") as f:
        # Store key length header
        f.write(len(encrypted_aes_key).to_bytes(2, "big"))
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(encrypted_file_data)
        
    print(f"[+] File stored securely: {output_bundle_path}")
    return output_bundle_path

# Decrypt and Retrieve File
def retrieve_file_securely(bundle_path, restored_output_path, private_key):
    with open(bundle_path, "rb") as f:
        # Read header to know key length
        key_len = int.from_bytes(f.read(2), "big")
        encrypted_aes_key = f.read(key_len)
        nonce = f.read(12)
        encrypted_file_data = f.read()

    # Decrypt AES Key using RSA Private Key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt file payload using recovered AES Key
    aesgcm = AESGCM(aes_key)
    original_data = aesgcm.decrypt(nonce, encrypted_file_data, associated_data=None)

    # Restore original file
    with open(restored_output_path, "wb") as f:
        f.write(original_data)

    print(f"[+] File retrieved and restored: {restored_output_path}")

# Running the pipeline
if __name__ == "__main__":
    private_key, public_key = generate_user_keys()

    print("\n--- HYBRID CRYPTOGRAPHY SECURE STORAGE ---")
    print("1. Encrypt a typed secret message")
    print("2. Encrypt an existing file (Image, PDF, Document, etc.)")
    
    choice = input("\nSelect an option (1 or 2): ").strip()

    if choice == "1":
        user_text = input("\nEnter your secret message: ")
        file_name = "secret_message.txt"
        with open(file_name, "w") as f:
            f.write(user_text)

        bundle = store_file_securely(file_name, public_key)
        retrieve_file_securely(bundle, "restored_message.txt", private_key)

    elif choice == "2":
        file_path = input("\nEnter file name (e.g., photo.png or doc.pdf): ").strip()
        if os.path.exists(file_path):
            bundle = store_file_securely(file_path, public_key)
            out_name = "restored_" + os.path.basename(file_path)
            retrieve_file_securely(bundle, out_name, private_key)
        else:
            print("[-] File not found. Please verify the file path.")

    else:
        print("[-] Invalid choice. Exiting.")
