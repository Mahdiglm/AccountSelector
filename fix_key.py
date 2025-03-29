import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Constants for key derivation
SCRYPT_N = 2**14    # CPU/memory cost factor
SCRYPT_R = 8        # Block size parameter
SCRYPT_P = 1        # Parallelization parameter

# Path to key file
key_file_path = "./app_data/key.bin"

# Generate a new key file
def generate_key_file():
    # Generate a new encryption key
    salt = os.urandom(16)
    
    # Use a fixed password (for demo only)
    password = b"AccountSelectorSecureStorageKey"
    
    # Use scrypt for key derivation
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )
    derived_key = kdf.derive(password)
    
    # Create a proper Fernet key
    key = base64.urlsafe_b64encode(derived_key)
    
    # Generate a key check value
    check_value = hashlib.sha256(key).digest()[:8]
    
    # Backup old key file if it exists
    if os.path.exists(key_file_path):
        backup_path = key_file_path + ".bak"
        print(f"Backing up existing key file to {backup_path}")
        os.rename(key_file_path, backup_path)
    
    # Save the key, salt, and check value
    with open(key_file_path, "wb") as f:
        f.write(salt + check_value + key)
    
    # Test the key to make sure it works with Fernet
    cipher = Fernet(key)
    test_data = cipher.encrypt(b"test")
    print(f"Created new key file at {key_file_path}")
    print(f"Key is valid for Fernet encryption: {bool(test_data)}")

if __name__ == "__main__":
    generate_key_file() 