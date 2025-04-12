import os
import base64
import hashlib
import getpass  # For secure password input
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Constants for key derivation
SCRYPT_N = 2**14    # CPU/memory cost factor
SCRYPT_R = 8        # Block size parameter
SCRYPT_P = 1        # Parallelization parameter

# Path to key file
key_file_path = "./app_data/key.bin"

# Regenerate the encryption key file from a NEW master password
def regenerate_key_from_password():
    print("\n*** SECURITY WARNING ***")
    print("This script is for emergency use ONLY, such as when the original master password is lost.")
    print("Running this script will generate a NEW encryption key based on a NEW master password.")
    print("==> ALL previously encrypted account data will become PERMANENTLY INACCESSIBLE <= ")
    print("    unless you have manually backed up the OLD key file ('key.bin') and know the OLD master password.")
    print(f"The current key file ('{key_file_path}') will be backed up to '{key_file_path}.bak' if it exists.")
    print("You MUST remember the NEW master password you enter here to encrypt/decrypt future data.")
    print("Consider using the application's backup/restore feature instead if possible.")
    
    confirm = input("\nType 'REGENERATE KEY' to confirm you understand the risks and wish to proceed: ")
    if confirm.strip() != 'REGENERATE KEY':
        print("Operation cancelled.")
        return

    # Generate a new encryption key
    salt = os.urandom(16)
    
    # Get password securely from user
    password_str = getpass.getpass("Enter a strong master password for encryption: ")
    password_confirm = getpass.getpass("Confirm master password: ")

    if password_str != password_confirm:
        print("Passwords do not match. Key generation cancelled.")
        return

    if not password_str:
        print("Password cannot be empty. Key generation cancelled.")
        return
        
    password = password_str.encode('utf-8') # Encode password to bytes
    
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
    
    # Backup old key file if it exists
    if os.path.exists(key_file_path):
        backup_path = key_file_path + ".bak"
        print(f"Backing up existing key file to {backup_path}")
        try:
            os.rename(key_file_path, backup_path)
        except OSError as e:
            print(f"Error backing up key file: {e}")
            print("Key generation cancelled.")
            return
    
    # Save the new salt and key
    try:
        with open(key_file_path, "wb") as f:
            f.write(salt + key) # Store salt first, then key
    except IOError as e:
        print(f"Error writing new key file: {e}")
        # Attempt to restore backup if backup succeeded
        if os.path.exists(backup_path):
             try:
                 os.rename(backup_path, key_file_path)
                 print("Restored backup key file.")
             except OSError as re:
                 print(f"CRITICAL: Failed to write new key AND failed to restore backup: {re}")
        return
    
    # Test the key to make sure it works with Fernet
    cipher = Fernet(key)
    test_data = cipher.encrypt(b"test")
    print(f"Created new key file at {key_file_path}")
    print(f"Key is valid for Fernet encryption: {bool(test_data)}")

if __name__ == "__main__":
    regenerate_key_from_password() 