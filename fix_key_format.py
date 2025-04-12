#!/usr/bin/env python3
"""
Fix Key Format - Utility to fix improperly formatted encryption keys

This script repairs key files with improper base64 padding for Fernet encryption.
"""

import os
import base64
import sys
import shutil
import logging
from cryptography.fernet import Fernet

# Setup basic logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

KEY_FILE = "./app_data/key.bin"
KEY_BACKUP = "./app_data/key.bin.bak"

def fix_key_file():
    """
    Fix the key file by ensuring proper base64 padding.
    """
    if not os.path.exists(KEY_FILE):
        logger.error(f"Key file not found at {KEY_FILE}.")
        return False
    
    # Create a backup of the original key file
    try:
        shutil.copy2(KEY_FILE, KEY_BACKUP)
        logger.info(f"Backup created at {KEY_BACKUP}")
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return False
    
    try:
        # Read the key file
        with open(KEY_FILE, "rb") as f:
            data = f.read()
            
        if len(data) < 16:
            logger.error("Key file is too short (< 16 bytes).")
            print(f"Key file size: {len(data)} bytes")
            return False
            
        # Split into salt and key
        salt = data[:16]
        key = data[16:]
        
        logger.info(f"Original key length: {len(key)} bytes")
        print(f"Original key: {key[:10]}...{key[-10:]} (length={len(key)})")
        
        # Check if key is valid
        is_valid = False
        try:
            Fernet(key)
            is_valid = True
            logger.info("Original key is already valid for Fernet")
        except Exception as e:
            logger.warning(f"Original key is not valid: {e}")
            print(f"Key error: {e}")
        
        if not is_valid:
            # Try to fix the key
            # 1. Check if this is a base64 encoded key
            try:
                # Try to decode the key to see if it's valid base64
                base64.urlsafe_b64decode(key + b'=' * (4 - len(key) % 4))
                logger.info("Key is valid base64 format, applying padding fix")
            except Exception as e:
                logger.warning(f"Key is not valid base64: {e}")
                print(f"The key does not appear to be valid base64: {e}")
            
            # Ensure proper padding
            padding_needed = 4 - (len(key) % 4 if len(key) % 4 else 0)
            if padding_needed < 4:
                fixed_key = key + b'=' * padding_needed
                logger.info(f"Added {padding_needed} padding bytes")
                print(f"Added {padding_needed} padding bytes to fix key")
            else:
                fixed_key = key
            
            # Ensure key is exactly right length for Fernet (32 bytes when decoded)
            try:
                # Attempt to decode to check byte length
                decoded = base64.urlsafe_b64decode(fixed_key)
                logger.info(f"Decoded key length: {len(decoded)} bytes")
                
                if len(decoded) != 32:
                    logger.error(f"Key has incorrect length when decoded: {len(decoded)} bytes (should be 32)")
                    print(f"Error: Decoded key length is {len(decoded)} bytes (should be 32)")
                    return False
            except Exception as e:
                logger.error(f"Failed to decode key: {e}")
                print(f"Error: Failed to decode key: {e}")
                return False
            
            # Try to create a Fernet instance with the fixed key
            try:
                Fernet(fixed_key)
                logger.info("Fixed key is valid for Fernet")
                print("Fixed key is valid for Fernet encryption")
            except Exception as e:
                logger.error(f"Fixed key is still invalid: {e}")
                print(f"Error: Fixed key is still invalid: {e}")
                return False
        else:
            fixed_key = key
            
        # Write the fixed key back to the file
        with open(KEY_FILE, "wb") as f:
            f.write(salt + fixed_key)
        
        logger.info("Key file successfully fixed!")
        print(f"Key file has been successfully fixed! New key length: {len(fixed_key)} bytes")
        return True
    
    except Exception as e:
        logger.error(f"Error fixing key file: {e}")
        print(f"An unexpected error occurred: {e}")
        # Restore from backup if something went wrong
        try:
            shutil.copy2(KEY_BACKUP, KEY_FILE)
            logger.info("Restored original key file from backup")
            print("Restored original key file from backup")
        except Exception as backup_e:
            logger.error(f"Failed to restore backup: {backup_e}")
            print(f"Failed to restore backup: {backup_e}")
        
        return False

def generate_new_key_file():
    """
    Generate a completely new key file if fixing fails.
    This requires setting a new master password.
    Warning: This will make existing encrypted data inaccessible.
    """
    if os.path.exists(KEY_FILE):
        try:
            backup2 = f"{KEY_FILE}.bak2"
            shutil.copy2(KEY_FILE, backup2)
            logger.info(f"Created second backup at {backup2} before generating new key")
            print(f"Created second backup at {backup2}")
        except Exception as e:
            logger.error(f"Failed to create second backup: {e}")
            print(f"Warning: Failed to create second backup: {e}")
    
    try:
        # Generate a new salt
        salt = os.urandom(16)
        
        # Get a new master password
        import getpass
        print("\nWARNING: You are about to generate a new encryption key.")
        print("This will make all existing encrypted data PERMANENTLY INACCESSIBLE!")
        print("Only proceed if you have no important data or have confirmed backups.\n")
        
        confirm = input("Type 'YES' to confirm you want to generate a new key: ")
        if confirm != "YES":
            print("Operation cancelled.")
            return False
        
        master_password = getpass.getpass("Enter a new master password: ")
        confirm_password = getpass.getpass("Confirm master password: ")
        
        if master_password != confirm_password:
            print("Passwords do not match.")
            return False
        
        if not master_password:
            print("Password cannot be empty.")
            return False
        
        # Generate a key using PBKDF2
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        # Validate the key
        try:
            Fernet(key)
            logger.info("New key is valid for Fernet")
            print("New key is valid for Fernet encryption")
        except Exception as e:
            logger.error(f"New key is invalid: {e}")
            print(f"Error: New key is invalid: {e}")
            return False
        
        # Write the new key file
        with open(KEY_FILE, "wb") as f:
            f.write(salt + key)
        
        logger.info("New key file generated successfully")
        print("\nNew key file generated successfully.")
        print("You will now need to re-create your accounts as existing encrypted data is no longer accessible.")
        return True
    
    except Exception as e:
        logger.error(f"Error generating new key file: {e}")
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    """Main function for the script."""
    print("=" * 80)
    print("Account Selector - Key Format Fix Utility")
    print("=" * 80)
    print("This utility will fix improperly formatted encryption keys.")
    print("It will create a backup of your existing key file before making any changes.")
    print()
    
    if not os.path.exists("./app_data"):
        print("Error: app_data directory not found.")
        print("Please run this script from the Account Selector root directory.")
        return 1
    
    if not os.path.exists(KEY_FILE):
        print(f"Error: Key file not found at {KEY_FILE}.")
        print("No action needed or create a new key file?")
        choice = input("Would you like to generate a new key file? (y/n): ").lower()
        if choice == 'y':
            if generate_new_key_file():
                return 0
            else:
                return 1
        return 1
    
    confirm = input("Do you want to proceed with fixing the key file? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        return 0
    
    print("Fixing key file...")
    if fix_key_file():
        print()
        print("Key file has been successfully fixed!")
        print("You should now be able to run the application normally.")
    else:
        print()
        print("Failed to fix key file using standard methods.")
        print(f"A backup was created at {KEY_BACKUP}")
        
        choice = input("Would you like to generate a completely new key file? (y/n): ").lower()
        if choice == 'y':
            if generate_new_key_file():
                return 0
            else:
                return 1
        
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 