import json
import os
import bcrypt
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
import uuid
import base64
import getpass
import hashlib
import time
import shutil
import zipfile
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import logging

from .models import User, Account, UserRole, AccountCategory, Backup

# Get the logger configured in account_selector.py
logger = logging.getLogger(__name__) # Use module-specific logger

# Constants for key derivation
ITERATIONS = 480000  # Increased from 100000 for better security
SCRYPT_N = 2**14    # CPU/memory cost factor
SCRYPT_R = 8        # Block size parameter
SCRYPT_P = 1        # Parallelization parameter

class Storage:
    def __init__(self, data_folder="./app_data", master_password=None):
        self.data_folder = data_folder
        self.users_file = os.path.join(data_folder, "users.json")
        self.accounts_file = os.path.join(data_folder, "accounts.json")
        self.key_file = os.path.join(data_folder, "key.bin")
        self.config_file = os.path.join(data_folder, "config.json")
        
        # Store whether encryption is initialized
        self.encryption_initialized = False
        
        # Create the data directory if it doesn't exist
        os.makedirs(data_folder, exist_ok=True)
        
        # Initialize config FIRST, as it might determine KDF method
        self._initialize_config() 
        
        # Initialize encryption key - requires master password if key doesn't exist
        # We pass master_password here if provided, otherwise _initialize_encryption will handle prompting if needed
        self._initialize_encryption(master_password) 
        
        # Initialize data storage (creates files, default admin if needed and NO key exists)
        self._initialize()
    
    def _initialize_config(self):
        """Initialize configuration settings."""
        default_config = {
            "encryption_method": "scrypt",  # scrypt or pbkdf2
            "password_policy": {
                "min_length": 12,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_special": True,
                "max_age_days": 90
            },
            "backup": {
                "auto_backup": True,
                "backup_interval_days": 7,
                "max_backups": 5,
                "last_backup": None
            }
        }
        
        if not os.path.exists(self.config_file):
            with open(self.config_file, "w") as f:
                json.dump(default_config, f, indent=2)
                
        # Load config
        try:
            with open(self.config_file, "r") as f:
                self.config = json.load(f)
                
                # Update with any new config settings that might not exist in older config files
                updated = False
                for key, value in default_config.items():
                    if key not in self.config:
                        self.config[key] = value
                        updated = True
                    # Also check nested dictionaries
                    elif isinstance(value, dict) and isinstance(self.config[key], dict):
                        for subkey, subvalue in value.items():
                            if subkey not in self.config[key]:
                                self.config[key][subkey] = subvalue
                                updated = True
                
                if updated:
                    # Save the updated config
                    with open(self.config_file, "w") as f:
                        json.dump(self.config, f, indent=2)
        except (IOError, json.JSONDecodeError) as e:
            # If anything goes wrong, use the default config
            logger.warning(f"Error loading or parsing config file '{self.config_file}': {e}. Using default config.", exc_info=True)
            self.config = default_config
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=2)

    def _initialize_encryption(self, master_password=None):
        """
        Initialize encryption. Requires master password if key file is missing or needs verification.
        """
        try:
            if not os.path.exists(self.key_file):
                logger.info("Encryption key file not found.")
                # Prompt for master password if not provided
                while not master_password:
                    logger.info("A master password is required to create the encryption key.")
                    master_password = getpass.getpass("Enter a new master password: ")
                    if not master_password:
                        logger.info("Master password cannot be empty.")
                        continue
                    confirm_password = getpass.getpass("Confirm master password: ")
                    if master_password != confirm_password:
                        logger.info("Passwords do not match. Please try again.")
                        master_password = None # Reset to loop again
                
                logger.info("Generating new encryption key...")
                # Generate a new encryption key
                salt = os.urandom(16)
                password = master_password.encode('utf-8')
                
                # Use the configured key derivation method
                encryption_method = self.config.get("encryption_method", "scrypt")
                if encryption_method == "scrypt":
                    # Use scrypt for key derivation (more secure against hardware attacks)
                    kdf = Scrypt(
                        salt=salt,
                        length=32,
                        n=SCRYPT_N,
                        r=SCRYPT_R,
                        p=SCRYPT_P
                    )
                    derived_key = kdf.derive(password)
                    # Ensure the key is properly formatted for Fernet (must be 32 url-safe base64-encoded bytes)
                    key = base64.urlsafe_b64encode(derived_key)
                else:
                    # Use PBKDF2 for key derivation
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=ITERATIONS,
                    )
                    derived_key = kdf.derive(password)
                    # Ensure the key is properly formatted for Fernet
                    key = base64.urlsafe_b64encode(derived_key)
                
                # Verify the key is valid for Fernet before saving
                try:
                    Fernet(key)
                    logger.info("New key validated successfully")
                except Exception as e:
                    logger.critical(f"Generated key is not valid for Fernet: {e}")
                    raise ValueError(f"Failed to generate a valid encryption key: {e}")
                
                # Save ONLY salt and key
                os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
                with open(self.key_file, "wb") as f:
                    f.write(salt + key)
                logger.info("New encryption key generated and saved.")

            else:
                # Load existing key and salt
                with open(self.key_file, "rb") as f:
                    data = f.read()
                    if len(data) < 16: # Basic check for salt length
                         raise ValueError("Invalid key file format.")
                    salt = data[:16]
                    stored_key = data[16:] # Key starts after salt

                # If master password is provided (e.g., for verification), derive and compare keys
                if master_password is not None:
                    logger.info("Verifying master password...")
                    password = master_password.encode('utf-8')
                    
                    # Use the configured key derivation method
                    encryption_method = self.config.get("encryption_method", "scrypt")
                    if encryption_method == "scrypt":
                        kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
                        derived_key = kdf.derive(password)
                        derived_key = base64.urlsafe_b64encode(derived_key)
                    else: # pbkdf2
                        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
                        derived_key = kdf.derive(password)
                        derived_key = base64.urlsafe_b64encode(derived_key)
                    
                    # Direct comparison of derived key with stored key
                    if derived_key != stored_key:
                        raise ValueError("Invalid master password")
                    
                    # Use the verified key
                    key = derived_key
                    logger.info("Master password verified successfully.")
                else:
                    # Use the stored key directly if no master password provided for verification
                    key = stored_key
            
            # Ensure the key has proper base64 padding if needed
            padding_needed = 4 - (len(key) % 4 if len(key) % 4 else 0)
            if padding_needed < 4:
                key = key + b'=' * padding_needed
                logger.info(f"Applied {padding_needed} bytes of padding to the key")
            
            # Validate the key format
            try:
                # Check if the key is valid base64 and decodes to exactly 32 bytes
                decoded_key = base64.urlsafe_b64decode(key)
                if len(decoded_key) != 32:
                    logger.warning(f"Decoded key has incorrect length: {len(decoded_key)} bytes (should be 32)")
                    raise ValueError(f"Invalid key length: {len(decoded_key)} bytes (should be 32)")
                
                # Initialize the Fernet cipher with the properly formatted key
                self.cipher = Fernet(key)
                self.encryption_initialized = True
                logger.info("Encryption successfully initialized")
            except Exception as e:
                logger.critical(f"Invalid encryption key format: {e}")
                raise ValueError(f"Invalid encryption key format: {e}")
            
        except (IOError, ValueError, InvalidToken) as e:
            logger.critical(f"Error initializing encryption: {str(e)}", exc_info=True)
            self.encryption_initialized = False
            # Depending on context, might need to exit or handle differently
            raise RuntimeError(f"Encryption initialization failed: {str(e)}")
    
    def _encrypt_password(self, password: str) -> str:
        """Encrypt a password."""
        if not self.encryption_initialized:
            raise RuntimeError("Encryption not initialized")
        
        try:
            return self.cipher.encrypt(password.encode()).decode()
        except (TypeError, ValueError) as e: # Catch potential encoding/type errors
            raise RuntimeError(f"Error encrypting password: {str(e)}")
    
    def _decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt an encrypted password."""
        if not self.encryption_initialized:
            raise RuntimeError("Encryption not initialized")
        
        try:
            return self.cipher.decrypt(encrypted_password.encode()).decode()
        except InvalidToken:
            raise ValueError("Invalid or corrupted password data")
        except (TypeError, ValueError) as e: # Catch potential decoding/type errors
            raise RuntimeError(f"Error decrypting password: {str(e)}")
    
    def _initialize(self):
        """Initialize the data storage."""
        try:
            # Create data folder if it doesn't exist
            if not os.path.exists(self.data_folder):
                os.makedirs(self.data_folder)
            
            # Create users file if it doesn't exist
            if not os.path.exists(self.users_file):
                with open(self.users_file, "w") as f:
                    json.dump([], f)
            
            # Create accounts file if it doesn't exist
            if not os.path.exists(self.accounts_file):
                with open(self.accounts_file, "w") as f:
                    json.dump([], f)
            
            # Create admin user ONLY if no users exist AND encryption is initialized
            # This assumes the first user sets the master password if needed
            if self.encryption_initialized:
                logger.debug("Encryption initialized, checking for existing users for initial setup...")
                users = self._load_users()
                logger.debug(f"Found {len(users)} users.")
                if not users:
                    logger.info("No users found. Creating initial admin user.")
                    admin_username = input("Enter username for the initial admin user: ").strip()
                    while not admin_username:
                        logger.info("Admin username cannot be empty.")
                        admin_username = input("Enter username for the initial admin user: ").strip()
                        
                    admin_password = None
                    while not admin_password:
                        admin_password = getpass.getpass(f"Enter password for admin user '{admin_username}': ")
                        if not admin_password:
                            logger.info("Password cannot be empty.")
                            continue
                        confirm_password = getpass.getpass("Confirm password: ")
                        if admin_password != confirm_password:
                            logger.info("Passwords do not match.")
                            admin_password = None # Reset

                    try:
                        # Use create_user to leverage policy validation
                        self.create_user(admin_username, admin_password, role=UserRole.ADMIN)
                        logger.info(f"Admin user '{admin_username}' created successfully.")
                    except ValueError as e:
                        logger.error(f"Error creating admin user: {e}. Please restart and try again.")
                        # Exit or raise to prevent inconsistent state? For now, just print.
                    except (IOError, RuntimeError, Exception) as e: # Catch broader errors during user creation/saving
                        logger.error(f"Unexpected error creating admin user '{admin_username}': {e}", exc_info=True)
                    
        except (IOError, OSError) as e:
            logger.error(f"Error initializing data storage: {str(e)}", exc_info=True)
            raise RuntimeError(f"Error initializing data storage: {str(e)}")
    
    def _load_users(self) -> List[User]:
        """Load users from storage with proper error handling."""
        try:
            with open(self.users_file, "r") as f:
                users_data = json.load(f)
                users = []
                for user_data in users_data:
                    # Ensure favorites is a set
                    if "favorites" in user_data and not isinstance(user_data["favorites"], list):
                        user_data["favorites"] = set()
                    elif "favorites" in user_data:
                        user_data["favorites"] = set(user_data["favorites"])
                    
                    users.append(User.model_validate(user_data))
                return users
        except FileNotFoundError:
            # If the file doesn't exist, return an empty list
            return []
        except json.JSONDecodeError as e:
            # If the file is not valid JSON, raise an error
            raise ValueError(f"Invalid users file format: {str(e)}")
        except (IOError, OSError, TypeError, ValueError) as e: # Broader catch for file/data issues
            # For other errors, raise a generic error
            raise RuntimeError(f"Error loading users: {str(e)}")
    
    def _save_users(self, users: List[User]):
        """Save users to storage with proper error handling and data protection."""
        try:
            # Create a backup of the current file if it exists
            if os.path.exists(self.users_file):
                backup_file = f"{self.users_file}.bak"
                try:
                    with open(self.users_file, "r") as src, open(backup_file, "w") as dst:
                        dst.write(src.read())
                except (IOError, OSError) as e:
                    logger.warning(f"Failed to create users backup file '{backup_file}': {str(e)}", exc_info=True)
            
            # Convert sets to lists for JSON serialization
            user_data = []
            for user in users:
                data = user.model_dump()
                if "favorites" in data and isinstance(data["favorites"], set):
                    data["favorites"] = list(data["favorites"])
                user_data.append(data)
            
            # Write to a temporary file first, then rename to avoid data loss on crash
            temp_file = f"{self.users_file}.tmp"
            with open(temp_file, "w") as f:
                json.dump(user_data, f, default=str, indent=2)
            
            # Replace the original file with the temporary file
            os.replace(temp_file, self.users_file)
            
        except (IOError, OSError, TypeError) as e: # Catch issues during user serialization/saving
            raise RuntimeError(f"Error saving users: {str(e)}")
    
    def _save_user(self, user: User):
        """Save a single user by appending to the users list."""
        try:
            users = self._load_users()
            users.append(user)
            self._save_users(users)
        except (RuntimeError, ValueError) as e: # Catch errors from lower-level functions
            raise RuntimeError(f"Error saving user: {str(e)}")
    
    def _load_accounts(self) -> List[Account]:
        """Load accounts from storage and decrypt passwords."""
        try:
            with open(self.accounts_file, "r") as f:
                accounts_data = json.load(f)
                accounts = []
                for account_data in accounts_data:
                    # Decrypt password if it's encrypted
                    if "password" in account_data and account_data["password"].startswith("gAAAAAB"):
                        try:
                            account_data["password"] = self._decrypt_password(account_data["password"])
                        except (ValueError, RuntimeError) as e:
                            # Log the error but keep the encrypted password
                            logger.warning(f"Warning: Could not decrypt password for account {account_data.get('name', 'unknown')}: {str(e)}")
                            # Mark the password as unavailable
                            account_data["password"] = "[encrypted - decryption failed]"
                    accounts.append(Account.model_validate(account_data))
                return accounts
        except FileNotFoundError:
            # If the file doesn't exist, return an empty list
            return []
        except json.JSONDecodeError as e:
            # If the file is not valid JSON, raise an error
            raise ValueError(f"Invalid accounts file format: {str(e)}")
        except (IOError, OSError, TypeError, ValueError, RuntimeError) as e: # Broader catch for file/data/decryption issues
            # For other errors, raise a generic error
            raise RuntimeError(f"Error loading accounts: {str(e)}")
    
    def _save_accounts(self, accounts: List[Account]):
        """Save accounts to storage with encrypted passwords."""
        if not self.encryption_initialized:
             # Fail explicitly if encryption isn't ready
             raise RuntimeError("Cannot save accounts: Encryption not initialized.")
             
        try:
            # Create a backup of the current file if it exists
            if os.path.exists(self.accounts_file):
                backup_file = f"{self.accounts_file}.bak"
                try:
                    # Use shutil.copy2 to preserve metadata if possible
                    shutil.copy2(self.accounts_file, backup_file)
                except (IOError, OSError) as e:
                    logger.warning(f"Failed to create accounts backup file '{backup_file}': {str(e)}", exc_info=True)
            
            # Encrypt passwords before saving
            account_data = []
            for account in accounts:
                data = account.model_dump()
                # Encrypt the password field if it exists and is not already encrypted
                if "password" in data and isinstance(data["password"], str) and data["password"] and not data["password"].startswith("gAAAAAB"):
                    try:
                        data["password"] = self._encrypt_password(data["password"])
                    except Exception as e:
                        # If encryption fails for a specific password, raise an error.
                        # Do not save plaintext passwords.
                        raise RuntimeError(f"CRITICAL: Failed to encrypt password for account {data.get('name', 'unknown')}: {str(e)}. Aborting save.")
                account_data.append(data)
            
            # Write to a temporary file first, then rename to avoid data loss on crash
            temp_file = f"{self.accounts_file}.tmp"
            with open(temp_file, "w") as f:
                json.dump(account_data, f, default=str, indent=2)
            
            # Replace the original file with the temporary file
            os.replace(temp_file, self.accounts_file)
            
        except Exception as e:
            # Attempt to restore backup if save failed after backup was made
            if 'backup_file' in locals() and os.path.exists(backup_file):
                 try:
                      shutil.move(backup_file, self.accounts_file)
                      logger.warning(f"Account save failed. Attempting to restore from backup '{backup_file}'.")
                      logger.info(f"Restored accounts file from backup '{backup_file}'.")
                 except Exception as re:
                      logger.critical(f"Failed to save accounts AND failed to restore backup '{backup_file}': {re}", exc_info=True)
                      
            # Re-raise original error if backup restoration wasn't attempted or failed
            raise # Reraises the exception caught by the outer try block
    
    # User management methods
    def get_user(self, username: str) -> Optional[User]:
        """Get a user by username."""
        if not username:
            return None
            
        try:
            users = self._load_users()
            for user in users:
                if user.username == username:
                    return user
            return None
        except (RuntimeError, ValueError) as e: # Errors from _load_users
            raise RuntimeError(f"Error retrieving user: {str(e)}")
    
    def create_user(self, username: str, password: str, role: UserRole = UserRole.USER) -> User:
        """Create a new user with the specified username, password, and role."""
        # Validate inputs
        if not username or not password:
            raise ValueError("Username and password are required")
            
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
            
        # Validate password against policy
        self._validate_password_against_policy(password)
        
        # Check if user already exists
        existing_user = self.get_user(username)
        if existing_user:
            raise ValueError(f"User '{username}' already exists")
        
        try:
            # Create password hash
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            
            # Create user object
            user = User(
                username=username,
                password_hash=password_hash.decode(),
                role=role,
                created_at=datetime.now(),
                password_last_changed=datetime.now()
            )
            
            # Save user
            users = self._load_users()
            users.append(user)
            self._save_users(users)
            
            return user
        except ValueError as e:
            # Re-raise validation errors
            raise
        except (IOError, RuntimeError, Exception) as e: # Catch broader errors during user creation/saving
            raise RuntimeError(f"Error creating user: {str(e)}")
    
    def _validate_password_against_policy(self, password: str) -> None:
        """
        Validate a password against the configured password policy.
        Raises ValueError if the password doesn't meet the policy.
        """
        policy = self.config.get("password_policy", {})
        logger.debug(f"Validating password against policy: {policy}")
        logger.debug(f"Password provided (length {len(password)}): {'*' * len(password)}") # Log length, not password itself
        
        # Check minimum length
        min_length = policy.get("min_length", 8)
        if len(password) < min_length:
            raise ValueError(f"Password must be at least {min_length} characters long")
        
        # Check for uppercase
        if policy.get("require_uppercase", True) and not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one uppercase letter")
        
        # Check for lowercase
        if policy.get("require_lowercase", True) and not any(c.islower() for c in password):
            raise ValueError("Password must contain at least one lowercase letter")
        
        # Check for numbers
        if policy.get("require_numbers", True) and not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one number")
        
        # Check for special characters
        if policy.get("require_special", True) and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in password):
            raise ValueError("Password must contain at least one special character")
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user with the given username and password.
        Returns the User object if authentication is successful, otherwise None.
        """
        # Input validation
        if not username or not password:
            return None
            
        try:
            # Get user
            user = self.get_user(username)
            if not user:
                return None
            
            # Check password
            if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                # Update last login
                users = self._load_users()
                for u in users:
                    if u.username == username:
                        u.last_login = datetime.now()
                self._save_users(users)
                return user
            
            return None
        except Exception as e:
            raise RuntimeError(f"Error during authentication: {str(e)}")
    
    def update_user(self, username: str, new_password: Optional[str] = None, 
                   new_role: Optional[UserRole] = None,
                   selected_account_ids: Optional[List[str]] = None) -> Optional[User]:
        """Update a user's password or role."""
        # Input validation
        if not username:
            raise ValueError("Username is required")
            
        user_to_update = None
        updated = False
        
        try:
            users = self._load_users()
            
            for i, user in enumerate(users):
                if user.username == username:
                    user_to_update = users[i] # Keep reference to the user object in the list
                    
                    if new_password:
                         # Validate password against policy
                         self._validate_password_against_policy(new_password)
                         
                         # Check password history if enabled
                         prevent_reuse = self.config.get("password_policy", {}).get("prevent_reuse", True)
                         history_count = self.config.get("password_policy", {}).get("history_count", 3)
                         
                         if prevent_reuse and history_count > 0:
                             if not hasattr(user_to_update, "password_history") or user_to_update.password_history is None:
                                 user_to_update.password_history = []
                                 
                             # Check new password against history
                             for old_hash in user_to_update.password_history:
                                 logger.debug(f"Checking history for user {username}: Comparing new pw against old hash {old_hash[:10]}...")
                                 # Check for match first
                                 matched = False
                                 try:
                                     matched = bcrypt.checkpw(new_password.encode('utf-8'), old_hash.encode('utf-8'))
                                 except ValueError: # Catch specific errors from checkpw, e.g., invalid salt/hash
                                     logger.warning(f"Ignoring potentially invalid hash in password history for user {username}: {old_hash[:10]}...", exc_info=True)
                                     continue # Skip this invalid hash

                                 if matched:
                                     logger.warning(f"Password reuse detected for user {username}. New password matches hash in history.")
                                     # THIS is the error we want to propagate out
                                     raise ValueError(f"New password cannot be the same as one of the last {history_count} passwords.")
                                 
                             # --- If reuse check passed, proceed --- 
                             
                             password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                             
                             # Add the OLD hash to history AFTER check passes and BEFORE saving new hash
                             if user_to_update.password_hash:
                                user_to_update.password_history.append(user_to_update.password_hash)
                                # Trim history to the correct count
                                user_to_update.password_history = user_to_update.password_history[-history_count:]
                             
                             # Now update the user's hash
                             user_to_update.password_hash = password_hash.decode('utf-8')
                             user_to_update.password_last_changed = datetime.now()
                             updated = True
                    
                    if selected_account_ids is not None: # Allow updating selection
                        # Basic validation: Ensure it's a list of strings
                        if isinstance(selected_account_ids, list) and all(isinstance(item, str) for item in selected_account_ids):
                            user_to_update.selected_account_ids = selected_account_ids
                            updated = True
                        else:
                            logger.warning("Warning: Invalid format for selected_account_ids, not updated.") # Or raise ValueError?
                    
                    if new_role:
                        if new_role not in [role.value for role in UserRole]: # Check against enum values
                            raise ValueError(f"Invalid role: {new_role}")
                        user_to_update.role = new_role
                        updated = True
                    
                    break # Found user, exit loop
            
            if user_to_update and updated:
                 self._save_users(users)
                 return user_to_update
            elif user_to_update and not updated:
                 return user_to_update # Return user even if nothing changed
            else:
                 return None # User not found
                 
        except ValueError as e:
            # Re-raise validation errors
            raise
        except (IOError, RuntimeError, Exception) as e: # Catch broader errors during user update
            raise RuntimeError(f"Error updating user '{username}': {str(e)}")
    
    def delete_user(self, username: str) -> bool:
        """Delete a user and their accounts."""
        # Input validation
        if not username:
            raise ValueError("Username is required")
            
        # Cannot delete the last admin
        if username == "admin":
            admins = self.get_users_by_role(UserRole.ADMIN)
            if len(admins) <= 1:
                raise ValueError("Cannot delete the last admin user")
        
        try:
            users = self._load_users()
            
            for i, user in enumerate(users):
                if user.username == username:
                    users.pop(i)
                    self._save_users(users)
                    
                    # Delete all accounts created by this user
                    accounts = self._load_accounts()
                    accounts = [acc for acc in accounts if acc.created_by != username]
                    self._save_accounts(accounts)
                    
                    return True
            
            return False
        except ValueError as e:
            # Re-raise validation errors
            raise
        except (IOError, RuntimeError, Exception) as e: # Catch broader errors during user deletion
            raise RuntimeError(f"Error deleting user: {str(e)}")
    
    def get_users_by_role(self, role: UserRole) -> List[User]:
        """Get all users with the specified role."""
        try:
            users = self._load_users()
            return [user for user in users if user.role == role]
        except Exception as e:
            raise RuntimeError(f"Error retrieving users by role: {str(e)}")
    
    # Account management methods
    def get_accounts(self, username: str = None) -> List[Account]:
        accounts = self._load_accounts()
        if username:
            return [account for account in accounts if account.created_by == username]
        return accounts
    
    def get_account(self, account_id: str) -> Optional[Account]:
        accounts = self._load_accounts()
        for account in accounts:
            if account.id == account_id:
                return account
        return None
    
    def create_account(self, name: str, username: str, password: str, created_by: str,
                      website: Optional[str] = None, notes: Optional[str] = None,
                      category: str = AccountCategory.OTHER, tags: List[str] = None,
                      password_strength: int = 0, expiry_date: Optional[datetime] = None,
                      is_favorite: bool = False) -> Account:
        """Create a new account."""
        account = Account(
            id=str(uuid.uuid4()),
            name=name,
            username=username,
            password=password,  # Password will be encrypted when saved
            website=website,
            notes=notes,
            created_by=created_by,
            created_at=datetime.now(),
            category=category,
            tags=tags or [],
            password_strength=password_strength,
            is_favorite=is_favorite,
            expiry_date=expiry_date
        )
        
        accounts = self._load_accounts()
        accounts.append(account)
        self._save_accounts(accounts)
        
        return account

    def create_account_from_dict(self, account_data: Dict[str, Any]) -> Account:
        """Create a new account from a dictionary."""
        # Ensure all required fields are present
        required_fields = ["name", "username", "password", "created_by"]
        for field in required_fields:
            if field not in account_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Create account with basic fields
        account = Account(
            id=account_data.get("id", str(uuid.uuid4())),
            name=account_data["name"],
            username=account_data["username"],
            password=account_data["password"],
            website=account_data.get("website"),
            notes=account_data.get("notes"),
            created_by=account_data["created_by"],
            created_at=datetime.now(),
            category=account_data.get("category", AccountCategory.OTHER),
            tags=account_data.get("tags", []),
            password_strength=account_data.get("password_strength", 0),
            is_favorite=account_data.get("is_favorite", False),
            expiry_date=account_data.get("expiry_date")
        )
        
        # Check if account ID already exists before adding
        accounts = self._load_accounts()
        if any(acc.id == account.id for acc in accounts):
            logger.warning(f"Warning: Account with ID {account.id} ('{account.name}') already exists. Skipping import.")
            return None # Indicate skipped
            
        accounts.append(account)
        self._save_accounts(accounts)
        
        return account

    def toggle_favorite(self, account_id: str) -> Optional[Account]:
        """Toggle favorite status for an account."""
        accounts = self._load_accounts()
        
        for i, account in enumerate(accounts):
            if account.id == account_id:
                accounts[i].is_favorite = not accounts[i].is_favorite
                self._save_accounts(accounts)
                return accounts[i]
        
        return None

    def update_account(self, account_id: str, name: Optional[str] = None, 
                      username: Optional[str] = None, password: Optional[str] = None,
                      website: Optional[str] = None, notes: Optional[str] = None,
                      category: Optional[str] = None, tags: Optional[List[str]] = None,
                      password_strength: Optional[int] = None,
                      expiry_date: Optional[datetime] = None) -> Optional[Account]:
        """Update an existing account."""
        accounts = self._load_accounts()
        
        for i, account in enumerate(accounts):
            if account.id == account_id:
                if name:
                    accounts[i].name = name
                if username:
                    accounts[i].username = username
                if password:
                    accounts[i].password = password
                if website is not None:  # Allow empty string
                    accounts[i].website = website
                if notes is not None:  # Allow empty string
                    accounts[i].notes = notes
                if category:
                    accounts[i].category = category
                if tags is not None:
                    accounts[i].tags = tags
                if password_strength is not None:
                    accounts[i].password_strength = password_strength
                if expiry_date is not None:
                    accounts[i].expiry_date = expiry_date
                
                accounts[i].updated_at = datetime.now()
                self._save_accounts(accounts)
                return accounts[i]
        
        return None

    def get_accounts_by_category(self, category: str) -> List[Account]:
        """Get accounts filtered by category."""
        accounts = self._load_accounts()
        return [account for account in accounts if account.category == category]

    def get_accounts_by_tag(self, tag: str) -> List[Account]:
        """Get accounts that have a specific tag."""
        accounts = self._load_accounts()
        return [account for account in accounts if tag in account.tags]

    def get_favorite_accounts(self, username: Optional[str] = None) -> List[Account]:
        """Get favorite accounts, optionally filtered by owner."""
        accounts = self._load_accounts()
        filtered = [account for account in accounts if account.is_favorite]
        
        if username:
            filtered = [account for account in filtered if account.created_by == username]
        
        return filtered

    def search_accounts(self, query: str) -> List[Account]:
        """Search accounts by name, username, website, notes, or tags."""
        if not query:
            return []
        
        query = query.lower()
        accounts = self._load_accounts()
        
        results = []
        for account in accounts:
            # Check various fields for the query
            if (query in account.name.lower() or
                query in account.username.lower() or
                (account.website and query in account.website.lower()) or
                (account.notes and query in account.notes.lower()) or
                any(query in tag.lower() for tag in account.tags)):
                results.append(account)
        
        return results

    def update_user_theme(self, username: str, theme: str) -> Optional[User]:
        """Update a user's theme preference."""
        users = self._load_users()
        
        for i, user in enumerate(users):
            if user.username == username:
                users[i].theme = theme
                self._save_users(users)
                return users[i]
        
        return None

    def delete_account(self, account_id: str) -> bool:
        accounts = self._load_accounts()
        
        for i, account in enumerate(accounts):
            if account.id == account_id:
                accounts.pop(i)
                self._save_accounts(accounts)
                return True
        
        return False

    # Backup and restore methods
    def create_backup(self, name: str = None, encrypt: bool = True) -> Backup:
        """
        Create a backup of the application data.
        
        Args:
            name: Optional name for the backup
            encrypt: Whether to encrypt the backup
            
        Returns:
            Backup object with details about the created backup
        """
        try:
            # Create backup directory if it doesn't exist
            backup_dir = os.path.join(self.data_folder, "backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate backup ID and name
            backup_id = str(uuid.uuid4())
            if not name:
                name = f"Backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create backup path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"{timestamp}_{backup_id[:8]}.zip"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            # Get data to backup
            users = self._load_users()
            accounts = self._load_accounts()
            
            # Create temporary directory for backup files
            temp_dir = os.path.join(self.data_folder, "backup_temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            try:
                # Create copies of data files in temp directory
                users_temp = os.path.join(temp_dir, "users.json")
                accounts_temp = os.path.join(temp_dir, "accounts.json")
                config_temp = os.path.join(temp_dir, "config.json")
                
                # Write users data
                with open(users_temp, "w") as f:
                    json_data = []
                    for user in users:
                        data = user.model_dump()
                        if "favorites" in data and isinstance(data["favorites"], set):
                            data["favorites"] = list(data["favorites"])
                        json_data.append(data)
                    json.dump(json_data, f, default=str, indent=2)
                
                # Write accounts data
                with open(accounts_temp, "w") as f:
                    json_data = []
                    for account in accounts:
                        data = account.model_dump()
                        json_data.append(data)
                    json.dump(json_data, f, default=str, indent=2)
                
                # Copy config
                if os.path.exists(self.config_file):
                    shutil.copy2(self.config_file, config_temp)
                
                # Create metadata file
                metadata = {
                    "id": backup_id,
                    "name": name,
                    "created_at": datetime.now().isoformat(),
                    "user_count": len(users),
                    "account_count": len(accounts),
                    "is_encrypted": encrypt,
                    "app_version": "1.1.0"
                }
                
                with open(os.path.join(temp_dir, "metadata.json"), "w") as f:
                    json.dump(metadata, f, indent=2)
                
                # Create zip archive
                with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arc_path = os.path.relpath(file_path, temp_dir)
                            zipf.write(file_path, arc_path)
                
                # Get backup size
                backup_size = os.path.getsize(backup_path)
                
                # Encrypt backup if requested
                if encrypt and self.encryption_initialized:
                    encrypted_path = backup_path + ".enc"
                    
                    # Read the backup file
                    with open(backup_path, "rb") as f:
                        data = f.read()
                    
                    # Encrypt the data
                    encrypted_data = self.cipher.encrypt(data)
                    
                    # Write the encrypted data
                    with open(encrypted_path, "wb") as f:
                        f.write(encrypted_data)
                    
                    # Replace the original backup with the encrypted one
                    os.remove(backup_path)
                    os.rename(encrypted_path, backup_path)
                
                # Create and return Backup object
                backup = Backup(
                    id=backup_id,
                    name=name,
                    created_at=datetime.now(),
                    user_count=len(users),
                    account_count=len(accounts),
                    file_path=backup_path,
                    size_bytes=backup_size,
                    is_encrypted=encrypt
                )
                
                # Update config with last backup time
                if "backup" in self.config:
                    self.config["backup"]["last_backup"] = datetime.now().isoformat()
                    with open(self.config_file, "w") as f:
                        json.dump(self.config, f, indent=2)
                
                return backup
                
            finally:
                # Clean up temporary directory
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    
        except (IOError, RuntimeError, Exception) as e:
            raise RuntimeError(f"Error creating backup: {str(e)}")

    def restore_from_backup(self, backup_path: str, master_password: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore data from a backup file.
        
        Args:
            backup_path: Path to the backup file
            master_password: Optional master password for decryption
            
        Returns:
            Dictionary with restore statistics
        """
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        try:
            # Create temporary directory for extraction
            temp_dir = os.path.join(self.data_folder, "restore_temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            try:
                # Check if the backup is encrypted
                is_encrypted = False
                try:
                    with zipfile.ZipFile(backup_path, "r") as zipf:
                        # If we can list the contents, it's not encrypted
                        zipf.namelist()
                except zipfile.BadZipFile:
                    # If it's not a valid zip file, it might be encrypted
                    is_encrypted = True
                
                # Decrypt if necessary
                if is_encrypted:
                    # If a master password is provided for restore, ALWAYS use it 
                    # to initialize/re-initialize the cipher for decryption.
                    if master_password:
                        try:
                            # Attempt to initialize/verify using the provided password
                            self._initialize_encryption(master_password)
                        except ValueError as e: # Catch invalid password during init
                             raise ValueError("Invalid master password or corrupted backup") from e
                        except RuntimeError as e: # Catch other init errors
                             raise RuntimeError(f"Failed to initialize encryption for restore: {e}") from e
                    elif not self.encryption_initialized:
                        # If no password provided AND not initialized, it's an error
                        raise ValueError("Master password required: Encryption not initialized and backup is encrypted.")
                    # If no password provided but encryption IS initialized, 
                    # proceed using the existing self.cipher. 
                     
                    # Read the encrypted file
                    with open(backup_path, "rb") as f:
                        encrypted_data = f.read()
                    
                    # Decrypt the data
                    try:
                        decrypted_data = self.cipher.decrypt(encrypted_data)
                    except InvalidToken:
                        raise ValueError("Invalid master password or corrupted backup")
                    
                    # Write decrypted data to temporary file
                    temp_zip = os.path.join(temp_dir, "backup.zip")
                    with open(temp_zip, "wb") as f:
                        f.write(decrypted_data)
                    
                    # Extract from the temporary file
                    with zipfile.ZipFile(temp_zip, "r") as zipf:
                        zipf.extractall(temp_dir)
                    
                    # Remove the temporary zip
                    os.remove(temp_zip)
                else:
                    # Extract directly from the backup file
                    with zipfile.ZipFile(backup_path, "r") as zipf:
                        zipf.extractall(temp_dir)
                
                # Load metadata
                metadata_path = os.path.join(temp_dir, "metadata.json")
                if not os.path.exists(metadata_path):
                    raise ValueError("Invalid backup: metadata.json not found")
                
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
                
                # Create backup of current data
                backup_dir = os.path.join(self.data_folder, "restore_backups")
                os.makedirs(backup_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_before_restore = os.path.join(backup_dir, f"pre_restore_{timestamp}.zip")
                
                # Create a backup of current state before restoring
                self.create_backup(name=f"Automatic backup before restore {timestamp}", 
                                  encrypt=False)
                
                # Restore users
                users_path = os.path.join(temp_dir, "users.json")
                if os.path.exists(users_path):
                    shutil.copy2(users_path, self.users_file)
                
                # Restore accounts
                accounts_path = os.path.join(temp_dir, "accounts.json")
                if os.path.exists(accounts_path):
                    shutil.copy2(accounts_path, self.accounts_file)
                
                # Restore config (optional)
                config_path = os.path.join(temp_dir, "config.json")
                if os.path.exists(config_path):
                    # Load old config
                    with open(config_path, "r") as f:
                        old_config = json.load(f)
                    
                    # Load current config
                    with open(self.config_file, "r") as f:
                        current_config = json.load(f)
                    
                    # Merge configs, giving priority to new settings
                    merged_config = {**old_config, **current_config}
                    
                    # Save merged config
                    with open(self.config_file, "w") as f:
                        json.dump(merged_config, f, indent=2)
                
                return {
                    "success": True,
                    "metadata": metadata,
                    "backup_before_restore": backup_before_restore
                }
                
            finally:
                # Clean up temporary directory
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                    
        except (IOError, RuntimeError, Exception) as e:
            raise RuntimeError(f"Error restoring from backup: {str(e)}")
    
    def list_backups(self) -> List[Backup]:
        """
        List all available backups.
        
        Returns:
            List of Backup objects
        """
        try:
            backup_dir = os.path.join(self.data_folder, "backups")
            if not os.path.exists(backup_dir):
                return []
            
            backups = []
            
            for filename in os.listdir(backup_dir):
                if not filename.endswith(".zip"):
                    continue
                
                backup_path = os.path.join(backup_dir, filename)
                
                try:
                    # Extract metadata if possible
                    is_encrypted = False
                    metadata = None
                    
                    try:
                        with zipfile.ZipFile(backup_path, "r") as zipf:
                            if "metadata.json" in zipf.namelist():
                                with zipf.open("metadata.json") as f:
                                    metadata = json.load(f)
                    except zipfile.BadZipFile:
                        # If it's not a valid zip, assume it's encrypted
                        is_encrypted = True
                        
                        # Try to parse info from filename
                        parts = filename.split("_")
                        if len(parts) >= 2:
                            date_str = parts[0]
                            time_str = parts[1].split(".")[0] if "." in parts[1] else parts[1]
                            
                            try:
                                created_at = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
                            except ValueError:
                                created_at = datetime.fromtimestamp(os.path.getctime(backup_path))
                        else:
                            created_at = datetime.fromtimestamp(os.path.getctime(backup_path))
                        
                        # Create minimal metadata
                        metadata = {
                            "id": filename.split(".")[0],
                            "name": f"Encrypted backup {created_at.strftime('%Y-%m-%d %H:%M:%S')}",
                            "created_at": created_at.isoformat(),
                            "is_encrypted": True
                        }
                    
                    if metadata:
                        backup = Backup(
                            id=metadata.get("id", filename.split(".")[0]),
                            name=metadata.get("name", f"Backup {filename}"),
                            created_at=datetime.fromisoformat(metadata.get("created_at", datetime.now().isoformat())),
                            user_count=metadata.get("user_count", 0),
                            account_count=metadata.get("account_count", 0),
                            file_path=backup_path,
                            size_bytes=os.path.getsize(backup_path),
                            is_encrypted=metadata.get("is_encrypted", is_encrypted)
                        )
                        backups.append(backup)
                except (IOError, OSError, zipfile.BadZipFile, json.JSONDecodeError, TypeError, ValueError, RuntimeError) as e:
                    # Skip problematic backups
                    logger.warning(f"Warning: Failed to process backup {filename}: {str(e)}")
            
            # Sort backups by creation time (newest first)
            backups.sort(key=lambda b: b.created_at, reverse=True)
            
            return backups
            
        except (IOError, OSError) as e:
            raise RuntimeError(f"Error listing backups: {str(e)}")
    
    def auto_backup(self) -> Optional[Backup]:
        """
        Create an automatic backup if needed according to settings.
        
        Returns:
            Backup object if backup was created, None otherwise
        """
        try:
            # Check if auto backup is enabled
            if not self.config.get("backup", {}).get("auto_backup", True):
                return None
            
            # Get last backup time
            last_backup_str = self.config.get("backup", {}).get("last_backup")
            if last_backup_str:
                try:
                    last_backup = datetime.fromisoformat(last_backup_str)
                except ValueError:
                    last_backup = None
            else:
                last_backup = None
            
            # Check if backup is needed
            if last_backup:
                interval_days = self.config.get("backup", {}).get("backup_interval_days", 7)
                delta = (datetime.now() - last_backup).total_seconds() / (24 * 3600)
                if delta < interval_days:
                    return None
            
            # Create backup
            backup = self.create_backup(name=f"Auto-backup {datetime.now().strftime('%Y-%m-%d')}")
            
            # Manage backup retention
            max_backups = self.config.get("backup", {}).get("max_backups", 5)
            if max_backups > 0:
                backups = self.list_backups()
                if len(backups) > max_backups:
                    # Delete older backups
                    for old_backup in backups[max_backups:]:
                        try:
                            if os.path.exists(old_backup.file_path):
                                os.remove(old_backup.file_path)
                        except (IOError, OSError) as e:
                            logger.warning(f"Warning: Failed to delete old backup {old_backup.file_path}: {str(e)}")
            
            return backup
            
        except (RuntimeError, ValueError, IOError, OSError) as e:
            # Use print_warning or proper logging if available
            logger.warning(f"Warning: Auto-backup failed: {str(e)}")
            return None

    def change_password(self, username: str, new_password: str) -> bool:
        """
        Change a user's password.
        
        Args:
            username: Username to change password for
            new_password: New password to set
            
        Returns:
            True if password was changed successfully, False otherwise
        """
        user = self.get_user(username)
        
        if not user:
            return False
        
        try:
            # Hash the new password
            password_bytes = new_password.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password_bytes, salt)
            new_hash = hashed.decode('utf-8')
            
            # Store the previous password in history if needed
            if "password" in self.config and self.config["password"].get("prevent_reuse", True):
                history_count = self.config["password"].get("history_count", 3)
                
                if not hasattr(user, "password_history") or user.password_history is None:
                    user.password_history = []
                
                # Add current password to history
                if user.password_hash:
                    user.password_history.append(user.password_hash)
                    
                # Trim history to configured size
                if len(user.password_history) > history_count:
                    user.password_history = user.password_history[-history_count:]
            
            # Update the password hash
            user.password_hash = new_hash
            
            # Update last changed timestamp
            user.password_last_changed = datetime.now()
            
            # Save updated user data
            self._save_users()
            
            return True
            
        except Exception as e: # Catch broader exception here as bcrypt can raise various things
            logger.error(f"Error changing password for user '{username}': {e}", exc_info=True)
            return False
    
    def register_user(self, username: str, password: str, full_name: str = "") -> bool:
        """
        Register a new user.
        
        Args:
            username: Username for the new user
            password: Password for the new user
            full_name: Optional full name for the user
            
        Returns:
            True if registration successful, False otherwise
        """
        # Check if username already exists
        if self.user_exists(username):
            return False
        
        try:
            # Create default user role (regular user)
            role = UserRole.USER
            
            # If this is the first user, make them an admin
            users = self._load_users()
            if not users:
                role = UserRole.ADMIN
            
            # Hash the password
            password_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password_bytes, salt)
            password_hash = hashed.decode('utf-8')
            
            # Create user object
            new_user = User(
                username=username,
                password_hash=password_hash,
                full_name=full_name,
                role=role,
                created_at=datetime.now(),
                last_login=None,
                password_last_changed=datetime.now(),
                favorites=set(),
                settings={},
                password_history=[]
            )
            
            # Add user to storage
            users.append(new_user)
            self._save_users()
            
            return True
            
        except Exception as e: # Catch broader exception for registration process
            logger.error(f"Error registering user '{username}': {e}", exc_info=True)
            return False
    
    def user_exists(self, username: str) -> bool:
        """
        Check if a user exists.
        
        Args:
            username: Username to check
            
        Returns:
            True if user exists, False otherwise
        """
        users = self._load_users()
        return any(user.username == username for user in users)
    
    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """
        Update configuration settings.
        
        Args:
            new_config: New configuration dictionary
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            # Update config
            for key, value in new_config.items():
                if isinstance(value, dict) and key in self.config and isinstance(self.config[key], dict):
                    # Update nested dictionaries
                    self.config[key].update(value)
                else:
                    # Replace or add top-level keys
                    self.config[key] = value
            
            # Save updated config
            self.save_config()
            
            return True
            
        except (IOError, RuntimeError, Exception) as e:
            logger.error(f"Error updating config: {str(e)}")
            return False

    def save_config(self):
        """Save the current configuration to file."""
        with open(self.config_file, "w") as f:
            json.dump(self.config, f, indent=2)

    # Add public method to get users
    def get_users(self) -> List[User]:
         """Load and return all users."""
         return self._load_users() 