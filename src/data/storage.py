import json
import os
import bcrypt
from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import User, Account, UserRole, AccountCategory


class Storage:
    def __init__(self, data_folder="./app_data"):
        self.data_folder = data_folder
        self.users_file = os.path.join(data_folder, "users.json")
        self.accounts_file = os.path.join(data_folder, "accounts.json")
        self.key_file = os.path.join(data_folder, "key.bin")
        
        # Initialize encryption key
        self._initialize_encryption()
        
        # Initialize data storage
        self._initialize()
    
    def _initialize_encryption(self):
        """Initialize encryption for secure storage of account passwords."""
        if not os.path.exists(self.key_file):
            # Generate a new encryption key
            salt = os.urandom(16)
            # Using a fixed password here, ideally this would be configurable
            # or derived from a secure source
            password = b"AccountSelectorSecureStorageKey"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Save the key and salt
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            with open(self.key_file, "wb") as f:
                f.write(salt + key)
        else:
            # Load existing key and salt
            with open(self.key_file, "rb") as f:
                data = f.read()
                salt = data[:16]
                key = data[16:]
        
        # Initialize the Fernet cipher
        self.cipher = Fernet(key)
    
    def _encrypt_password(self, password: str) -> str:
        """Encrypt a password."""
        return self.cipher.encrypt(password.encode()).decode()
    
    def _decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt an encrypted password."""
        return self.cipher.decrypt(encrypted_password.encode()).decode()
    
    def _initialize(self):
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
        
        # Create admin user if no users exist
        users = self._load_users()
        if not users:
            admin_password = "Admin@SecureP@ss123!"  # Default admin password - CHANGE AFTER FIRST LOGIN
            password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt())
            admin_user = User(
                username="admin",
                password_hash=password_hash.decode(),
                role=UserRole.ADMIN
            )
            self._save_user(admin_user)
    
    def _load_users(self) -> List[User]:
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
    
    def _save_users(self, users: List[User]):
        with open(self.users_file, "w") as f:
            # Convert sets to lists for JSON serialization
            user_data = []
            for user in users:
                data = user.model_dump()
                if "favorites" in data and isinstance(data["favorites"], set):
                    data["favorites"] = list(data["favorites"])
                user_data.append(data)
            json.dump(user_data, f, default=str)
    
    def _save_user(self, user: User):
        users = self._load_users()
        users.append(user)
        self._save_users(users)
    
    def _load_accounts(self) -> List[Account]:
        with open(self.accounts_file, "r") as f:
            accounts_data = json.load(f)
            accounts = []
            for account_data in accounts_data:
                # Decrypt password if it's encrypted
                if "password" in account_data and account_data["password"].startswith("gAAAAAB"):
                    try:
                        account_data["password"] = self._decrypt_password(account_data["password"])
                    except Exception:
                        # If decryption fails, keep as is (might be unencrypted from older versions)
                        pass
                accounts.append(Account.model_validate(account_data))
            return accounts
    
    def _save_accounts(self, accounts: List[Account]):
        with open(self.accounts_file, "w") as f:
            # Encrypt passwords before saving
            account_data = []
            for account in accounts:
                data = account.model_dump()
                # Check if password is already encrypted
                if not data["password"].startswith("gAAAAAB"):
                    data["password"] = self._encrypt_password(data["password"])
                account_data.append(data)
            json.dump(account_data, f, default=str)
    
    # User management methods
    def get_user(self, username: str) -> Optional[User]:
        users = self._load_users()
        for user in users:
            if user.username == username:
                return user
        return None
    
    def create_user(self, username: str, password: str, role: UserRole = UserRole.USER) -> User:
        if self.get_user(username):
            raise ValueError(f"User '{username}' already exists")
        
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        user = User(
            username=username,
            password_hash=password_hash.decode(),
            role=role,
            created_at=datetime.now()
        )
        
        users = self._load_users()
        users.append(user)
        self._save_users(users)
        
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        user = self.get_user(username)
        if not user:
            return None
        
        if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            # Update last login
            users = self._load_users()
            for u in users:
                if u.username == username:
                    u.last_login = datetime.now()
            self._save_users(users)
            return user
        
        return None
    
    def update_user(self, username: str, new_password: Optional[str] = None, 
                   new_role: Optional[UserRole] = None) -> Optional[User]:
        users = self._load_users()
        
        for i, user in enumerate(users):
            if user.username == username:
                if new_password:
                    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                    users[i].password_hash = password_hash.decode()
                
                if new_role:
                    users[i].role = new_role
                
                self._save_users(users)
                return users[i]
        
        return None
    
    def delete_user(self, username: str) -> bool:
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
        
        accounts = self._load_accounts()
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