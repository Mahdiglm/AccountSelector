from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Set, Any
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


class AccountCategory(str, Enum):
    SOCIAL = "social"
    FINANCIAL = "financial"
    EMAIL = "email"
    SHOPPING = "shopping"
    ENTERTAINMENT = "entertainment"
    WORK = "work"
    EDUCATION = "education"
    GAMING = "gaming"
    OTHER = "other"
    CUSTOM = "custom"  # For user-defined categories


class User(BaseModel):
    username: str
    password_hash: str
    role: UserRole = UserRole.USER
    created_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    password_last_changed: Optional[datetime] = None
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    theme: str = "default"
    favorites: Set[str] = Field(default_factory=set)  # Set of account IDs
    settings: Dict[str, Any] = Field(default_factory=dict)  # User-specific settings
    
    # Session information for auto-logout feature
    session_token: Optional[str] = None
    session_expires: Optional[datetime] = None
    
    @validator('username')
    def username_must_be_valid(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if ' ' in v:
            raise ValueError('Username cannot contain spaces')
        return v


class Account(BaseModel):
    id: str
    name: str
    username: str
    password: str
    website: Optional[str] = None
    notes: Optional[str] = None
    category: str = AccountCategory.OTHER.value
    category_name: Optional[str] = None  # For custom categories
    tags: List[str] = Field(default_factory=list)
    password_strength: int = 0  # 0-100 scale
    created_by: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_favorite: bool = False
    expiry_date: Optional[datetime] = None
    
    # Additional metadata fields
    metadata: Dict[str, Any] = Field(default_factory=dict)
    auto_backup: bool = True  # Whether this account should be included in auto-backups
    
    @validator('name')
    def name_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Account name cannot be empty')
        return v
    
    @validator('username')
    def username_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Account username cannot be empty')
        return v
    
    @validator('password')
    def password_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Account password cannot be empty')
        return v


class Backup(BaseModel):
    id: str
    name: str
    created_at: datetime
    user_count: int
    account_count: int
    file_path: str
    size_bytes: int
    is_encrypted: bool
    notes: Optional[str] = None
    
    @validator('name')
    def name_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Backup name cannot be empty')
        return v


class UserSession:
    """
    Represents a user session with authentication state and expiry.
    This is not a Pydantic model as it's not stored in JSON.
    """
    def __init__(self, user: User, token: str, expires: datetime):
        self.user = user
        self.token = token
        self.expires = expires
        self.last_activity = datetime.now()
    
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return datetime.now() > self.expires
    
    def is_inactive(self, timeout_minutes: int) -> bool:
        """Check if the session is inactive for longer than the specified timeout."""
        if timeout_minutes <= 0:
            return False
        inactive_time = (datetime.now() - self.last_activity).total_seconds() / 60
        return inactive_time > timeout_minutes
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = datetime.now()