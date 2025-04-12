from pydantic import BaseModel, Field, validator
from pydantic import field_validator
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
    selected_account_ids: List[str] = Field(default_factory=list) # IDs of accounts selected by user
    password_history: List[str] = Field(default_factory=list) # Hashes of previous passwords
    
    @field_validator('username', mode='before')
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
    
    @field_validator('name', mode='before')
    def name_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Account name cannot be empty')
        return v
    
    @field_validator('username', mode='before')
    def username_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Account username cannot be empty')
        return v
    
    @field_validator('password', mode='before')
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
    
    @field_validator('name', mode='before')
    def name_must_not_be_empty(cls, v):
        if not v:
            raise ValueError('Backup name cannot be empty')
        return v