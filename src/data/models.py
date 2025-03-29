from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Set
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


class User(BaseModel):
    username: str
    password_hash: str
    role: UserRole = UserRole.USER
    created_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    theme: str = "default"
    favorites: Set[str] = Field(default_factory=set)  # Set of account IDs


class Account(BaseModel):
    id: str
    name: str
    username: str
    password: str
    website: Optional[str] = None
    notes: Optional[str] = None
    category: AccountCategory = AccountCategory.OTHER
    tags: List[str] = Field(default_factory=list)
    password_strength: int = 0  # 0-100 scale
    created_by: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_favorite: bool = False
    expiry_date: Optional[datetime] = None