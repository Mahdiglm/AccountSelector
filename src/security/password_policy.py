import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List

from ..data.models import User

class PasswordPolicy:
    """
    Enforces password policies for the application.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize password policy with optional configuration.
        
        Args:
            config: Configuration dictionary with policy settings
        """
        self.config = config or {}
        self._init_defaults()
    
    def _init_defaults(self):
        """Set default policy values if not specified in config"""
        if "password" not in self.config:
            self.config["password"] = {}
            
        password_config = self.config["password"]
        
        # Password strength requirements
        if "min_length" not in password_config:
            password_config["min_length"] = 8
        
        if "require_uppercase" not in password_config:
            password_config["require_uppercase"] = True
            
        if "require_lowercase" not in password_config:
            password_config["require_lowercase"] = True
            
        if "require_numbers" not in password_config:
            password_config["require_numbers"] = True
            
        if "require_special" not in password_config:
            password_config["require_special"] = True
            
        # Password expiration
        if "max_age_days" not in password_config:
            password_config["max_age_days"] = 90  # Default to 90 days
            
        if "enforce_expiration" not in password_config:
            password_config["enforce_expiration"] = True
            
        if "expiration_warning_days" not in password_config:
            password_config["expiration_warning_days"] = 7
            
        # Password history
        if "prevent_reuse" not in password_config:
            password_config["prevent_reuse"] = True
            
        if "history_count" not in password_config:
            password_config["history_count"] = 3
    
    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate a password against the policy.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple of (is_valid, list_of_validation_errors)
        """
        errors = []
        
        # Check length
        min_length = self.config["password"]["min_length"]
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")
        
        # Check for uppercase letters
        if self.config["password"]["require_uppercase"] and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letters
        if self.config["password"]["require_lowercase"] and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for numbers
        if self.config["password"]["require_numbers"] and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        # Check for special characters
        if self.config["password"]["require_special"]:
            special_pattern = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]'
            if not re.search(special_pattern, password):
                errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def check_password_expired(self, user: User) -> Tuple[bool, int]:
        """
        Check if a user's password has expired.
        
        Args:
            user: User to check
            
        Returns:
            Tuple of (is_expired, days_until_expiration)
        """
        # If not enforcing expiration or user doesn't have a last changed date, return not expired
        if not self.config["password"]["enforce_expiration"] or not user.password_last_changed:
            return False, -1
        
        # Calculate password age
        max_age_days = self.config["password"]["max_age_days"]
        now = datetime.now()
        expiration_date = user.password_last_changed + timedelta(days=max_age_days)
        
        # Calculate days until expiration
        days_until_expiration = (expiration_date - now).days
        
        # Check if expired
        is_expired = days_until_expiration <= 0
        
        return is_expired, days_until_expiration
    
    def needs_password_change_warning(self, user: User) -> bool:
        """
        Check if the user should be warned about upcoming password expiration.
        
        Args:
            user: User to check
            
        Returns:
            True if warning should be shown
        """
        is_expired, days_until_expiration = self.check_password_expired(user)
        
        # If already expired, no need for warning
        if is_expired:
            return False
        
        # If expiration not enforced or no last change date, no warning
        if not self.config["password"]["enforce_expiration"] or not user.password_last_changed:
            return False
        
        # Check if within warning period
        warning_days = self.config["password"]["expiration_warning_days"]
        return days_until_expiration <= warning_days
    
    def can_reuse_password(self, user: User, new_password_hash: str) -> bool:
        """
        Check if the new password can be used based on password history.
        
        Args:
            user: User changing password
            new_password_hash: Hash of the new password
            
        Returns:
            True if password can be used
        """
        # If not preventing reuse, always allow
        if not self.config["password"]["prevent_reuse"]:
            return True
        
        # If user has no password history, allow
        if not hasattr(user, "password_history") or not user.password_history:
            return True
        
        # Check if password hash exists in history
        return new_password_hash not in user.password_history
    
    def update_config(self, new_config: Dict[str, Any]):
        """
        Update the policy configuration.
        
        Args:
            new_config: New configuration dictionary
        """
        if "password" in new_config:
            self.config["password"].update(new_config["password"]) 