import random
import string
import re
from typing import Tuple, List, Dict


def measure_password_strength(password: str) -> Tuple[int, List[str]]:
    """
    Measure password strength on a scale of 0-100 and provide improvement suggestions.
    
    Returns:
        Tuple of (score, list of suggestions)
    """
    score = 0
    suggestions = []
    
    # Check password length
    if len(password) >= 16:
        score += 30
    elif len(password) >= 12:
        score += 25
        suggestions.append("Consider using a longer password (16+ characters)")
    elif len(password) >= 8:
        score += 15
        suggestions.append("Consider using a longer password (12+ characters)")
    else:
        score += max(0, len(password) * 2)  # Small score for very short passwords
        suggestions.append("Password is too short. Use at least 8 characters")
    
    # Check for character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    variety_score = 0
    variety_count = sum([has_lower, has_upper, has_digit, has_special])
    
    # Base points for each character type
    if has_lower:
        variety_score += 10
    else:
        suggestions.append("Add lowercase letters")
    
    if has_upper:
        variety_score += 10
    else:
        suggestions.append("Add uppercase letters")
    
    if has_digit:
        variety_score += 10
    else:
        suggestions.append("Add numbers")
    
    if has_special:
        variety_score += 15
    else:
        suggestions.append("Add special characters")
    
    # Bonus for using multiple character types
    if variety_count >= 3:
        variety_score += 5
    if variety_count == 4:
        variety_score += 5
    
    score += variety_score
    
    # Check for common patterns
    if re.search(r'(123|abc|qwerty|password|admin|user)', password.lower()):
        score -= 15
        suggestions.append("Avoid common patterns like '123', 'abc', or 'password'")
    
    # Check for sequential characters
    if re.search(r'(abcd|efgh|ijkl|mnop|qrst|uvwx|0123|4567|89012)', password.lower()):
        score -= 10
        suggestions.append("Avoid sequential characters like 'abcd' or '1234'")
    
    # Check for repeating characters
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        suggestions.append("Avoid repeating characters")
    
    # Check for keyboard patterns
    if re.search(r'(qwert|asdf|zxcv)', password.lower()):
        score -= 10
        suggestions.append("Avoid keyboard patterns like 'qwert' or 'asdf'")
    
    # Ensure score is within range
    score = max(0, min(score, 100))
    
    # Map score to category
    if score >= 80:
        category = "Strong"
    elif score >= 60:
        category = "Good"
    elif score >= 40:
        category = "Fair"
    else:
        category = "Weak"
    
    # If score is good but we still have suggestions, add an encouraging message
    if score >= 60 and suggestions:
        suggestions.insert(0, f"Password strength: {category} ({score}/100). Could be improved:")
    elif suggestions:
        suggestions.insert(0, f"Password strength: {category} ({score}/100). Please improve:")
    else:
        suggestions.insert(0, f"Password strength: {category} ({score}/100)")
    
    return score, suggestions


def generate_password(length: int = 16, include_upper: bool = True, 
                      include_lower: bool = True, include_digits: bool = True, 
                      include_special: bool = True) -> str:
    """
    Generate a strong random password with specified characteristics.
    Ensures at least one character from each selected character set is included.
    """
    # Define character sets
    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    special_chars = string.punctuation
    
    # Initialize variables
    chars = ""
    must_have_chars = []
    
    # Add character sets based on parameters
    if include_upper:
        chars += upper_chars
        must_have_chars.append(random.choice(upper_chars))
    
    if include_lower:
        chars += lower_chars
        must_have_chars.append(random.choice(lower_chars))
    
    if include_digits:
        chars += digit_chars
        must_have_chars.append(random.choice(digit_chars))
    
    if include_special:
        chars += special_chars
        must_have_chars.append(random.choice(special_chars))
    
    if not chars:
        # Default to all character types if none selected
        chars = upper_chars + lower_chars + digit_chars + special_chars
        must_have_chars = [
            random.choice(upper_chars),
            random.choice(lower_chars),
            random.choice(digit_chars),
            random.choice(special_chars)
        ]
    
    # Ensure minimum length
    length = max(len(must_have_chars), length)
    
    # Generate password with random characters
    remaining_length = length - len(must_have_chars)
    password_chars = must_have_chars + [random.choice(chars) for _ in range(remaining_length)]
    
    # Shuffle the characters to ensure randomness
    random.shuffle(password_chars)
    
    return ''.join(password_chars)


def get_password_suggestion(strength: int) -> str:
    """Get a suggestion based on password strength."""
    if strength < 40:
        return "Your password is weak. Consider using the password generator."
    elif strength < 60:
        return "Your password is fair but could be stronger."
    elif strength < 80:
        return "Your password is good! Add more complexity for even better security."
    else:
        return "Your password is strong! Good job."


def mask_password(password: str, show_percent: float = 0.3, min_shown: int = 2) -> str:
    """
    Return a masked version of a password, showing only a small portion.
    Example: "password123" -> "pa*******3"
    """
    if not password:
        return ""
    
    # Calculate characters to show (at least min_shown)
    to_show = max(min_shown, int(len(password) * show_percent))
    
    # Show first and last characters, mask the middle
    start_chars = min(to_show // 2, len(password) // 2)
    end_chars = min(to_show - start_chars, len(password) - start_chars)
    
    masked = password[:start_chars] + '*' * (len(password) - start_chars - end_chars)
    if end_chars > 0:
        masked += password[-end_chars:]
    
    return masked