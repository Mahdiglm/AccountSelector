import os
from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QMessageBox, QDialog, QFormLayout, QDialogButtonBox,
    QCheckBox, QApplication, QProgressBar
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon, QPixmap

from ..data.storage import Storage
from ..data.models import User, UserRole
from ..security.password_policy import PasswordPolicy

class PasswordChangeDialog(QDialog):
    """Dialog for changing expired passwords"""
    
    def __init__(self, user: User, storage: Storage, parent=None, force_change: bool = False):
        super().__init__(parent)
        
        self.user = user
        self.storage = storage
        self.force_change = force_change
        self.policy = PasswordPolicy(self.storage.config)
        
        self.setWindowTitle("Change Password")
        self.resize(400, 300)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Add message about expiration if forced
        if force_change:
            message = QLabel("Your password has expired and must be changed before continuing.")
            message.setStyleSheet("color: red; font-weight: bold;")
            layout.addWidget(message)
        
        # Form layout
        form_layout = QFormLayout()
        
        # Current password
        self.current_password = QLineEdit()
        self.current_password.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Current Password:", self.current_password)
        
        # New password
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.textChanged.connect(self.validate_password)
        form_layout.addRow("New Password:", self.new_password)
        
        # Confirm password
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.textChanged.connect(self.validate_password)
        form_layout.addRow("Confirm Password:", self.confirm_password)
        
        layout.addLayout(form_layout)
        
        # Password strength meter
        self.strength_label = QLabel("Password Strength:")
        layout.addWidget(self.strength_label)
        
        self.strength_meter = QProgressBar()
        self.strength_meter.setRange(0, 100)
        self.strength_meter.setValue(0)
        layout.addWidget(self.strength_meter)
        
        # Password requirements
        self.requirements_label = QLabel("Password must meet the following requirements:")
        layout.addWidget(self.requirements_label)
        
        self.validation_label = QLabel()
        self.validation_label.setStyleSheet("color: red;")
        layout.addWidget(self.validation_label)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        # If force change, disable Cancel
        if force_change:
            buttons.button(QDialogButtonBox.Cancel).setEnabled(False)
            
        layout.addWidget(buttons)
        
        # Set accept button to disabled initially
        buttons.button(QDialogButtonBox.Ok).setEnabled(False)
        self.accept_button = buttons.button(QDialogButtonBox.Ok)
    
    def validate_password(self):
        """Validate the password and update UI elements"""
        new_password = self.new_password.text()
        confirm_password = self.confirm_password.text()
        
        # Check if passwords match
        passwords_match = new_password == confirm_password
        
        # Validate against policy
        is_valid, errors = self.policy.validate_password(new_password)
        
        # Update validation message
        if not new_password:
            self.validation_label.setText("")
        elif not passwords_match:
            self.validation_label.setText("Passwords do not match")
        elif errors:
            self.validation_label.setText("\n".join(errors))
        else:
            self.validation_label.setText("Password meets all requirements")
            self.validation_label.setStyleSheet("color: green;")
        
        # Calculate strength
        strength = self._calculate_strength(new_password)
        self.strength_meter.setValue(strength)
        
        # Update strength meter color
        if strength < 40:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        elif strength < 70:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
        else:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: green; }")
        
        # Enable/disable accept button
        self.accept_button.setEnabled(
            bool(new_password) and 
            passwords_match and 
            is_valid and
            bool(self.current_password.text())
        )
    
    def _calculate_strength(self, password: str) -> int:
        """Calculate password strength as a percentage"""
        if not password:
            return 0
            
        score = 0
        # Length contribution (up to 40 points)
        length_score = min(40, len(password) * 4)
        score += length_score
        
        # Character variety (up to 60 points)
        has_lowercase = any(c.islower() for c in password)
        has_uppercase = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>/?`~' for c in password)
        
        variety_score = 0
        if has_lowercase: variety_score += 15
        if has_uppercase: variety_score += 15
        if has_digit: variety_score += 15
        if has_special: variety_score += 15
        
        score += variety_score
        
        return score
    
    def accept(self):
        """Handle password change when dialog is accepted"""
        current_password = self.current_password.text()
        new_password = self.new_password.text()
        
        # Use authenticate_user to verify current password
        if not self.storage.authenticate_user(self.user.username, current_password):
            QMessageBox.critical(self, "Error", "Current password is incorrect")
            return
        
        try:
            # Use update_user which handles policy and history correctly
            updated_user = self.storage.update_user(username=self.user.username, new_password=new_password)
            success = updated_user is not None
            
            if success:
                QMessageBox.information(self, "Success", "Password changed successfully")
                super().accept()
            else:
                QMessageBox.critical(self, "Error", "Failed to change password")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change password: {str(e)}")

class RegisterDialog(QDialog):
    """Dialog for user registration"""
    
    def __init__(self, storage: Storage, parent=None):
        super().__init__(parent)
        
        self.storage = storage
        self.policy = PasswordPolicy(self.storage.config)
        
        self.setWindowTitle("Register New User")
        self.resize(400, 350)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        
        # Username
        self.username_input = QLineEdit()
        self.username_input.textChanged.connect(self.check_username)
        form_layout.addRow("Username:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.validate_input)
        form_layout.addRow("Password:", self.password_input)
        
        # Confirm password
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.textChanged.connect(self.validate_input)
        form_layout.addRow("Confirm Password:", self.confirm_password)
        
        # Full name
        self.fullname_input = QLineEdit()
        form_layout.addRow("Full Name:", self.fullname_input)
        
        layout.addLayout(form_layout)
        
        # Username validation message
        self.username_label = QLabel()
        self.username_label.setStyleSheet("color: red;")
        layout.addWidget(self.username_label)
        
        # Password strength meter
        self.strength_label = QLabel("Password Strength:")
        layout.addWidget(self.strength_label)
        
        self.strength_meter = QProgressBar()
        self.strength_meter.setRange(0, 100)
        self.strength_meter.setValue(0)
        layout.addWidget(self.strength_meter)
        
        # Password validation message
        self.validation_label = QLabel()
        self.validation_label.setStyleSheet("color: red;")
        layout.addWidget(self.validation_label)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        # Set accept button to disabled initially
        buttons.button(QDialogButtonBox.Ok).setEnabled(False)
        self.accept_button = buttons.button(QDialogButtonBox.Ok)
    
    def check_username(self):
        """Check if username is valid and available"""
        username = self.username_input.text()
        
        if not username:
            self.username_label.setText("")
            return False
        
        # Check username length
        if len(username) < 3:
            self.username_label.setText("Username must be at least 3 characters long")
            return False
        
        # Check for spaces
        if " " in username:
            self.username_label.setText("Username cannot contain spaces")
            return False
        
        # Use get_user to check if user exists
        if self.storage.get_user(username):
            self.username_label.setText("Username already exists")
            return False
        
        self.username_label.setText("Username available")
        self.username_label.setStyleSheet("color: green;")
        return True
    
    def validate_input(self):
        """Validate user input and update UI"""
        password = self.password_input.text()
        confirm = self.confirm_password.text()
        
        username_valid = self.check_username()
        
        # Check if passwords match
        passwords_match = password == confirm
        
        # Validate against policy
        is_valid, errors = self.policy.validate_password(password)
        
        # Update validation message
        if not password:
            self.validation_label.setText("")
        elif not passwords_match:
            self.validation_label.setText("Passwords do not match")
        elif errors:
            self.validation_label.setText("\n".join(errors))
        else:
            self.validation_label.setText("Password meets all requirements")
            self.validation_label.setStyleSheet("color: green;")
        
        # Calculate strength
        strength = self._calculate_strength(password)
        self.strength_meter.setValue(strength)
        
        # Update strength meter color
        if strength < 40:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        elif strength < 70:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
        else:
            self.strength_meter.setStyleSheet("QProgressBar::chunk { background-color: green; }")
        
        # Enable/disable accept button
        self.accept_button.setEnabled(
            username_valid and
            bool(password) and 
            passwords_match and 
            is_valid and
            bool(self.fullname_input.text())
        )
    
    def _calculate_strength(self, password: str) -> int:
        """Calculate password strength as a percentage"""
        if not password:
            return 0
            
        score = 0
        # Length contribution (up to 40 points)
        length_score = min(40, len(password) * 4)
        score += length_score
        
        # Character variety (up to 60 points)
        has_lowercase = any(c.islower() for c in password)
        has_uppercase = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>/?`~' for c in password)
        
        variety_score = 0
        if has_lowercase: variety_score += 15
        if has_uppercase: variety_score += 15
        if has_digit: variety_score += 15
        if has_special: variety_score += 15
        
        score += variety_score
        
        return score
    
    def accept(self):
        """Handle registration when dialog is accepted"""
        username = self.username_input.text()
        password = self.password_input.text()
        fullname = self.fullname_input.text()
        
        try:
            # Use create_user instead of register_user
            # Note: create_user doesn't take fullname, we could add it or ignore it here.
            # Let's ignore fullname for now to match create_user signature.
            # TODO: Consider adding fullname to User model and create_user if needed.
            new_user = self.storage.create_user(username, password) # Role defaults to USER
            success = new_user is not None
            
            if success:
                QMessageBox.information(self, "Success", "User registered successfully. You can now log in.")
                super().accept()
            else:
                QMessageBox.critical(self, "Error", "Failed to register user")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to register user: {str(e)}")

class LoginWidget(QWidget):
    """Widget for user login"""
    
    login_successful = Signal(User)
    
    def __init__(self, storage: Storage):
        super().__init__()
        self.storage = storage
        self.policy = PasswordPolicy(self.storage.config)
        self._init_ui()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 50, 50, 50)
        
        # Title
        title_label = QLabel("Account Selector")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Version
        version_label = QLabel("Version 1.1.0")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)
        
        # Spacer
        layout.addSpacing(30)
        
        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        username_label.setFixedWidth(100)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)
        
        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        password_label.setFixedWidth(100)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your password")
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Remember me
        remember_layout = QHBoxLayout()
        self.remember_checkbox = QCheckBox("Remember username")
        remember_layout.addWidget(self.remember_checkbox)
        remember_layout.addStretch()
        layout.addLayout(remember_layout)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)
        
        # Register link
        register_layout = QHBoxLayout()
        register_layout.addStretch()
        self.register_button = QPushButton("Register")
        self.register_button.setFlat(True)
        self.register_button.clicked.connect(self.show_register_dialog)
        register_layout.addWidget(self.register_button)
        layout.addLayout(register_layout)
        
        # Connect enter key to login
        self.username_input.returnPressed.connect(self.handle_login)
        self.password_input.returnPressed.connect(self.handle_login)
        
        # Load remembered username if available
        if "login" in self.storage.config and "last_username" in self.storage.config["login"]:
            last_username = self.storage.config["login"]["last_username"]
            self.username_input.setText(last_username)
            self.remember_checkbox.setChecked(True)
            self.password_input.setFocus()
    
    def handle_login(self):
        """Handle login button click"""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Please enter both username and password")
            return
        
        try:
            # Use authenticate_user instead of the removed authenticate method
            user = self.storage.authenticate_user(username, password)
            
            if user:
                # Save username if remember checked
                if self.remember_checkbox.isChecked():
                    if "login" not in self.storage.config:
                        self.storage.config["login"] = {}
                    self.storage.config["login"]["last_username"] = username
                    self.storage.save_config()
                
                # Check if password has expired
                is_expired, days_until = self.policy.check_password_expired(user)
                
                if is_expired:
                    # Show password change dialog
                    dialog = PasswordChangeDialog(user, self.storage, self, force_change=True)
                    result = dialog.exec()
                    
                    # Only proceed if password was changed
                    if result == QDialog.Accepted:
                        # Reload user with updated info
                        user = self.storage.get_user(username)
                        self.login_successful.emit(user)
                    else:
                        return
                    
                elif self.policy.needs_password_change_warning(user):
                    # Show warning dialog
                    warning = QMessageBox(self)
                    warning.setWindowTitle("Password Expiration Warning")
                    warning.setText(f"Your password will expire in {days_until} days.")
                    warning.setInformativeText("Would you like to change it now?")
                    warning.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                    warning.setDefaultButton(QMessageBox.Yes)
                    
                    if warning.exec() == QMessageBox.Yes:
                        # Show password change dialog
                        dialog = PasswordChangeDialog(user, self.storage, self)
                        dialog.exec()
                        
                        # Reload user with updated info
                        user = self.storage.get_user(username)
                    
                    self.login_successful.emit(user)
                    
                else:
                    # No expiration issues, proceed with login
                    self.login_successful.emit(user)
                
                # Clear password field
                self.password_input.clear()
                
            else:
                QMessageBox.warning(self, "Login Failed", "Invalid username or password")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during login: {str(e)}")
    
    def show_register_dialog(self):
        """Show dialog for registering a new user"""
        dialog = RegisterDialog(self.storage, self)
        dialog.exec() 