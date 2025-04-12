from typing import Optional, List, Dict, Any, Callable
import sys
import time
import os
from datetime import datetime

from src.data.storage import Storage
from src.data.models import User, UserRole, AccountCategory
from src.utils.cli import (
    print_header, print_success, print_error, print_info, print_warning,
    display_accounts_table, display_users_table, ask_to_continue,
    render_menu, form_input, confirm_action, display_spinner, clear_screen
)
from src.utils.password import (
    measure_password_strength, generate_password, 
    get_password_suggestion, mask_password
)
from src.utils.export import (
    export_to_json, export_to_csv, 
    import_from_json, import_from_csv, import_from_text
)
from src.utils.themes import get_available_themes
import questionary  # Keep the direct import for now

# Get the logger configured in account_selector.py
import logging
logger = logging.getLogger(__name__) # Use module-specific logger


class AccountSelectorApp:
    def __init__(self):
        self.storage = Storage()
        self.current_user: Optional[User] = None
        # self.selected_accounts = []  # To track accounts selected/purchased by users
    
    def start(self):
        """Start the application."""
        while True:
            if self.current_user is None:
                # Show login/signup menu
                result = self.show_auth_menu()
                if result is False:  # Exit application
                    self.exit_app()
            else:
                # Show appropriate menu based on user role
                if self.current_user.role == UserRole.ADMIN:
                    result = self.show_admin_menu()
                else:
                    result = self.show_user_menu()
                
                if result is False:  # Logout
                    self.logout()
    
    def exit_app(self):
        """Exit the application."""
        print_header("Goodbye!")
        print_info("Thank you for using Account Selector!")
        sys.exit(0)
    
    def logout(self):
        """Log out the current user."""
        username = self.current_user.username
        self.current_user = None
        print_success(f"Logged out successfully: {username}")
        time.sleep(1)
    
    def show_auth_menu(self) -> bool:
        """Show authentication menu (login/signup)."""
        options = [
            ("1", "Login", self.login),
            ("2", "Sign Up", self.signup),
            ("3", "Exit", lambda: False)
        ]
        
        callback = render_menu("Account Selector - Authentication", options)
        if callback is None:
            return True
        
        return callback()
    
    def login(self) -> bool:
        """Login form."""
        print_header("Login")
        
        fields = [
            {"name": "username", "message": "Username:"},
            {"name": "password", "message": "Password:", "type": "password"}
        ]
        
        form_data = form_input(fields)
        
        if not form_data.get("username") or not form_data.get("password"):
            print_error("Username and password are required.")
            logger.warning("Login attempt failed: Missing username or password.")
            ask_to_continue()
            return True
        
        display_spinner("Logging in...", 0.5)
        
        user = self.storage.authenticate_user(
            form_data["username"], 
            form_data["password"]
        )
        
        if user:
            self.current_user = user
            # Load selected accounts from user data
            self.selected_accounts = [
                self.storage.get_account(acc_id) 
                for acc_id in self.current_user.selected_account_ids 
                if self.storage.get_account(acc_id) is not None
            ]
            # Convert loaded accounts to dicts for consistency with previous logic
            self.selected_accounts = [acc.model_dump() for acc in self.selected_accounts]
            
            print_success(f"Welcome back, {user.username}!")
            ask_to_continue()
            return True
        else:
            print_error("Invalid username or password.")
            logger.warning(f"Login attempt failed for user '{form_data['username']}'.")
            ask_to_continue()
            return True
    
    def signup(self) -> bool:
        """Sign up form."""
        print_header("Sign Up")
        
        fields = [
            {"name": "username", "message": "Username:"},
            {"name": "password", "message": "Password:", "type": "password"},
            {"name": "password_confirm", "message": "Confirm Password:", "type": "password"}
        ]
        
        form_data = form_input(fields)
        
        if not form_data.get("username") or not form_data.get("password"):
            print_error("Username and password are required.")
            logger.warning("Signup attempt failed: Missing username or password.")
            ask_to_continue()
            return True
        
        if form_data["password"] != form_data["password_confirm"]:
            print_error("Passwords do not match.")
            logger.warning("Signup attempt failed: Passwords do not match.")
            ask_to_continue()
            return True
        
        # Check if username already exists
        if self.storage.get_user(form_data["username"]):
            print_error(f"Username '{form_data['username']}' is already taken.")
            logger.warning(f"Signup attempt failed: Username '{form_data['username']}' already exists.")
            ask_to_continue()
            return True
        
        display_spinner("Creating account...", 0.5)
        
        try:
            user = self.storage.create_user(
                form_data["username"],
                form_data["password"]
            )
            
            print_success(f"Account created successfully: {user.username}")
            
            # Auto login
            self.current_user = user
            
            ask_to_continue()
            return True
        except Exception as e:
            print_error(f"Error creating account: {str(e)}")
            logger.error(f"Error during signup for username '{form_data.get('username', 'N/A')}': {e}", exc_info=True)
            ask_to_continue()
            return True
    
    def show_user_menu(self) -> bool:
        """Show menu for regular users."""
        options = [
            ("1", "Browse Available Accounts", self.browse_accounts),
            ("2", "View My Selected Accounts", self.view_selected_accounts),
            ("3", "Change Password", self.change_password),
            ("4", "Change Theme", self.change_theme),
            ("5", "Logout", lambda: False)
        ]
        
        callback = render_menu(f"Account Selector - User: {self.current_user.username}", options)
        if callback is None:
            return True
        
        return callback()
    
    def show_admin_menu(self) -> bool:
        """Show menu for admin users."""
        options = [
            ("1", "Browse All Accounts", self.browse_accounts),
            ("2", "Add New Account", self.add_account),
            ("3", "Manage Account", self.manage_account),
            ("4", "Manage Users", self.manage_users),
            ("5", "Import/Export Accounts", self.import_export_menu),
            ("6", "View Account Stats", self.view_account_stats),
            ("7", "Change Theme", self.change_theme),
            ("8", "Change Password", self.change_password),
            ("9", "Logout", lambda: False)
        ]
        
        callback = render_menu(f"Account Selector - Admin: {self.current_user.username}", options)
        if callback is None:
            return True
        
        return callback()
    
    def browse_accounts(self) -> bool:
        """Browse available accounts with option to select/buy for users."""
        
        # If admin, show all accounts; if user, show accounts not created by the user
        if self.current_user.role == UserRole.ADMIN:
            accounts = self.storage.get_accounts()
            title = "All Accounts"
            print_header(title)
        else:
            # Filter out accounts already selected by this user
            all_accounts = self.storage.get_accounts()
            # Use the persisted list from the current user object
            selected_account_ids = self.current_user.selected_account_ids
            accounts = [acc for acc in all_accounts if acc.id not in selected_account_ids]
            title = "Available Accounts (Read-only Access)"
            print_header(title)
            print_info("As a regular user, you can view account credentials but cannot modify them.")
        
        # Convert to dicts for display
        account_dicts = [account.model_dump() for account in accounts]
        
        # Show credentials only to admin
        show_credentials = self.current_user.role == UserRole.ADMIN
        
        display_accounts_table(account_dicts, show_credentials=show_credentials)
        
        # If user, offer option to select/buy an account
        if self.current_user.role == UserRole.USER and accounts:
            if confirm_action("Would you like to select an account? (Read-only access)", default=True):
                self.select_account(accounts)
        
        ask_to_continue()
        return True
    
    def select_account(self, accounts: List):
        """Allow user to select/buy an account with read-only credential access."""
        # Create account choices
        account_choices = {f"{acc.name} ({acc.username})": acc.id for acc in accounts}
        account_choices["Cancel"] = None
        
        selected = questionary.select(
            "Select an account to purchase:",
            choices=list(account_choices.keys())
        ).ask()
        
        if selected == "Cancel" or selected is None:
            return
        
        account_id = account_choices[selected]
        account = self.storage.get_account(account_id)
        
        if not account:
            print_error("Account not found.")
            logger.error(f"Attempted to select non-existent account ID: {account_id}")
            return
        
        # Confirm selection
        if confirm_action(f"Confirm selection of '{account.name}'? (Read-only access)", default=True):
            display_spinner("Processing selection...", 0.5)
            
            # Add to selected accounts
            self.selected_accounts.append(account.model_dump())
            
            # Also add to the user's persistent list
            if account.id not in self.current_user.selected_account_ids:
                self.current_user.selected_account_ids.append(account.id)
                # Persist the change immediately
                try:
                    self.storage.update_user(username=self.current_user.username, 
                                              selected_account_ids=self.current_user.selected_account_ids)
                except Exception as e:
                    print_error(f"Error saving selection: {e}")
                    logger.error(f"Failed to save account selection (ID: {account.id}) for user {self.current_user.username}: {e}", exc_info=True)
                    # Optionally revert local change if save fails?
                    self.current_user.selected_account_ids.pop() 
                    # Let user know save failed
                    ask_to_continue()
                    return # Abort showing details if save failed
            
            print_success(f"You have successfully selected '{account.name}'!")
            
            # Display account details including credentials
            print_header(f"Account: {account.name} - Details (Read-only)")
            account_dict = account.model_dump()
            display_accounts_table([account_dict], show_credentials=True)
            print_info("These credentials are for viewing only and cannot be modified by regular users.")
    
    def view_selected_accounts(self) -> bool:
        """View accounts selected/purchased by the user (read-only)."""
        print_header("My Selected Accounts (Read-only)")
        
        if not self.current_user or not self.current_user.selected_account_ids:
            print_info("You haven't selected any accounts yet.")
            ask_to_continue()
            return True
        
        # Fetch account details based on stored IDs
        selected_accounts_details = []
        missing_ids = []
        for acc_id in self.current_user.selected_account_ids:
            account = self.storage.get_account(acc_id)
            if account:
                selected_accounts_details.append(account.model_dump())
            else:
                missing_ids.append(acc_id)
        
        if missing_ids:
             print_warning(f"Warning: Could not find details for some selected account IDs: {', '.join(missing_ids)}")
             logger.warning(f"Could not find account details for IDs: {missing_ids} for user {self.current_user.username}")
             # Optionally offer to clean up the list?
             
        if not selected_accounts_details:
             print_info("Could not retrieve details for any selected accounts.")
             ask_to_continue()
             return True
             
        display_accounts_table(selected_accounts_details, show_credentials=True)
        print_info("Note: These credentials are for viewing only and cannot be modified.")
        
        ask_to_continue()
        return True
    
    def view_account_stats(self) -> bool:
        """View account statistics."""
        if self.current_user.role != UserRole.ADMIN:
            print_error("You don't have permission to access this feature.")
            ask_to_continue()
            return True
        
        print_header("Account Statistics")
        
        accounts = self.storage.get_accounts()
        
        if not accounts:
            print_info("No accounts available for statistics.")
            ask_to_continue()
            return True
        
        # Basic stats
        total_accounts = len(accounts)
        print_info(f"Total accounts: {total_accounts}")
        
        # Password strength stats
        strength_levels = {"Strong": 0, "Good": 0, "Fair": 0, "Weak": 0}
        for account in accounts:
            strength = account.password_strength
            if strength >= 80:
                strength_levels["Strong"] += 1
            elif strength >= 60:
                strength_levels["Good"] += 1
            elif strength >= 40:
                strength_levels["Fair"] += 1
            else:
                strength_levels["Weak"] += 1
        
        print_info("\nPassword Strength Distribution:")
        print_success(f"Strong: {strength_levels['Strong']} ({(strength_levels['Strong']/total_accounts)*100:.1f}%)")
        print_info(f"Good: {strength_levels['Good']} ({(strength_levels['Good']/total_accounts)*100:.1f}%)")
        print_warning(f"Fair: {strength_levels['Fair']} ({(strength_levels['Fair']/total_accounts)*100:.1f}%)")
        print_error(f"Weak: {strength_levels['Weak']} ({(strength_levels['Weak']/total_accounts)*100:.1f}%)")
        
        # Category stats
        categories = {}
        for account in accounts:
            category = account.category
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        print_info("\nAccount Categories:")
        for category, count in categories.items():
            print_info(f"{category}: {count} ({(count/total_accounts)*100:.1f}%)")
        
        ask_to_continue()
        return True
    
    def add_account(self) -> bool:
        """Add a new account. Admin only."""
        if self.current_user.role != UserRole.ADMIN:
            print_error("You don't have permission to add accounts.")
            ask_to_continue()
            return True
            
        print_header("Add New Account")
        
        # First step - basic info
        fields = [
            {"name": "name", "message": "Account Name:"},
            {"name": "username", "message": "Account Username:"},
            {"name": "password", "message": "Account Password:", "type": "password"},
            {"name": "website", "message": "Website (optional):"}
        ]
        
        form_data = form_input(fields)
        
        if not form_data.get("name") or not form_data.get("username") or not form_data.get("password"):
            print_error("Account name, username, and password are required.")
            logger.warning("Add account attempt failed: Missing required fields.")
            ask_to_continue()
            return True
        
        # Check password strength
        password = form_data["password"]
        strength, suggestions = measure_password_strength(password)
        
        # Show password strength feedback
        print_header("Password Strength Analysis")
        
        if strength >= 80:
            print_success(suggestions[0])
        elif strength >= 60:
            print_info(suggestions[0])
        elif strength >= 40:
            print_warning(suggestions[0])
        else:
            print_error(suggestions[0])
        
        for suggestion in suggestions[1:]:
            print_info(f"- {suggestion}")
        
        # Offer to generate a stronger password
        if strength < 60:
            if confirm_action("Would you like to generate a stronger password?", default=True):
                password = self.generate_password_dialog()
                form_data["password"] = password
                
                # Re-measure strength with new password
                strength, _ = measure_password_strength(password)
                print_success(f"New password generated with strength score: {strength}/100")
        
        # Second step - additional info
        print_header("Additional Account Information")
        
        # Select category
        category_options = [category.value for category in AccountCategory]
        category = questionary.select(
            "Select Category:",
            choices=category_options,
            default=AccountCategory.OTHER.value
        ).ask()
        
        # Enter tags
        tags_input = questionary.text(
            "Tags (comma-separated):"
        ).ask()
        
        tags = []
        if tags_input:
            tags = [tag.strip() for tag in tags_input.split(",")]
        
        # Notes
        notes = questionary.text(
            "Notes:"
        ).ask()
        
        # Add expiry date option
        has_expiry = confirm_action("Does this account have an expiration date?", default=False)
        expiry_date = None
        if has_expiry:
            expiry_input = questionary.text(
                "Expiry Date (YYYY-MM-DD):"
            ).ask()
            try:
                if expiry_input:
                    expiry_date = datetime.strptime(expiry_input, "%Y-%m-%d")
            except ValueError:
                print_error("Invalid date format. Using no expiry date.")
                logger.warning(f"Invalid expiry date format entered: '{expiry_input}'")
                expiry_date = None
        
        display_spinner("Adding account...", 0.5)
        
        try:
            account = self.storage.create_account(
                name=form_data["name"],
                username=form_data["username"],
                password=form_data["password"],
                website=form_data.get("website", ""),
                notes=notes or "",
                created_by=self.current_user.username,
                category=category,
                tags=tags,
                password_strength=strength,
                expiry_date=expiry_date
            )
            
            print_success(f"Account '{account.name}' added successfully!")
            ask_to_continue()
            return True
        except Exception as e:
            print_error(f"Error adding account: {str(e)}")
            logger.error(f"Error adding account '{form_data.get('name', 'N/A')}': {e}", exc_info=True)
            ask_to_continue()
            return True
    
    def generate_password_dialog(self) -> str:
        """Show dialog to generate a password."""
        print_header("Password Generator")
        
        fields = [
            {"name": "length", "message": "Password Length:", "default": "16"},
            {"name": "include_upper", "message": "Include Uppercase Letters?", "type": "confirm", "default": True},
            {"name": "include_lower", "message": "Include Lowercase Letters?", "type": "confirm", "default": True},
            {"name": "include_digits", "message": "Include Numbers?", "type": "confirm", "default": True},
            {"name": "include_special", "message": "Include Special Characters?", "type": "confirm", "default": True}
        ]
        
        options = form_input(fields)
        
        try:
            length = int(options.get("length", 16))
        except ValueError:
            length = 16
        
        password = generate_password(
            length=length,
            include_upper=options.get("include_upper", True),
            include_lower=options.get("include_lower", True),
            include_digits=options.get("include_digits", True),
            include_special=options.get("include_special", True)
        )
        
        print_success(f"Generated password: {password}")
        
        return password
    
    def change_theme(self) -> bool:
        """Change the application theme."""
        print_header("Change Theme")
        
        available_themes = get_available_themes()
        theme_choices = [f"{name}: {desc}" for name, desc in available_themes.items()]
        
        selected = questionary.select(
            "Select Theme:",
            choices=theme_choices
        ).ask()
        
        if not selected:
            return True
        
        # Extract theme name from selection
        theme_name = selected.split(":", 1)[0].strip()
        
        # In a real app, we would save the theme preference
        print_success(f"Theme changed to '{theme_name}'")
        print_info("Note: Theme changes will take effect on restart in this version.")
        
        ask_to_continue()
        return True
    
    def import_export_menu(self) -> bool:
        """Show import/export menu."""
        if self.current_user.role != UserRole.ADMIN:
            print_error("You don't have permission to access this feature.")
            ask_to_continue()
            return True
        
        options = [
            ("1", "Export Accounts to JSON", self.export_to_json_dialog),
            ("2", "Export Accounts to CSV", self.export_to_csv_dialog),
            ("3", "Import Accounts from JSON", self.import_from_json_dialog),
            ("4", "Import Accounts from CSV", self.import_from_csv_dialog),
            ("5", "Import Accounts from Text", self.import_from_text_dialog),
            ("6", "Back", lambda: False)
        ]
        
        callback = render_menu("Import/Export Accounts", options)
        if callback is None:
            return True
        
        return callback()
    
    def export_to_json_dialog(self) -> bool:
        """Export accounts to JSON."""
        print_header("Export Accounts to JSON")
        
        accounts = self.storage.get_accounts()
        if not accounts:
            print_info("No accounts to export.")
            ask_to_continue()
            return True
        
        # Convert to dicts for export
        account_dicts = [account.model_dump() for account in accounts]
        
        # Get export path
        export_dir = "exports"
        os.makedirs(export_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = os.path.join(export_dir, f"accounts_export_{timestamp}.json")
        
        filename = questionary.text(
            "Export filename:",
            default=default_filename
        ).ask()
        
        if not filename:
            filename = default_filename
        
        # Do the export
        try:
            filepath = export_to_json(account_dicts, filename)
            print_success(f"Successfully exported {len(account_dicts)} accounts to {filepath}")
            logger.info(f"Exported {len(account_dicts)} accounts to JSON: {filepath}")
        except Exception as e:
            print_error(f"Export failed: {str(e)}")
            logger.error(f"JSON export failed for file '{filename}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def export_to_csv_dialog(self) -> bool:
        """Export accounts to CSV."""
        print_header("Export Accounts to CSV")
        
        accounts = self.storage.get_accounts()
        if not accounts:
            print_info("No accounts to export.")
            ask_to_continue()
            return True
        
        # Convert to dicts for export
        account_dicts = [account.model_dump() for account in accounts]
        
        # Get export path
        export_dir = "exports"
        os.makedirs(export_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = os.path.join(export_dir, f"accounts_export_{timestamp}.csv")
        
        filename = questionary.text(
            "Export filename:",
            default=default_filename
        ).ask()
        
        if not filename:
            filename = default_filename
        
        # Do the export
        try:
            filepath = export_to_csv(account_dicts, filename)
            print_success(f"Successfully exported {len(account_dicts)} accounts to {filepath}")
            logger.info(f"Exported {len(account_dicts)} accounts to CSV: {filepath}")
        except Exception as e:
            print_error(f"Export failed: {str(e)}")
            logger.error(f"CSV export failed for file '{filename}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def import_from_json_dialog(self) -> bool:
        """Import accounts from JSON."""
        print_header("Import Accounts from JSON")
        
        import_dir = "imports"
        os.makedirs(import_dir, exist_ok=True)
        
        # Get import path
        filename = questionary.text(
            "Enter path to JSON file:"
        ).ask()
        
        if not filename:
            print_error("No filename provided.")
            ask_to_continue()
            return True
        
        # Do the import
        try:
            imported_accounts = import_from_json(filename, self.current_user.username)
            
            if not imported_accounts:
                print_error("No accounts were imported. Check file format.")
                ask_to_continue()
                return True
            
            print_success(f"Successfully imported {len(imported_accounts)} accounts")
            
            # Add accounts to storage
            for account_data in imported_accounts:
                self.storage.create_account_from_dict(account_data)
            
            print_success(f"Accounts added to database from {filename}")
            logger.info(f"Completed JSON import from '{filename}'. Imported {len(imported_accounts)} accounts.")
        except Exception as e:
            print_error(f"Import failed: {str(e)}")
            logger.error(f"JSON import failed for file '{filename}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def import_from_csv_dialog(self) -> bool:
        """Import accounts from CSV."""
        print_header("Import Accounts from CSV")
        
        import_dir = "imports"
        os.makedirs(import_dir, exist_ok=True)
        
        # Get import path
        filename = questionary.text(
            "Enter path to CSV file:"
        ).ask()
        
        if not filename:
            print_error("No filename provided.")
            ask_to_continue()
            return True
        
        # Do the import
        try:
            imported_accounts = import_from_csv(filename, self.current_user.username)
            
            if not imported_accounts:
                print_error("No accounts were imported. Check file format.")
                ask_to_continue()
                return True
            
            print_success(f"Successfully imported {len(imported_accounts)} accounts")
            
            # Add accounts to storage
            for account_data in imported_accounts:
                self.storage.create_account_from_dict(account_data)
            
            print_success(f"Accounts added to database from {filename}")
            logger.info(f"Completed CSV import from '{filename}'. Imported {len(imported_accounts)} accounts.")
        except Exception as e:
            print_error(f"Import failed: {str(e)}")
            logger.error(f"CSV import failed for file '{filename}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def import_from_text_dialog(self) -> bool:
        """Import accounts from text file."""
        print_header("Import Accounts from Text")
        
        import_dir = "imports"
        os.makedirs(import_dir, exist_ok=True)
        
        # Get import path
        filename = questionary.text(
            "Enter path to text file:"
        ).ask()
        
        if not filename:
            print_error("No filename provided.")
            ask_to_continue()
            return True
        
        # Do the import
        try:
            imported_accounts = import_from_text(filename, self.current_user.username)
            
            if not imported_accounts:
                print_error("No accounts were imported. Check file format.")
                ask_to_continue()
                return True
            
            print_success(f"Successfully imported {len(imported_accounts)} accounts")
            
            # Add accounts to storage
            for account_data in imported_accounts:
                self.storage.create_account_from_dict(account_data)
            
            print_success(f"Accounts added to database from {filename}")
            logger.info(f"Completed Text import from '{filename}'. Imported {len(imported_accounts)} accounts.")
        except Exception as e:
            print_error(f"Import failed: {str(e)}")
            logger.error(f"Text import failed for file '{filename}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def manage_account(self) -> bool:
        """Manage an existing account. Admin only."""
        if self.current_user.role != UserRole.ADMIN:
            print_error("You don't have permission to manage accounts.")
            ask_to_continue()
            return True
            
        print_header("Manage Account")
        
        # Get all accounts for admin
        accounts = self.storage.get_accounts()
        
        if not accounts:
            print_info("There are no accounts to manage.")
            ask_to_continue()
            return True
        
        # Convert to dicts for display
        account_dicts = [account.model_dump() for account in accounts]
        
        # Display accounts
        display_accounts_table(account_dicts, show_credentials=False)
        
        # Ask which account to manage
        account_choices = {f"{acc.name} ({acc.username})": acc.id for acc in accounts}
        account_choices["Cancel"] = None
        
        # Use questionary directly
        selected = questionary.select(
            "Select account to manage:",
            choices=list(account_choices.keys())
        ).ask()
        
        if selected == "Cancel" or selected is None:
            return True
        
        account_id = account_choices[selected]
        account = self.storage.get_account(account_id)
        
        if not account:
            print_error("Account not found.")
            logger.error(f"Attempted to manage non-existent account ID: {account_id}")
            ask_to_continue()
            return True
        
        # Show account management options
        self.show_account_management_menu(account)
        
        return True
    
    def show_account_management_menu(self, account):
        """Show menu for managing a specific account."""
        while True:
            print_header(f"Managing Account: {account.name}")
            
            # Display current account details
            account_dict = account.model_dump()
            display_accounts_table([account_dict], show_credentials=True)
            
            options = [
                ("1", "Edit Account", lambda: self.edit_account(account)),
                ("2", "Delete Account", lambda: self.delete_account(account)),
                ("3", "Back", lambda: False)
            ]
            
            callback = render_menu(f"Account: {account.name} - Options", options)
            if callback is None or callback() is False:
                break
    
    def edit_account(self, account) -> bool:
        """Edit an existing account."""
        print_header(f"Edit Account: {account.name}")
        
        fields = [
            {"name": "name", "message": "Account Name:", "default": account.name},
            {"name": "username", "message": "Account Username:", "default": account.username},
            {"name": "password", "message": "Account Password (leave empty to keep current):", "type": "password"},
            {"name": "website", "message": "Website:", "default": account.website or ""},
            {"name": "notes", "message": "Notes:", "default": account.notes or ""}
        ]
        
        form_data = form_input(fields)
        
        if not form_data.get("name") or not form_data.get("username"):
            print_error("Account name and username are required.")
            logger.warning(f"Edit account failed for ID {account.id}: Missing name or username.")
            ask_to_continue()
            return True
        
        # If password is empty, don't update it
        if not form_data.get("password"):
            del form_data["password"]
        
        display_spinner("Updating account...", 0.5)
        
        try:
            updated_account = self.storage.update_account(
                account_id=account.id,
                name=form_data["name"],
                username=form_data["username"],
                password=form_data.get("password"),
                website=form_data["website"],
                notes=form_data["notes"]
            )
            
            if updated_account:
                print_success(f"Account '{updated_account.name}' updated successfully!")
                # Update the account object for the calling function
                account.name = updated_account.name
                account.username = updated_account.username
                if "password" in form_data:
                    account.password = updated_account.password
                account.website = updated_account.website
                account.notes = updated_account.notes
            else:
                print_error("Failed to update account.")
            
            ask_to_continue()
            return True
        except Exception as e:
            print_error(f"Error updating account: {str(e)}")
            logger.error(f"Error updating account ID {account.id}: {e}", exc_info=True)
            ask_to_continue()
            return True
    
    def delete_account(self, account) -> bool:
        """Delete an existing account."""
        print_header(f"Delete Account: {account.name}")
        
        confirm = confirm_action(
            f"Are you sure you want to delete account '{account.name}'? This cannot be undone.",
            default=False
        )
        
        if not confirm:
            print_info("Deletion cancelled.")
            ask_to_continue()
            return True
        
        display_spinner("Deleting account...", 0.5)
        
        try:
            success = self.storage.delete_account(account.id)
            
            if success:
                print_success(f"Account '{account.name}' deleted successfully!")
            else:
                print_error("Failed to delete account.")
            
            ask_to_continue()
            return False  # Return to account list
        except Exception as e:
            print_error(f"Error deleting account: {str(e)}")
            logger.error(f"Error deleting account ID {account.id}: {e}", exc_info=True)
            ask_to_continue()
            return True
    
    def change_password(self) -> bool:
        """Change user's password."""
        print_header("Change Password")
        
        fields = [
            {"name": "current_password", "message": "Current Password:", "type": "password"},
            {"name": "new_password", "message": "New Password:", "type": "password"},
            {"name": "confirm_password", "message": "Confirm New Password:", "type": "password"}
        ]
        
        form_data = form_input(fields)
        
        # Verify current password
        user = self.storage.authenticate_user(
            self.current_user.username,
            form_data["current_password"]
        )
        
        if not user:
            print_error("Current password is incorrect.")
            logger.warning(f"Password change failed for user {self.current_user.username}: Incorrect current password.")
            ask_to_continue()
            return True
        
        # Check if new passwords match
        if form_data["new_password"] != form_data["confirm_password"]:
            print_error("New passwords do not match.")
            logger.warning(f"Password change failed for user {self.current_user.username}: New passwords do not match.")
            ask_to_continue()
            return True
        
        # Update password
        display_spinner("Updating password...", 0.5)
        
        try:
            updated_user = self.storage.update_user(
                username=self.current_user.username,
                new_password=form_data["new_password"]
            )
            
            if updated_user:
                self.current_user = updated_user
                print_success("Password updated successfully!")
            else:
                # This case might indicate an unexpected issue if no exception was raised
                print_error("Failed to update password (no exception).")
                logger.error(f"Admin password update returned None without exception for user '{self.current_user.username}'")
        except Exception as e:
            print_error(f"Error updating password: {str(e)}")
            logger.error(f"Admin failed to update password for user '{self.current_user.username}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def manage_users(self) -> bool:
        """Admin function to manage users."""
        if self.current_user.role != UserRole.ADMIN:
            print_error("You don't have permission to access this.")
            ask_to_continue()
            return True
        
        while True:
            print_header("Manage Users")
            
            # Get all users
            all_users = self.storage.get_users()
            
            # Convert to dicts for display
            user_dicts = [user.model_dump() for user in all_users]
            
            # Display users
            display_users_table(user_dicts)
            
            options = [
                ("1", "Add User", self.admin_add_user),
                ("2", "Edit User", self.admin_edit_user),
                ("3", "Delete User", self.admin_delete_user),
                ("4", "Back", lambda: False)
            ]
            
            callback = render_menu("User Management", options)
            if callback is None or callback() is False:
                break
        
        return True
    
    def admin_add_user(self) -> bool:
        """Admin function to add a new user."""
        print_header("Add New User")
        
        fields = [
            {"name": "username", "message": "Username:"},
            {"name": "password", "message": "Password:", "type": "password"},
            {"name": "role", "message": "Role:", "type": "select", 
             "choices": [UserRole.USER, UserRole.ADMIN]}
        ]
        
        form_data = form_input(fields)
        
        if not form_data.get("username") or not form_data.get("password"):
            print_error("Username and password are required.")
            logger.warning("Admin add user failed: Missing username or password.")
            ask_to_continue()
            return True
        
        # Check if username already exists
        if self.storage.get_user(form_data["username"]):
            print_error(f"Username '{form_data['username']}' is already taken.")
            logger.warning(f"Admin add user failed: Username '{form_data['username']}' already exists.")
            ask_to_continue()
            return True
        
        display_spinner("Creating user...", 0.5)
        
        try:
            user = self.storage.create_user(
                form_data["username"],
                form_data["password"],
                form_data["role"]
            )
            
            print_success(f"User '{user.username}' created successfully with role '{user.role}'.")
            ask_to_continue()
            return True
        except Exception as e:
            print_error(f"Error creating user: {str(e)}")
            logger.error(f"Admin failed to create user '{form_data.get('username', 'N/A')}': {e}", exc_info=True)
            ask_to_continue()
            return True
    
    def admin_edit_user(self) -> bool:
        """Admin function to edit an existing user."""
        print_header("Edit User")
        
        # Get all users
        all_users = self.storage.get_users()
        
        # Create selection options excluding current admin
        user_choices = {user.username: user for user in all_users 
                       if user.username != self.current_user.username}
        user_choices["Cancel"] = None
        
        # Use questionary directly
        selected = questionary.select(
            "Select user to edit:",
            choices=list(user_choices.keys())
        ).ask()
        
        if selected == "Cancel" or selected is None:
            return True
        
        user = user_choices[selected]
        
        # Edit options
        print_header(f"Edit User: {user.username}")
        
        edit_options = [
            ("1", "Change Password", lambda: self.admin_change_user_password(user)),
            ("2", "Change Role", lambda: self.admin_change_user_role(user)),
            ("3", "Back", lambda: False)
        ]
        
        callback = render_menu(f"Edit User: {user.username}", edit_options)
        if callback is None:
            return True
        
        return callback()
    
    def admin_change_user_password(self, user) -> bool:
        """Admin function to change a user's password."""
        print_header(f"Change Password for: {user.username}")
        
        fields = [
            {"name": "new_password", "message": "New Password:", "type": "password"},
            {"name": "confirm_password", "message": "Confirm New Password:", "type": "password"}
        ]
        
        form_data = form_input(fields)
        
        if not form_data.get("new_password"):
            print_error("Password is required.")
            logger.warning(f"Admin change password failed for user '{user.username}': No password provided.")
            ask_to_continue()
            return True
        
        # Check if new passwords match
        if form_data["new_password"] != form_data["confirm_password"]:
            print_error("Passwords do not match.")
            logger.warning(f"Admin change password failed for user '{user.username}': Passwords do not match.")
            ask_to_continue()
            return True
        
        # Update password
        display_spinner("Updating password...", 0.5)
        
        try:
            updated_user = self.storage.update_user(
                username=user.username,
                new_password=form_data["new_password"]
            )
            
            if updated_user:
                print_success(f"Password for '{user.username}' updated successfully!")
            else:
                # This case might indicate an unexpected issue if no exception was raised
                print_error("Failed to update password (no exception).")
                logger.error(f"Admin password update returned None without exception for user '{user.username}'")
        except Exception as e:
            print_error(f"Error updating password: {str(e)}")
            logger.error(f"Admin failed to update password for user '{user.username}': {e}", exc_info=True)
        
        ask_to_continue()
        return True
    
    def admin_change_user_role(self, user) -> bool:
        """Admin function to change a user's role."""
        print_header(f"Change Role for: {user.username}")
        
        current_role = user.role
        new_role = UserRole.ADMIN if current_role == UserRole.USER else UserRole.USER
        
        confirm = confirm_action(
            f"Change user '{user.username}' role from '{current_role}' to '{new_role}'?",
            default=False
        )
        
        if not confirm:
            print_info("Role change cancelled.")
            ask_to_continue()
            return True
        
        display_spinner("Updating role...", 0.5)
        
        updated_user = self.storage.update_user(
            username=user.username,
            new_role=new_role
        )
        
        if updated_user:
            print_success(f"Role for '{user.username}' updated to '{new_role}' successfully!")
        else:
            print_error("Failed to update role.")
            logger.error(f"Admin role update returned None for user '{user.username}'")
        
        ask_to_continue()
        return True
    
    def admin_delete_user(self) -> bool:
        """Admin function to delete a user."""
        print_header("Delete User")
        
        # Get all users
        all_users = self.storage.get_users()
        
        # Create selection options excluding current admin
        user_choices = {user.username: user for user in all_users 
                       if user.username != self.current_user.username}
        user_choices["Cancel"] = None
        
        # Use questionary directly
        selected = questionary.select(
            "Select user to delete:",
            choices=list(user_choices.keys())
        ).ask()
        
        if selected == "Cancel" or selected is None:
            return True
        
        user = user_choices[selected]
        
        confirm = confirm_action(
            f"Are you sure you want to delete user '{user.username}'? This will also delete all accounts created by this user.",
            default=False
        )
        
        if not confirm:
            print_info("Deletion cancelled.")
            ask_to_continue()
            return True
        
        display_spinner("Deleting user...", 0.5)
        
        success = self.storage.delete_user(user.username)
        
        if success:
            print_success(f"User '{user.username}' and all their accounts deleted successfully!")
        else:
            print_error("Failed to delete user.")
            logger.error(f"Admin user deletion failed for user '{user.username}'")
        
        ask_to_continue()
        return True 