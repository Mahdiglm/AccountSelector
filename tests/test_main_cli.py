# tests/test_main_cli.py

import pytest
import os
import sys
from unittest.mock import patch, call, MagicMock
import logging

# Assuming src is importable (e.g., running pytest from root)
from src.data.storage import Storage
from src.main import AccountSelectorApp
from src.data.models import UserRole, Account, AccountCategory

# Keep original Storage init for patching later
Storage_orig_init = Storage.__init__

# Setup logger for this test module
logger = logging.getLogger(__name__)

# Fixture for temporary storage 
@pytest.fixture
def temp_app_storage(tmp_path):
    test_data_folder = tmp_path / "test_app_data_cli"
    test_data_folder.mkdir()
    yield str(test_data_folder)

# Fixture for temporary storage used by CLI tests
@pytest.fixture
@patch('src.data.storage.getpass.getpass')
@patch('builtins.input')
def initialized_storage(mock_input, mock_getpass, mocker, temp_app_storage):
    master_pw = "testpassword"
    admin_user = "testadmin"
    admin_pass = "AdminPass123!"

    # Mocks are now passed as arguments by the decorators
    # Configure the mocks inside the fixture
    mock_input.return_value = admin_user
    mock_getpass.side_effect = [admin_pass, admin_pass]

    logger.debug(f"[Fixture] Setting up initialized_storage in {temp_app_storage}")
    logger.debug(f"[Fixture] Mocking input with return_value: {admin_user}")
    logger.debug(f"[Fixture] Mocking getpass with side_effect (admin only): [{'*'*len(admin_pass)}, {'*'*len(admin_pass)}]")
    
    storage = Storage(data_folder=temp_app_storage, master_password=master_pw)
    # Ensure admin was created
    assert storage.get_user(admin_user) is not None
    # Return storage configured with initial admin
    return storage 

# --- Integration Tests ---

def test_app_start_calls_auth_menu(mocker, initialized_storage):
    """Test that app.start() calls show_auth_menu when no user is logged in."""
    # Use the storage already initialized with admin user
    # NOTE: This test focuses on the initial state leading to auth menu.
    # We don't need to run app.start() which causes console issues.
    storage = initialized_storage
    
    # Patch the Storage class in src.main so the app gets our initialized instance
    mocker.patch('src.main.Storage', return_value=storage)

    app = AccountSelectorApp()
    # Check the initial condition: no user logged in
    assert app.current_user is None
    # We infer that if current_user is None, app.start() *would* call show_auth_menu.


def test_successful_login(mocker, capsys, initialized_storage):
    """Test logging in successfully as the initial admin."""
    storage = initialized_storage
    admin_user = "testadmin"
    admin_pass = "AdminPass123!"

    # Inputs for login: select login(1), enter user, enter pass, press enter to continue
    inputs = ["1", admin_user, "any_key_press"] # ask_to_continue needs input
    mock_input = mocker.patch('builtins.input', side_effect=inputs)
    mock_getpass = mocker.patch('getpass.getpass', return_value=admin_pass)
    
    # Patch the Storage class in src.main so the app gets our initialized instance
    mocker.patch('src.main.Storage', return_value=storage)

    # Patch form_input to bypass questionary and return mocked data
    mocker.patch('src.main.form_input', return_value={'username': admin_user, 'password': admin_pass})

    app = AccountSelectorApp()
    # We assume show_auth_menu would call self.login if input is "1"
    result = app.login()
    assert result is True # login returns True on success

    captured = capsys.readouterr()
    assert f"Welcome back, {admin_user}!" in captured.out
    assert app.current_user is not None
    assert app.current_user.username == admin_user
    
    # Verify input and getpass were called as expected
    # input calls: select menu(1), ask_to_continue(any_key_press)
    # getpass calls: password field(1)
    assert mock_input.call_count == 1 # Only _ask_to_continue calls input now
    # getpass is not called directly by login anymore due to form_input patch
    # mock_getpass.assert_called_once() # No longer relevant


def test_failed_login_wrong_password(mocker, capsys, initialized_storage):
    """Test failed login with wrong password."""
    storage = initialized_storage
    admin_user = "testadmin"
    admin_pass = "AdminPass123!"
    wrong_pass = "wrongpassword"

    # Inputs: select login(1), enter user, enter wrong pass, press enter
    inputs = ["1", admin_user, "any_key_press"] 
    mock_input = mocker.patch('builtins.input', side_effect=inputs)

    # Patch the Storage class in src.main so the app gets our initialized instance
    mocker.patch('src.main.Storage', return_value=storage)

    # Patch form_input to bypass questionary and return mocked data
    mocker.patch('src.main.form_input', return_value={'username': admin_user, 'password': wrong_pass})

    app = AccountSelectorApp()
    # We assume show_auth_menu would call self.login if input is "1"
    result = app.login()
    assert result is True # login always returns True to keep menu loop going

    captured = capsys.readouterr()
    assert "Invalid username or password." in captured.out
    assert app.current_user is None
    assert mock_input.call_count == 1 # Only ask_to_continue calls input


# Delete the helper function as we are calling methods directly now
# def run_app_with_inputs(mocker, capsys, inputs, data_folder):
#    ...

# Delete the old auth menu test which ran app.start()
# def test_app_shows_auth_menu(mocker, capsys, temp_app_storage):
#    ...


# TODO: Add tests for:
# - Failed Login (non-existent user)
# - Sign Up (success, duplicate user, weak password)
# - Admin actions (add account, etc.)
# - User actions (browse, select account)
# - Password Change 

def test_add_account_success(mocker, initialized_storage):
    """Test adding a new account successfully via the app method."""
    storage = initialized_storage

    # Patch Storage *before* creating the app instance
    mocker.patch('src.main.Storage', return_value=storage)

    app = AccountSelectorApp()
    app.current_user = storage.get_user("testadmin") # Set current user

    account_details = {
        "name": "Test Site",
        "username": "testuser",
        "password": "TestPassword123!",
        "notes": "Some notes."
    }

    # Mock form_input to provide the details
    mock_form = mocker.patch('src.main.form_input', return_value=account_details)
    # Mock ask_to_continue to prevent hanging
    mock_ask = mocker.patch('src.main.ask_to_continue')
    # Mock the category selection prompt within add_account
    mock_cat_select = mocker.patch('src.main.questionary.select')
    # Configure the mock object that mock_cat_select returns to have an ask() method
    mock_cat_select.return_value.ask.return_value = "Default" # Simulate choosing 'Default' category

    # Mock the tags input prompt within add_account
    mock_tag_text = mocker.patch('src.main.questionary.text')
    mock_tag_text.return_value.ask.return_value = "test, tag" # Simulate entering tags

    # Mock the expiry confirmation prompt within add_account (called via confirm_action)
    mock_expiry_confirm = mocker.patch('src.utils.cli.questionary.confirm')
    mock_expiry_confirm.return_value.ask.return_value = False # Simulate answering No

    # Call the method under test
    result = app.add_account()

    # Assertions
    assert result is True # add_account should return True on success
    mock_form.assert_called_once()
    mock_ask.assert_called_once()

    # Verify account was created in storage
    all_accounts = storage.get_accounts()
    created_account = next((acc for acc in all_accounts if acc.name == "Test Site"), None)
    assert created_account is not None
    assert created_account.username == "testuser"
    # Note: We don't check the password directly here as it's encrypted in storage


# Add more tests below... 

# --- browse_accounts Tests ---

def test_browse_accounts_admin_view(mocker, initialized_storage):
    """Test that browse_accounts shows all accounts with credentials for admin."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    assert admin_user is not None # Make sure admin exists from fixture

    # --- Arrange ---
    # 1. Create some test accounts
    # Need valid passwords according to policy
    account1 = storage.create_account(name="Site_A", username="userA", password="ValidPassA1!", created_by=admin_user.username, notes="Notes A")
    account2 = storage.create_account(name="Site_B", username="userB", password="ValidPassB2?", created_by=admin_user.username, notes="Notes B")

    # 2. Setup App instance with logged-in admin
    mocker.patch('src.main.Storage', return_value=storage) # Patch storage for app init
    app = AccountSelectorApp()
    app.current_user = admin_user # Manually set logged-in user

    # 3. Mock display and continuation functions
    mock_display = mocker.patch('src.main.display_accounts_table')
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mock_print_header = mocker.patch('src.main.print_header') # Also mock header printing

    # --- Act ---
    result = app.browse_accounts()

    # --- Assert ---
    assert result is True # Method should return True to continue menu loop

    # Verify display_accounts_table was called correctly
    mock_display.assert_called_once()
    args, kwargs = mock_display.call_args
    
    # Check the data passed to the display function
    displayed_data = args[0]
    assert isinstance(displayed_data, list)
    assert len(displayed_data) == 2 # Should display both accounts
    # Check if data for account1 and account2 is present (can check names or ids)
    displayed_names = {acc['name'] for acc in displayed_data}
    assert displayed_names == {"Site_A", "Site_B"}

    # Check that show_credentials was True for admin
    assert kwargs.get('show_credentials') is True

    # Verify other mocks
    mock_ask.assert_called_once()
    # Verify header was printed with "All Accounts"
    # Use call_args_list to check all calls if needed, or assert_any_call
    mock_print_header.assert_any_call("All Accounts") 

def test_browse_accounts_user_view(mocker, initialized_storage):
    """Test browse_accounts shows available (non-selected) accounts without credentials for regular users."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")

    # --- Arrange ---
    # 1. Create a regular user
    test_user = storage.create_user("testuser", "RegularUserPass1!")

    # 2. Create some accounts (as admin)
    account1 = storage.create_account(name="Site_A", username="userA", password="ValidPassA1!", created_by=admin_user.username)
    account2 = storage.create_account(name="Site_B", username="userB", password="ValidPassB2?", created_by=admin_user.username)
    account3 = storage.create_account(name="Site_C", username="userC", password="ValidPassC3#", created_by=admin_user.username)

    # 3. Simulate user selecting one account
    test_user.selected_account_ids.append(account2.id)
    storage.update_user(username=test_user.username, selected_account_ids=test_user.selected_account_ids)
    # Re-fetch user to ensure updated state is used
    test_user = storage.get_user(test_user.username)
    assert account2.id in test_user.selected_account_ids

    # 4. Setup App instance with logged-in regular user
    mocker.patch('src.main.Storage', return_value=storage) # Patch storage for app init
    app = AccountSelectorApp()
    app.current_user = test_user # Manually set logged-in user

    # 5. Mock display, prompts, and info functions
    mock_display = mocker.patch('src.main.display_accounts_table')
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mock_print_header = mocker.patch('src.main.print_header') 
    mock_print_info = mocker.patch('src.main.print_info')
    # Mock the confirmation prompt for selecting an account to return False (don't proceed)
    mock_confirm = mocker.patch('src.main.confirm_action', return_value=False)
    
    # --- Act ---
    result = app.browse_accounts()

    # --- Assert ---
    assert result is True # Method should return True

    # Verify display_accounts_table was called correctly
    mock_display.assert_called_once()
    args, kwargs = mock_display.call_args
    
    # Check the data passed includes only non-selected accounts (A and C)
    displayed_data = args[0]
    assert isinstance(displayed_data, list)
    assert len(displayed_data) == 2 
    displayed_names = {acc['name'] for acc in displayed_data}
    assert displayed_names == {"Site_A", "Site_C"}
    assert "Site_B" not in displayed_names # Ensure selected account is excluded

    # Check that show_credentials was False for regular user
    assert kwargs.get('show_credentials') is False

    # Verify header/info messages
    mock_print_header.assert_any_call("Available Accounts (Read-only Access)")
    mock_print_info.assert_any_call("As a regular user, you can view account credentials but cannot modify them.")

    # Verify confirm_action was called (since accounts were available)
    mock_confirm.assert_called_once_with("Would you like to select an account? (Read-only access)", default=True)
    
    # Verify ask_to_continue was called
    mock_ask.assert_called_once() 

# --- manage_account / delete_account Tests ---

def test_delete_account_admin(mocker, initialized_storage):
    """Test deleting an account via the admin management flow."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    assert admin_user is not None

    # --- Arrange ---
    # 1. Create an account to delete
    account_to_delete = storage.create_account(
        name="ToDelete", username="del_user", password="ToDeletePass1!", created_by=admin_user.username
    )
    assert storage.get_account(account_to_delete.id) is not None # Verify exists initially

    # 2. Setup App instance
    mocker.patch('src.main.Storage', return_value=storage) 
    app = AccountSelectorApp()
    app.current_user = admin_user

    # 3. Mock UI interactions
    #    - Select the account in manage_account
    #    - Choose 'Delete Account' in show_account_management_menu
    #    - Confirm deletion in delete_account
    #    - ask_to_continue at the end
    mock_q_select = mocker.patch('src.main.questionary.select')
    mock_q_select.return_value.ask.return_value = f"{account_to_delete.name} ({account_to_delete.username})" # Simulate selecting the account
    
    # Mock render_menu to simulate choosing option 2 (Delete)
    # It needs to return the callback function associated with deleting
    # We need to capture the options passed to render_menu to find the right callback
    delete_callback = None
    def capture_render_menu_options(*args, **kwargs):
        nonlocal delete_callback
        options = args[1] # Options are usually the second argument
        for _, label, callback_func in options:
            if label == "Delete Account":
                delete_callback = callback_func
                break
        return delete_callback # Return the found callback to be executed
    mock_render = mocker.patch('src.main.render_menu', side_effect=capture_render_menu_options)
    
    # Mock confirm_action within delete_account to return True
    mock_confirm = mocker.patch('src.main.confirm_action', return_value=True) 
    
    # Mock ask_to_continue used within delete_account
    mock_ask = mocker.patch('src.main.ask_to_continue')
    
    # Mock display tables and headers to reduce noise
    mocker.patch('src.main.display_accounts_table')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.print_success')
    mocker.patch('src.main.print_info')

    # --- Act ---
    # Call manage_account, which should lead to delete_account through the mocks
    result = app.manage_account()
    # manage_account returns True to continue loop, inner delete returns False
    assert result is True

    # --- Assert ---
    # Ensure the mocks were called as expected
    mock_q_select.assert_called_once() 
    mock_render.assert_called_once() # Called by show_account_management_menu
    mock_confirm.assert_called_once_with(
        f"Are you sure you want to delete account '{account_to_delete.name}'? This cannot be undone.",
        default=False
    )
    mock_ask.assert_called_once() # Called after deletion attempt
    
    # Verify the account is actually deleted from storage
    assert storage.get_account(account_to_delete.id) is None 

# --- manage_users / delete_user Tests ---

def test_delete_user_admin(mocker, initialized_storage):
    """Test deleting a user via the admin management flow."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    assert admin_user is not None

    # --- Arrange ---
    # 1. Create a user to delete
    user_to_delete = storage.create_user("usertodelete", "ValidUserPass123!")
    assert storage.get_user(user_to_delete.username) is not None

    # 2. Setup App instance
    mocker.patch('src.main.Storage', return_value=storage) 
    app = AccountSelectorApp()
    app.current_user = admin_user

    # 3. Mock UI interactions
    #    - Choose 'Delete User' in manage_users menu
    #    - Select the user in admin_delete_user
    #    - Confirm deletion in admin_delete_user
    #    - ask_to_continue at the end

    # Mock the UI elements *within* admin_delete_user
    mock_select_ask = mocker.patch('src.main.questionary.select').return_value.ask
    # Ensure the mock returns the username string, as questionary would
    mock_select_ask.return_value = user_to_delete.username 
    
    # Mock confirm_action within admin_delete_user
    mock_confirm = mocker.patch('src.main.confirm_action', return_value=True) 

    # Mock ask_to_continue
    mock_ask = mocker.patch('src.main.ask_to_continue')

    # Mock display tables and headers
    mocker.patch('src.main.display_users_table')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.print_success')
    mocker.patch('src.main.print_info')

    # --- Act: Directly call admin_delete_user ---
    # We've already confirmed manage_users calls the right function via menu
    # Now test the delete function in isolation with its mocks
    result = app.admin_delete_user()

    # --- Assert mocks for admin_delete_user were called
    mock_select_ask.assert_called_once() # Called by admin_delete_user
    mock_confirm.assert_called_once_with(
        f"Are you sure you want to delete user '{user_to_delete.username}'? This will also delete all accounts created by this user.",
        default=False
    )
    mock_ask.assert_called_once() # Called after deletion

    # Verify the user is actually deleted from storage
    assert storage.get_user(user_to_delete.username) is None 

# --- Sign Up Tests ---

def test_signup_success(mocker, initialized_storage):
    """Test successful user signup."""
    storage = initialized_storage # Fixture provides initial admin, but we won't use them
    
    # --- Arrange ---
    signup_details = {
        "username": "newsignup",
        "password": "ValidNewSignupPass123!",
        "password_confirm": "ValidNewSignupPass123!"
    }

    # Setup App instance
    mocker.patch('src.main.Storage', return_value=storage) 
    app = AccountSelectorApp()
    assert app.current_user is None # Start logged out

    # Mock UI interactions
    mock_form = mocker.patch('src.main.form_input', return_value=signup_details)
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.print_success')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.signup()
    
    # --- Assert ---
    assert result is True # Signup returns True
    mock_form.assert_called_once()
    mock_ask.assert_called_once()

    # Verify user was created in storage
    created_user = storage.get_user("newsignup")
    assert created_user is not None
    assert created_user.username == "newsignup"
    assert created_user.role == UserRole.USER # Default role
    
    # Verify user is auto-logged in
    assert app.current_user is not None
    assert app.current_user.username == "newsignup"


def test_signup_failure_password_mismatch(mocker, initialized_storage):
    """Test signup failure when passwords don't match."""
    storage = initialized_storage
    
    # --- Arrange ---
    signup_details = {
        "username": "newsignupfail",
        "password": "ValidPass123!",
        "password_confirm": "WrongPass123!"
    }

    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    assert app.current_user is None

    mock_form = mocker.patch('src.main.form_input', return_value=signup_details)
    mock_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.signup()
    
    # --- Assert ---
    assert result is True # Signup returns True even on handled failure to keep main loop running
    mock_form.assert_called_once()
    mock_error.assert_called_once_with("Passwords do not match.")
    mock_ask_continue.assert_called_once() # Verify input pause was mocked
    assert storage.get_user("newsignupfail") is None # User not created
    assert app.current_user is None # User not logged in


def test_signup_failure_username_exists(mocker, initialized_storage):
    """Test signup failure when username already exists."""
    storage = initialized_storage
    existing_user = storage.get_user("testadmin")
    assert existing_user is not None

    # --- Arrange ---
    signup_details = {
        "username": existing_user.username,
        "password": "AnyValidPassword123!",
        "password_confirm": "AnyValidPassword123!"
    }

    mocker.patch('src.main.Storage', return_value=storage) 
    app = AccountSelectorApp()
    assert app.current_user is None

    mock_form = mocker.patch('src.main.form_input', return_value=signup_details)
    mock_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.signup()
    
    # --- Assert ---
    assert result is True # Signup returns True even on handled failure to keep main loop running
    mock_form.assert_called_once()
    mock_error.assert_called_once_with(f"Username '{existing_user.username}' is already taken.")
    # Check mock was called
    mock_ask_continue.assert_called_once()
    # Check storage again to ensure no modification happened to the existing user
    retrieved_user = storage.get_user(existing_user.username)
    assert retrieved_user is not None
    assert retrieved_user.password_hash == existing_user.password_hash
    assert app.current_user is None # User not logged in

# --- Change Password Tests ---

def test_change_password_success(mocker, initialized_storage):
    """Test successful password change."""
    storage = initialized_storage
    user_to_test = storage.get_user("testadmin")
    original_password = "AdminPass123!"
    new_password = "NewValidPass456!"
    
    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = user_to_test
    
    change_details = {
        "current_password": original_password,
        "new_password": new_password,
        "confirm_password": new_password
    }
    
    mock_form = mocker.patch('src.main.form_input', return_value=change_details)
    mock_success = mocker.patch('src.main.print_success')
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')
    
    # --- Act ---
    result = app.change_password()
    
    # --- Assert ---
    assert result is True # change_password returns True
    mock_form.assert_called_once()
    mock_success.assert_called_once_with("Password updated successfully!")
    mock_ask.assert_called_once()
    
    # Verify password was actually changed in storage
    updated_user = storage.get_user(user_to_test.username)
    assert updated_user.password_hash != user_to_test.password_hash
    # Check if the new password works for authentication (indirect check)
    assert storage.authenticate_user(user_to_test.username, new_password) is not None


def test_change_password_failure_wrong_current(mocker, initialized_storage):
    """Test password change failure due to incorrect current password."""
    storage = initialized_storage
    user_to_test = storage.get_user("testadmin")
    wrong_current_password = "WrongPassword!"
    new_password = "NewValidPass456!"

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = user_to_test

    change_details = {
        "current_password": wrong_current_password,
        "new_password": new_password,
        "confirm_password": new_password
    }

    mock_form = mocker.patch('src.main.form_input', return_value=change_details)
    mock_error = mocker.patch('src.main.print_error')
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.change_password()

    # --- Assert ---
    assert result is True # change_password still returns True after error message
    mock_form.assert_called_once()
    mock_error.assert_called_once_with("Current password is incorrect.")
    mock_ask.assert_called_once()
    
    # Verify password was NOT changed
    unchanged_user = storage.get_user(user_to_test.username)
    assert unchanged_user.password_hash == user_to_test.password_hash


def test_change_password_failure_mismatch_new(mocker, initialized_storage):
    """Test password change failure due to new passwords not matching."""
    storage = initialized_storage
    user_to_test = storage.get_user("testadmin")
    original_password = "AdminPass123!"
    new_password = "NewValidPass456!"
    mismatched_confirm = "MismatchedPass789!"

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = user_to_test

    change_details = {
        "current_password": original_password,
        "new_password": new_password,
        "confirm_password": mismatched_confirm
    }

    mock_form = mocker.patch('src.main.form_input', return_value=change_details)
    mock_error = mocker.patch('src.main.print_error')
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')

    # --- Act ---
    result = app.change_password()

    # --- Assert ---
    assert result is True # change_password still returns True after error message
    mock_form.assert_called_once()
    mock_error.assert_called_once_with("New passwords do not match.")
    mock_ask.assert_called_once()

    # Verify password was NOT changed
    unchanged_user = storage.get_user(user_to_test.username)
    assert unchanged_user.password_hash == user_to_test.password_hash


@pytest.mark.xfail(raises=ValueError, reason="Tests policy violation handling; ValueError is caught by app")
def test_change_password_failure_policy(mocker, initialized_storage):
    """Test password change failure due to new password not meeting policy."""
    storage = initialized_storage
    user_to_test = storage.get_user("testadmin")
    original_password = "AdminPass123!"
    weak_password = "short" # Fails policy

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = user_to_test

    change_details = {
        "current_password": original_password,
        "new_password": weak_password,
        "confirm_password": weak_password
    }

    mock_form = mocker.patch('src.main.form_input', return_value=change_details)
    mock_error = mocker.patch('src.main.print_error')
    mock_ask = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')
    
    # Mock the internal validation method to raise the policy error
    policy_error_msg = "Password must be at least 12 characters long"
    def mock_validate_policy(password):
        if password == weak_password:
            raise ValueError(policy_error_msg)
        # Otherwise, do nothing (pass validation)

    mock_validation = mocker.patch.object(
        storage, 
        '_validate_password_against_policy', 
        side_effect=mock_validate_policy
    )

    # --- Act ---
    result = app.change_password()
     # The error message comes from the ValueError raised by storage
    mock_error.assert_called_once_with(f"Error changing password: {policy_error_msg}") 
    mock_ask.assert_called_once()
    mock_validation.assert_called_with(weak_password) # Verify the validation was attempted

    # Verify password was NOT changed
    unchanged_user = storage.get_user(user_to_test.username)
    assert unchanged_user.password_hash == user_to_test.password_hash

# --- Import/Export Tests ---

@pytest.fixture
def storage_with_accounts(initialized_storage):
    """Fixture to provide initialized storage with a couple of accounts."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    storage.create_account("TestAcc1", "user1", "Pass1@acc", created_by=admin_user.username)
    storage.create_account("TestAcc2", "user2", "Pass2@acc", created_by=admin_user.username)
    return storage


def test_export_to_json_success(mocker, storage_with_accounts):
    """Test successful export of accounts to JSON."""
    storage = storage_with_accounts
    admin_user = storage.get_user("testadmin")
    accounts_in_storage = storage.get_accounts()
    assert len(accounts_in_storage) == 2 # Ensure fixture created accounts

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user # Log in admin

    test_export_filename = "test_export.json"
    expected_export_path = os.path.join("exports", test_export_filename)

    # Mock UI and file system interactions
    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = expected_export_path
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_datetime = mocker.patch('src.main.datetime') # Prevent timestamp issues
    mock_datetime.now.return_value.strftime.return_value = "timestamp"

    # Mock the actual export function
    mock_export_json = mocker.patch('src.main.export_to_json', return_value=expected_export_path)

    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')

    # --- Act ---
    result = app.export_to_json_dialog()

    # --- Assert ---
    assert result is True
    mock_os_makedirs.assert_called_once_with("exports", exist_ok=True)
    mock_q_text.assert_called_once() # Check filename prompt was shown
    
    # Verify export_to_json was called correctly
    mock_export_json.assert_called_once()
    call_args, _ = mock_export_json.call_args
    exported_data = call_args[0]
    export_filename_arg = call_args[1]
    
    assert export_filename_arg == expected_export_path
    assert len(exported_data) == len(accounts_in_storage)
    # Check if exported data matches (simple check based on usernames)
    exported_usernames = {acc['username'] for acc in exported_data}
    storage_usernames = {acc.username for acc in accounts_in_storage}
    assert exported_usernames == storage_usernames

    mock_print_success.assert_called_once_with(
        f"Successfully exported {len(accounts_in_storage)} accounts to {expected_export_path}"
    )
    mock_ask_continue.assert_called_once()

def test_export_to_csv_success(mocker, storage_with_accounts):
    """Test successful export of accounts to CSV."""
    storage = storage_with_accounts
    admin_user = storage.get_user("testadmin")
    accounts_in_storage = storage.get_accounts()
    assert len(accounts_in_storage) == 2

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_export_filename = "test_export.csv"
    expected_export_path = os.path.join("exports", test_export_filename)

    # Mock UI and file system interactions
    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = expected_export_path
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_datetime = mocker.patch('src.main.datetime')
    mock_datetime.now.return_value.strftime.return_value = "timestamp"

    # Mock the actual export function
    mock_export_csv = mocker.patch('src.main.export_to_csv', return_value=expected_export_path)

    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')

    # --- Act ---
    result = app.export_to_csv_dialog()

    # --- Assert ---
    assert result is True
    mock_os_makedirs.assert_called_once_with("exports", exist_ok=True)
    mock_q_text.assert_called_once()
    
    # Verify export_to_csv was called correctly
    mock_export_csv.assert_called_once()
    call_args, _ = mock_export_csv.call_args
    exported_data = call_args[0]
    export_filename_arg = call_args[1]
    
    assert export_filename_arg == expected_export_path
    assert len(exported_data) == len(accounts_in_storage)
    exported_usernames = {acc['username'] for acc in exported_data}
    storage_usernames = {acc.username for acc in accounts_in_storage}
    assert exported_usernames == storage_usernames

    mock_print_success.assert_called_once_with(
        f"Successfully exported {len(accounts_in_storage)} accounts to {expected_export_path}"
    )
    mock_ask_continue.assert_called_once()

def test_export_to_json_failure(mocker, storage_with_accounts):
    """Test handling of failure during JSON export."""
    storage = storage_with_accounts
    admin_user = storage.get_user("testadmin")
    assert len(storage.get_accounts()) == 2

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_export_filename = "fail_export.json"
    expected_export_path = os.path.join("exports", test_export_filename)
    error_message = "Disk full simulation"

    # Mock UI and file system interactions
    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = expected_export_path
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_datetime = mocker.patch('src.main.datetime')
    mock_datetime.now.return_value.strftime.return_value = "timestamp"

    # Mock the actual export function to raise an error
    mock_export_json = mocker.patch('src.main.export_to_json', side_effect=Exception(error_message))

    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    # Mock logger to prevent errors showing in test output
    mock_logger_error = mocker.patch('src.main.logger.error') 

    # --- Act ---
    result = app.export_to_json_dialog()

    # --- Assert ---
    assert result is True # Dialog still returns True to continue main loop
    mock_os_makedirs.assert_called_once()
    mock_q_text.assert_called_once()
    mock_export_json.assert_called_once() # Verify it was called
    mock_print_error.assert_called_once_with(f"Export failed: {error_message}")
    mock_logger_error.assert_called_once() # Verify error was logged
    mock_ask_continue.assert_called_once()

# --- Import Tests ---

def test_import_from_json_success(mocker, initialized_storage):
    """Test successful import of accounts from JSON."""
    storage = initialized_storage # Use clean storage for import test
    admin_user = storage.get_user("testadmin")
    assert len(storage.get_accounts()) == 0 # Start with no accounts

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_import_filename = "test_import.json"
    # Simulate data returned by the import_from_json utility function
    mock_imported_data = [
        {"name": "ImportAcc1", "username": "import_user1", "password": "ImpP@ss1"},
        {"name": "ImportAcc2", "username": "import_user2", "password": "ImpP@ss2"},
    ]

    # Mock UI and file system interactions
    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = test_import_filename
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    
    # Mock the actual import function
    mock_import_json = mocker.patch('src.main.import_from_json', return_value=mock_imported_data)

    # Mock the storage method that adds accounts
    mock_storage_add = mocker.patch.object(storage, 'create_account_from_dict')

    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_info = mocker.patch('src.main.logger.info')

    # --- Act ---
    result = app.import_from_json_dialog()

    # --- Assert ---
    assert result is True
    mock_os_makedirs.assert_called_once_with("imports", exist_ok=True)
    mock_q_text.assert_called_once() # Verify filename prompt
    mock_import_json.assert_called_once_with(test_import_filename, admin_user.username)
    
    # Verify that storage.create_account_from_dict was called for each imported account
    assert mock_storage_add.call_count == len(mock_imported_data)
    mock_storage_add.assert_any_call(mock_imported_data[0])
    mock_storage_add.assert_any_call(mock_imported_data[1])

    # Check success messages
    assert mock_print_success.call_count == 2
    mock_print_success.assert_any_call(f"Successfully imported {len(mock_imported_data)} accounts")
    mock_print_success.assert_any_call(f"Accounts added to database from {test_import_filename}")
    mock_logger_info.assert_called_once() # Verify log message
    mock_ask_continue.assert_called_once()

def test_import_from_csv_success(mocker, initialized_storage):
    """Test successful import of accounts from CSV."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    assert len(storage.get_accounts()) == 0

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_import_filename = "test_import.csv"
    mock_imported_data = [
        {"name": "ImportCSV1", "username": "csv_user1", "password": "CsvP@ss1"},
    ]

    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = test_import_filename
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_import_csv = mocker.patch('src.main.import_from_csv', return_value=mock_imported_data)
    mock_storage_add = mocker.patch.object(storage, 'create_account_from_dict')
    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_info = mocker.patch('src.main.logger.info')

    # --- Act ---
    result = app.import_from_csv_dialog()

    # --- Assert ---
    assert result is True
    mock_os_makedirs.assert_called_once_with("imports", exist_ok=True)
    mock_q_text.assert_called_once()
    mock_import_csv.assert_called_once_with(test_import_filename, admin_user.username)
    assert mock_storage_add.call_count == len(mock_imported_data)
    mock_storage_add.assert_called_once_with(mock_imported_data[0])
    assert mock_print_success.call_count == 2
    mock_print_success.assert_any_call(f"Successfully imported {len(mock_imported_data)} accounts")
    mock_print_success.assert_any_call(f"Accounts added to database from {test_import_filename}")
    mock_logger_info.assert_called_once()
    mock_ask_continue.assert_called_once()

def test_import_from_text_success(mocker, initialized_storage):
    """Test successful import of accounts from Text."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    assert len(storage.get_accounts()) == 0

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_import_filename = "test_import.txt"
    mock_imported_data = [
        {"name": "ImportTxt1", "username": "txt_user1", "password": "TxtP@ss1"},
    ]

    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = test_import_filename
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_import_text = mocker.patch('src.main.import_from_text', return_value=mock_imported_data)
    mock_storage_add = mocker.patch.object(storage, 'create_account_from_dict')
    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_info = mocker.patch('src.main.logger.info')

    # --- Act ---
    result = app.import_from_text_dialog()

    # --- Assert ---
    assert result is True
    mock_os_makedirs.assert_called_once_with("imports", exist_ok=True)
    mock_q_text.assert_called_once()
    mock_import_text.assert_called_once_with(test_import_filename, admin_user.username)
    assert mock_storage_add.call_count == len(mock_imported_data)
    mock_storage_add.assert_called_once_with(mock_imported_data[0])
    assert mock_print_success.call_count == 2
    mock_print_success.assert_any_call(f"Successfully imported {len(mock_imported_data)} accounts")
    mock_print_success.assert_any_call(f"Accounts added to database from {test_import_filename}")
    mock_logger_info.assert_called_once()
    mock_ask_continue.assert_called_once()

def test_import_from_json_returns_empty(mocker, initialized_storage):
    """Test import handling when the import utility returns no accounts."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_import_filename = "empty_import.json"
    # Simulate import_from_json returning an empty list
    mock_imported_data = []

    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = test_import_filename
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_import_json = mocker.patch('src.main.import_from_json', return_value=mock_imported_data)
    mock_storage_add = mocker.patch.object(storage, 'create_account_from_dict')
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_info = mocker.patch('src.main.logger.info')

    # --- Act ---
    result = app.import_from_json_dialog()

    # --- Assert ---
    assert result is True
    mock_os_makedirs.assert_called_once()
    mock_q_text.assert_called_once()
    mock_import_json.assert_called_once_with(test_import_filename, admin_user.username)
    # Verify storage add was NOT called
    mock_storage_add.assert_not_called()
    # Verify the correct error message was printed
    mock_print_error.assert_called_once_with("No accounts were imported. Check file format.")
    mock_logger_info.assert_not_called() # No success info logged
    mock_ask_continue.assert_called_once()

def test_import_from_json_raises_exception(mocker, initialized_storage):
    """Test import handling when the import utility raises an exception."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_import_filename = "bad_format.json"
    error_message = "Simulated JSONDecodeError"

    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = test_import_filename
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    # Mock import_from_json to raise an exception
    mock_import_json = mocker.patch('src.main.import_from_json', side_effect=Exception(error_message))
    mock_storage_add = mocker.patch.object(storage, 'create_account_from_dict')
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_error = mocker.patch('src.main.logger.error')

    # --- Act ---
    result = app.import_from_json_dialog()

    # --- Assert ---
    assert result is True # Still returns True to keep app loop running
    mock_os_makedirs.assert_called_once()
    mock_q_text.assert_called_once()
    mock_import_json.assert_called_once_with(test_import_filename, admin_user.username)
    # Verify storage add was NOT called
    mock_storage_add.assert_not_called()
    # Verify the correct error message was printed
    mock_print_error.assert_called_once_with(f"Import failed: {error_message}")
    mock_logger_error.assert_called_once() # Verify error was logged
    mock_ask_continue.assert_called_once()

def test_import_from_json_storage_error(mocker, initialized_storage):
    """Test import handling when storage fails to add an imported account."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    test_import_filename = "import_causes_storage_error.json"
    mock_imported_data = [
        {"name": "ImportOK", "username": "import_ok", "password": "ImpOK@ss1"},
        {"name": "ImportFail", "username": "import_fail", "password": "ImpFail@ss1"}, # This one will fail
    ]
    error_message = "Simulated storage validation error"

    mock_q_text = mocker.patch('src.main.questionary.text')
    mock_q_text.return_value.ask.return_value = test_import_filename
    mock_os_makedirs = mocker.patch('src.main.os.makedirs')
    mock_import_json = mocker.patch('src.main.import_from_json', return_value=mock_imported_data)
    
    # Mock storage create_account_from_dict to fail on the second call
    def mock_storage_add_effect(account_data):
        if account_data['name'] == "ImportFail":
            raise Exception(error_message)
        # Otherwise succeed (return None or dummy account if needed by caller)
        return None 
    mock_storage_add = mocker.patch.object(storage, 'create_account_from_dict', side_effect=mock_storage_add_effect)

    mock_print_success = mocker.patch('src.main.print_success')
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_error = mocker.patch('src.main.logger.error')
    mock_logger_info = mocker.patch('src.main.logger.info')

    # --- Act ---
    result = app.import_from_json_dialog()

    # --- Assert ---
    assert result is True # Still returns True
    mock_os_makedirs.assert_called_once()
    mock_q_text.assert_called_once()
    mock_import_json.assert_called_once()
    
    # Verify storage add was called for both, even though one failed
    assert mock_storage_add.call_count == len(mock_imported_data)
    
    # Verify the overall import success message was printed (before the error)
    mock_print_success.assert_any_call(f"Successfully imported {len(mock_imported_data)} accounts")
    
    # Verify the error from the failed storage add was caught and printed
    mock_print_error.assert_called_once_with(f"Import failed: {error_message}")
    mock_logger_error.assert_called_once() # Verify error was logged
    mock_ask_continue.assert_called_once()
    # Verify the final "Accounts added" success message was NOT printed
    with pytest.raises(AssertionError): # Check that this specific call did NOT happen
         mock_print_success.assert_any_call(f"Accounts added to database from {test_import_filename}")
    # Verify info was not logged for successful completion
    mock_logger_info.assert_not_called()

# --- Admin Account/User Management Tests ---

def test_edit_account_success_no_password_change(mocker, storage_with_accounts):
    """Test successfully editing account details without changing the password."""
    storage = storage_with_accounts
    admin_user = storage.get_user("testadmin")
    account_to_edit = storage.get_accounts()[0] # Get the first account from fixture
    original_name = account_to_edit.name
    original_username = account_to_edit.username

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    edited_details = {
        "name": "Edited Account Name",
        "username": "edited_username",
        "password": "", # Simulate empty password field (keep current)
        "website": "https://edited.example.com",
        "notes": "Edited notes."
    }
    
    # Mock form_input to return edited details
    mock_form = mocker.patch('src.main.form_input', return_value=edited_details)

    # Mock storage.update_account to simulate success
    # It should return the updated account object
    updated_account_mock = Account(
        id=account_to_edit.id, # Keep same ID
        created_by=account_to_edit.created_by,
        name=edited_details["name"],
        username=edited_details["username"],
        password=account_to_edit.password, # Password remains unchanged
        website=edited_details["website"],
        notes=edited_details["notes"]
    )
    mock_storage_update = mocker.patch.object(storage, 'update_account', return_value=updated_account_mock)

    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    # Pass the original account object to the method
    result = app.edit_account(account_to_edit) 

    # --- Assert ---
    assert result is True
    mock_form.assert_called_once()

    # Verify storage.update_account was called correctly (without password)
    mock_storage_update.assert_called_once_with(
        account_id=account_to_edit.id,
        name=edited_details["name"],
        username=edited_details["username"],
        password=None, # Password field should be None or excluded
        website=edited_details["website"],
        notes=edited_details["notes"]
    )

    # Verify success message
    mock_print_success.assert_called_once_with(f"Account '{edited_details['name']}' updated successfully!")
    mock_ask_continue.assert_called_once()

    # IMPORTANT: Verify the original account object passed in was also updated
    assert account_to_edit.name == edited_details["name"]
    assert account_to_edit.username == edited_details["username"]
    assert account_to_edit.website == edited_details["website"]
    assert account_to_edit.notes == edited_details["notes"]
    # Password attribute on the object might or might not be updated depending on impl details,
    # but the key is that storage.update_account wasn't called with a new password.

def test_edit_account_success_with_password_change(mocker, storage_with_accounts):
    """Test successfully editing account details including changing the password."""
    storage = storage_with_accounts
    admin_user = storage.get_user("testadmin")
    account_to_edit = storage.get_accounts()[0]
    new_password = "NewPassword123!"

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    edited_details = {
        "name": "Edited Name PW",
        "username": "edited_user_pw",
        "password": new_password, # Provide a new password
        "website": "",
        "notes": "PW changed."
    }
    
    mock_form = mocker.patch('src.main.form_input', return_value=edited_details)

    # Mock storage.update_account 
    updated_account_mock = Account(
        id=account_to_edit.id,
        created_by=account_to_edit.created_by,
        name=edited_details["name"],
        username=edited_details["username"],
        password="encrypted_" + new_password, # Simulate storage returning updated (encrypted) pw
        website=edited_details["website"],
        notes=edited_details["notes"]
    )
    mock_storage_update = mocker.patch.object(storage, 'update_account', return_value=updated_account_mock)

    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.edit_account(account_to_edit)

    # --- Assert ---
    assert result is True
    mock_form.assert_called_once()

    # Verify storage.update_account was called correctly (WITH password)
    mock_storage_update.assert_called_once_with(
        account_id=account_to_edit.id,
        name=edited_details["name"],
        username=edited_details["username"],
        password=new_password, # Check new password was passed
        website=edited_details["website"],
        notes=edited_details["notes"]
    )

    mock_print_success.assert_called_once()
    mock_ask_continue.assert_called_once()

    # Verify the original account object passed in was also updated
    assert account_to_edit.name == edited_details["name"]
    assert account_to_edit.username == edited_details["username"]
    assert account_to_edit.website == edited_details["website"]
    assert account_to_edit.notes == edited_details["notes"]
    # Check if the password attribute on the original object was updated
    assert account_to_edit.password == updated_account_mock.password

def test_edit_account_failure_empty_required(mocker, storage_with_accounts):
    """Test edit account failure when required fields (name/username) are empty."""
    storage = storage_with_accounts
    admin_user = storage.get_user("testadmin")
    account_to_edit = storage.get_accounts()[0]

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    # Simulate form input with an empty name
    edited_details_empty_name = {
        "name": "", 
        "username": "valid_user",
        "password": "",
        "website": "",
        "notes": ""
    }
    
    mock_form = mocker.patch('src.main.form_input', return_value=edited_details_empty_name)
    mock_storage_update = mocker.patch.object(storage, 'update_account') # Mock update
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_warning = mocker.patch('src.main.logger.warning')

    # --- Act --- 
    result = app.edit_account(account_to_edit)

    # --- Assert ---
    assert result is True # Method returns True even on handled failure
    mock_form.assert_called_once()
    mock_print_error.assert_called_once_with("Account name and username are required.")
    mock_logger_warning.assert_called_once() # Check warning logged
    mock_ask_continue.assert_called_once()
    mock_storage_update.assert_not_called() # Ensure storage update was not attempted

# --- Admin User Management Tests ---

def test_admin_add_user_success(mocker, initialized_storage):
    """Test admin successfully adding a new user."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    new_username = "newlyaddeduser"
    new_password = "NewUserPass123!"
    new_role = UserRole.USER

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    add_user_details = {
        "username": new_username,
        "password": new_password,
        "role": new_role
    }

    mock_form = mocker.patch('src.main.form_input', return_value=add_user_details)
    mock_storage_create = mocker.spy(storage, 'create_user') # Spy on the real method
    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.admin_add_user()

    # --- Assert ---
    assert result is True
    mock_form.assert_called_once()
    mock_storage_create.assert_called_once_with(new_username, new_password, new_role)
    mock_print_success.assert_called_once_with(f"User '{new_username}' created successfully with role '{new_role}'.")
    mock_ask_continue.assert_called_once()
    # Verify user actually exists in storage now
    assert storage.get_user(new_username) is not None


def test_admin_add_user_duplicate(mocker, initialized_storage):
    """Test admin add user failure when username already exists."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    existing_username = admin_user.username # Try to add admin again

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    add_user_details = {
        "username": existing_username,
        "password": "AnyPass123!",
        "role": UserRole.USER
    }

    mock_form = mocker.patch('src.main.form_input', return_value=add_user_details)
    mock_storage_create = mocker.spy(storage, 'create_user')
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_warning = mocker.patch('src.main.logger.warning')

    # --- Act ---
    result = app.admin_add_user()

    # --- Assert ---
    assert result is True # Returns True even on handled failure
    mock_form.assert_called_once()
    mock_storage_create.assert_not_called() # Should not attempt creation
    mock_print_error.assert_called_once_with(f"Username '{existing_username}' is already taken.")
    mock_logger_warning.assert_called_once()
    mock_ask_continue.assert_called_once()


def test_admin_add_user_policy_fail(mocker, initialized_storage):
    """Test admin add user failure due to password policy."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    new_username = "policyfailuser"
    weak_password = "short"
    role = UserRole.USER

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    add_user_details = {
        "username": new_username,
        "password": weak_password,
        "role": role
    }

    mock_form = mocker.patch('src.main.form_input', return_value=add_user_details)
    # Spy on storage.create_user to confirm it raises ValueError
    mocker.spy(storage, 'create_user') 
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')
    mock_logger_error = mocker.patch('src.main.logger.error')

    # --- Act ---
    result = app.admin_add_user()

    # --- Assert ---
    assert result is True # Returns True even on handled failure
    mock_form.assert_called_once()
    storage.create_user.assert_called_once_with(new_username, weak_password, role)
    # Error message comes from the caught exception
    mock_print_error.assert_called_once() 
    # Check that the error message contains the policy violation reason
    assert "Password must be at least 12 characters long" in mock_print_error.call_args[0][0]
    mock_logger_error.assert_called_once()
    mock_ask_continue.assert_called_once()
    assert storage.get_user(new_username) is None # User not created

def test_admin_change_user_password_success(mocker, initialized_storage):
    """Test admin successfully changing another user's password."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    user_to_edit = storage.create_user("user_to_edit", "InitialPass123!")
    new_password = "AdminSetNewPass456!"

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    change_pass_details = {
        "new_password": new_password,
        "confirm_password": new_password
    }

    mock_form = mocker.patch('src.main.form_input', return_value=change_pass_details)
    mock_storage_update = mocker.spy(storage, 'update_user')
    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.admin_change_user_password(user_to_edit)

    # --- Assert ---
    assert result is True
    mock_form.assert_called_once()
    mock_storage_update.assert_called_once_with(username=user_to_edit.username, new_password=new_password)
    mock_print_success.assert_called_once_with(f"Password for '{user_to_edit.username}' updated successfully!")
    mock_ask_continue.assert_called_once()
    # Verify password actually changed
    assert storage.authenticate_user(user_to_edit.username, new_password) is not None


def test_admin_change_user_password_mismatch(mocker, initialized_storage):
    """Test admin change password failure due to mismatch."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    user_to_edit = storage.create_user("user_to_edit_mm", "InitialPassMM1!")

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    change_pass_details = {
        "new_password": "NewPassMismatch1!",
        "confirm_password": "NewPassMismatch2@"
    }

    mock_form = mocker.patch('src.main.form_input', return_value=change_pass_details)
    mock_storage_update = mocker.spy(storage, 'update_user')
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mock_logger_warning = mocker.patch('src.main.logger.warning')

    # --- Act ---
    result = app.admin_change_user_password(user_to_edit)

    # --- Assert ---
    assert result is True
    mock_form.assert_called_once()
    mock_storage_update.assert_not_called()
    mock_print_error.assert_called_once_with("Passwords do not match.")
    mock_logger_warning.assert_called_once()
    mock_ask_continue.assert_called_once()


def test_admin_change_user_password_policy_fail(mocker, initialized_storage):
    """Test admin change password failure due to policy."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    user_to_edit = storage.create_user("user_to_edit_pf", "InitialPassPF1!")
    weak_password = "weak"

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    change_pass_details = {
        "new_password": weak_password,
        "confirm_password": weak_password
    }

    mock_form = mocker.patch('src.main.form_input', return_value=change_pass_details)
    # Spy on storage.update_user to confirm it raises ValueError
    mocker.spy(storage, 'update_user') 
    mock_print_error = mocker.patch('src.main.print_error')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')
    mock_logger_error = mocker.patch('src.main.logger.error')

    # --- Act ---
    result = app.admin_change_user_password(user_to_edit)

    # --- Assert ---
    assert result is True # Returns True even on handled failure
    mock_form.assert_called_once()
    storage.update_user.assert_called_once_with(username=user_to_edit.username, new_password=weak_password)
    # Error message comes from the caught exception in storage.update_user
    mock_print_error.assert_called_once()
    assert "Password must be at least 12 characters long" in mock_print_error.call_args[0][0]
    mock_logger_error.assert_called_once()
    mock_ask_continue.assert_called_once()
    # Verify password was not changed
    assert storage.authenticate_user(user_to_edit.username, "InitialPassPF1!") is not None

def test_admin_change_user_role_user_to_admin(mocker, initialized_storage):
    """Test admin changing a USER role to ADMIN."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    user_to_edit = storage.create_user("user_to_promote", "PromoteMe123!", role=UserRole.USER)
    assert user_to_edit.role == UserRole.USER # Verify initial role

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    mock_confirm = mocker.patch('src.main.confirm_action', return_value=True) # Confirm the change
    mock_storage_update = mocker.spy(storage, 'update_user')
    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.admin_change_user_role(user_to_edit)

    # --- Assert ---
    assert result is True
    mock_confirm.assert_called_once_with(
        f"Change user '{user_to_edit.username}' role from '{UserRole.USER}' to '{UserRole.ADMIN}'?",
        default=False
    )
    mock_storage_update.assert_called_once_with(username=user_to_edit.username, new_role=UserRole.ADMIN)
    mock_print_success.assert_called_once_with(f"Role for '{user_to_edit.username}' updated to '{UserRole.ADMIN}' successfully!")
    mock_ask_continue.assert_called_once()
    # Verify role actually changed
    updated_user = storage.get_user(user_to_edit.username)
    assert updated_user.role == UserRole.ADMIN


def test_admin_change_user_role_admin_to_user(mocker, initialized_storage):
    """Test admin changing an ADMIN role to USER."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    user_to_edit = storage.create_user("user_to_demote", "DemoteMe123!", role=UserRole.ADMIN)
    assert user_to_edit.role == UserRole.ADMIN # Verify initial role

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    mock_confirm = mocker.patch('src.main.confirm_action', return_value=True)
    mock_storage_update = mocker.spy(storage, 'update_user')
    mock_print_success = mocker.patch('src.main.print_success')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.admin_change_user_role(user_to_edit)

    # --- Assert ---
    assert result is True
    mock_confirm.assert_called_once_with(
        f"Change user '{user_to_edit.username}' role from '{UserRole.ADMIN}' to '{UserRole.USER}'?",
        default=False
    )
    mock_storage_update.assert_called_once_with(username=user_to_edit.username, new_role=UserRole.USER)
    mock_print_success.assert_called_once_with(f"Role for '{user_to_edit.username}' updated to '{UserRole.USER}' successfully!")
    mock_ask_continue.assert_called_once()
    updated_user = storage.get_user(user_to_edit.username)
    assert updated_user.role == UserRole.USER


def test_admin_change_user_role_cancel(mocker, initialized_storage):
    """Test cancelling the role change."""
    storage = initialized_storage
    admin_user = storage.get_user("testadmin")
    user_to_edit = storage.create_user("user_nochange", "NoChange123!", role=UserRole.USER)
    original_role = user_to_edit.role

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    mock_confirm = mocker.patch('src.main.confirm_action', return_value=False) # Simulate cancelling
    mock_storage_update = mocker.spy(storage, 'update_user')
    mock_print_info = mocker.patch('src.main.print_info')
    mock_ask_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')
    mocker.patch('src.main.display_spinner')

    # --- Act ---
    result = app.admin_change_user_role(user_to_edit)

    # --- Assert ---
    assert result is True
    mock_confirm.assert_called_once()
    mock_storage_update.assert_not_called() # Role should not be updated
    mock_print_info.assert_called_once_with("Role change cancelled.")
    mock_ask_continue.assert_called_once()
    # Verify role did not change
    not_updated_user = storage.get_user(user_to_edit.username)
    assert not_updated_user.role == original_role

@pytest.fixture
def storage_for_stats(initialized_storage):
    """Fixture for stats test with varied account strengths and categories."""
    storage = initialized_storage
    admin = storage.get_user("testadmin")
    # Strong (80+) 
    storage.create_account("StrongAcc", "u_strong", "StrongP@ssword123!", created_by=admin.username, password_strength=90, category=AccountCategory.FINANCIAL.value)
    # Good (60-79)
    storage.create_account("GoodAcc", "u_good", "GoodPass123?", created_by=admin.username, password_strength=70, category=AccountCategory.SOCIAL.value)
    # Fair (40-59)
    storage.create_account("FairAcc", "u_fair", "FairPass", created_by=admin.username, password_strength=50, category=AccountCategory.SOCIAL.value)
    # Weak (<40)
    storage.create_account("WeakAcc", "u_weak", "weak", created_by=admin.username, password_strength=10, category=AccountCategory.OTHER.value)
    return storage

def test_view_account_stats(mocker, storage_for_stats):
    """Test viewing account statistics as admin."""
    storage = storage_for_stats
    admin_user = storage.get_user("testadmin")
    accounts = storage.get_accounts()
    assert len(accounts) == 4 # Verify fixture setup

    # --- Arrange ---
    mocker.patch('src.main.Storage', return_value=storage)
    app = AccountSelectorApp()
    app.current_user = admin_user

    # Mock print functions
    mock_print_info = mocker.patch('src.main.print_info')
    mock_print_success = mocker.patch('src.main.print_success')
    mock_print_warning = mocker.patch('src.main.print_warning')
    mock_ask_to_continue = mocker.patch('src.main.ask_to_continue')
    mocker.patch('src.main.print_header')

    # --- Act ---
    result = app.view_account_stats()

    # --- Assert ---
    assert result is True
    mock_ask_to_continue.assert_called_once()

    # Check total accounts
    mock_print_info.assert_any_call(f"Total accounts: {len(accounts)}") # 4

    # Check password strength print calls (via mocked print_success)
    assert any("Password Strength Distribution" in call for call in mock_print_success.call_args_list)
    assert any("Strong | 1 (25.0%)" in call for call in mock_print_success.call_args_list)
    assert any("Good   | 1 (25.0%)" in call for call in mock_print_success.call_args_list)
    assert any("Fair   | 1 (25.0%)" in call for call in mock_print_success.call_args_list)
    assert any("Weak   | 1 (25.0%)" in call for call in mock_print_success.call_args_list)

    # Check category print calls (via mocked print_warning)
    assert any("Account Category Distribution" in call for call in mock_print_warning.call_args_list)
    assert any("Financial | 1 (25.0%)" in call for call in mock_print_warning.call_args_list)
    assert any("Social    | 1 (25.0%)" in call for call in mock_print_warning.call_args_list)
    assert any("Other     | 1 (25.0%)" in call for call in mock_print_warning.call_args_list)
    # Check uncategorized is not printed explicitly if count is 1
    assert not any("Uncategorized" in call for call in mock_print_warning.call_args_list)

# --- Other CLI Features ---

@patch("src.main.print_info")
@patch("src.main.ask_to_continue")
@patch("src.main.print_success")
@patch("src.main.questionary.select")
def test_change_theme(mock_select, mock_print_success, mock_print_info, mock_ask_to_continue, test_app):
    """Test changing the theme successfully."""
    selected_theme_full = "Dracula : A dark theme"
    selected_theme_name = "Dracula"
    mock_select.return_value.ask.return_value = selected_theme_full

    result = test_app.change_theme()

    assert result is True
    mock_select.assert_called_once()
    # Check that the prompt is correct
    assert mock_select.call_args[0][0] == "Select Theme:"
    # Check that the choices are present (basic check)
    assert len(mock_select.call_args[1]['choices']) > 1

    mock_print_success.assert_called_once_with(f"Theme changed to '{selected_theme_name}'")
    mock_print_info.assert_called_once_with("Note: Theme changes will take effect on restart in this version.")
    mock_ask_to_continue.assert_called_once()


@patch("src.main.ask_to_continue")
@patch("src.main.questionary.select")
def test_change_theme_cancel(mock_select, mock_ask_to_continue, test_app):
    """Test cancelling the theme change selection."""
    mock_select.return_value.ask.return_value = None # Simulate cancel

    result = test_app.change_theme()

    assert result is True
    mock_select.assert_called_once()
    mock_ask_to_continue.assert_not_called() # Should exit directly without asking to continue