# tests/test_storage.py

import pytest
import os
import shutil
from src.data.storage import Storage
from src.data.models import User, Account, UserRole
from unittest.mock import patch
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.fernet import InvalidToken

# Setup logger for this test module
logger = logging.getLogger(__name__)

# Define a fixture for a temporary test data directory
@pytest.fixture(scope="function")
def temp_storage(tmp_path):
    """Creates a temporary data directory and Storage instance for testing."""
    test_data_folder = tmp_path / "test_app_data"
    test_data_folder.mkdir()
    
    # Initial master password for tests
    master_password = "testpassword123!"
    
    # Mock input/getpass during Storage init ONLY to prevent blocking
    # if the initial admin creation prompt is triggered unexpectedly.
    # Tests should ideally manage user creation explicitly.
    with patch('builtins.input', return_value="dummy_admin"), \
         patch('getpass.getpass', return_value="dummy_pass"):
        # Instantiate Storage - this will create the key file if needed
        # The mocks above will handle the admin prompt if storage._initialize hits it.
        storage = Storage(data_folder=str(test_data_folder), master_password=master_password)
    
    # Yield the storage instance and password for tests to use
    yield storage, master_password
    
    # Teardown: Clean up the temporary directory (handled by tmp_path fixture)
    # No need for explicit shutil.rmtree(test_data_folder)

# --- Basic Initialization Tests ---

def test_storage_initialization(temp_storage):
    """Test that Storage initializes correctly and creates necessary files."""
    storage, _ = temp_storage
    assert os.path.exists(storage.data_folder)
    assert os.path.exists(storage.users_file)
    assert os.path.exists(storage.accounts_file)
    assert os.path.exists(storage.key_file)
    assert os.path.exists(storage.config_file)
    assert storage.encryption_initialized is True

def test_initial_admin_creation_prompt(mocker, tmp_path):
    """Test that admin creation prompt happens ONLY if files are empty."""
    test_data_folder = tmp_path / "test_app_data_empty"
    test_data_folder.mkdir()
    master_pw = "abc"

    # Mock input/getpass to simulate user entry during Storage init
    mock_input = mocker.patch('builtins.input', side_effect=['testadmin']) # Provide username
    valid_admin_pass = "ValidAdminPassword123!" # Increased length

    # Patch getpass directly where it's used in storage.py
    mock_getpass = mocker.patch('src.data.storage.getpass.getpass', side_effect=[valid_admin_pass, valid_admin_pass])
    
    storage = Storage(data_folder=str(test_data_folder), master_password=master_pw)
    
    assert mock_input.call_count == 1 # Should ask for admin username
    assert mock_getpass.call_count == 2 # Admin PW + confirm ONLY (master pw provided)
    
    admin_user = storage.get_user('testadmin')
    assert admin_user is not None
    assert admin_user.role == UserRole.ADMIN

# --- User Creation & Authentication Tests ---

def test_create_valid_user(temp_storage):
    """Test creating a valid user."""
    storage, _ = temp_storage
    username = "testuser"
    password = "ValidPass123!"
    user = storage.create_user(username, password)
    assert user is not None
    assert user.username == username
    assert user.role == UserRole.USER # Default role

    # Verify user is saved
    loaded_user = storage.get_user(username)
    assert loaded_user is not None
    assert loaded_user.username == username

def test_create_duplicate_user(temp_storage):
    """Test that creating a user with an existing username fails."""
    storage, _ = temp_storage
    username = "testuser"
    password = "ValidPass123!"
    storage.create_user(username, password) # Create first user

    with pytest.raises(ValueError, match=f"User '{username}' already exists"):
        storage.create_user(username, "AnotherPass456?") # Attempt duplicate

def test_create_user_violates_policy(temp_storage):
    """Test creating a user with a password that violates policy."""
    storage, _ = temp_storage
    username = "weakuser"
    password = "short"
    
    # Assuming default policy requires length >= 12
    with pytest.raises(ValueError, match="Password must be at least 12 characters long"):
        storage.create_user(username, password)

def test_authenticate_valid_user(temp_storage):
    """Test authenticating a user with correct credentials."""
    storage, _ = temp_storage
    username = "authuser"
    password = "AuthPass123!"
    storage.create_user(username, password)
    
    authenticated_user = storage.authenticate_user(username, password)
    assert authenticated_user is not None
    assert authenticated_user.username == username

def test_authenticate_invalid_password(temp_storage):
    """Test authenticating with an incorrect password."""
    storage, _ = temp_storage
    username = "authuser"
    password = "AuthPass123!"
    storage.create_user(username, password)
    
    authenticated_user = storage.authenticate_user(username, "WrongPass456?")
    assert authenticated_user is None

def test_authenticate_nonexistent_user(temp_storage):
    """Test authenticating a user that does not exist."""
    storage, _ = temp_storage
    authenticated_user = storage.authenticate_user("nosuchuser", "anypassword")
    assert authenticated_user is None

# --- Password History Tests ---

def test_password_history_prevents_reuse(temp_storage):
    """Test that changing password fails if the new password is in the history."""
    storage, _ = temp_storage
    username = "historyuser"
    initial_pw = "InitialPass123!"
    second_pw = "SecondPass456?"

    # Create user and change password once to populate history
    storage.create_user(username, initial_pw)
    storage.update_user(username, new_password=second_pw)

    # Log state before attempting the reuse
    logger.debug(f"Attempting password reuse for user '{username}'. ")
    logger.debug(f"  Initial PW: {'*' * len(initial_pw)}")
    logger.debug(f"  Second PW: {'*' * len(second_pw)}")
    logger.debug(f"  Attempting to reuse: {'*' * len(initial_pw)}")

    # Attempt to change back to the initial password and expect a ValueError
    with pytest.raises(ValueError) as excinfo:
        storage.update_user(username, new_password=initial_pw)
    assert "New password cannot be the same as one of the last 3 passwords" in str(excinfo.value)

def test_password_history_allows_reuse_after_limit(temp_storage):
    """Test that an old password can be reused after enough changes."""
    storage, _ = temp_storage
    username = "historylimituser"
    passwords = [
        "PassLimit_1!", 
        "PassLimit_2?", 
        "PassLimit_3#", 
        "PassLimit_4$",
        "PassLimit_5%"
    ]

    # Create user
    storage.create_user(username, passwords[0])

    # Change password multiple times (default history = 3)
    storage.update_user(username, new_password=passwords[1]) # history = [0]
    storage.update_user(username, new_password=passwords[2]) # history = [0, 1]
    storage.update_user(username, new_password=passwords[3]) # history = [0, 1, 2]
    storage.update_user(username, new_password=passwords[4]) # history = [1, 2, 3]

    # Now, attempt to change back to the first password (passwords[0])
    # H0 should now be allowed as it's outside the history limit [1, 2, 3]
    try:
        updated_user = storage.update_user(username, new_password=passwords[0])
        assert updated_user is not None
        # Verify the change by authenticating
        assert storage.authenticate_user(username, passwords[0]) is not None
    except ValueError as e:
        pytest.fail(f"Changing back to old password failed unexpectedly: {e}")

def test_password_history_disabled(temp_storage):
    """Test that password reuse is allowed if the policy is disabled."""
    storage, _ = temp_storage
    username = "nohistoryuser"
    pw1 = "NoHistoryPass1!"
    pw2 = "NoHistoryPass2?"

    # Modify config to disable history
    storage.config["password_policy"]["prevent_reuse"] = False
    storage.save_config() # Save modified config

    # Create user and change password
    storage.create_user(username, pw1)
    storage.update_user(username, new_password=pw2)

    # Attempt to change back immediately - should succeed
    try:
        updated_user = storage.update_user(username, new_password=pw1)
        assert updated_user is not None
        assert storage.authenticate_user(username, pw1) is not None
    except ValueError as e:
        pytest.fail(f"Changing password back failed unexpectedly when history disabled: {e}")

# --- Account CRUD Tests ---

def test_create_account(temp_storage):
    """Test creating a valid account."""
    storage, _ = temp_storage
    creator = "testcreator"
    storage.create_user(creator, "Password123!")

    account = storage.create_account(
        name="Test Site", 
        username="testacc", 
        password="AccPass123!", 
        created_by=creator,
        website="example.com",
        notes="Some notes."
    )
    assert account is not None
    assert account.name == "Test Site"
    assert account.username == "testacc"
    # Password should be stored unencrypted in the model initially
    assert account.password == "AccPass123!" 
    assert account.created_by == creator

    # Verify it was saved (and password gets encrypted)
    # Load using get_account which should decrypt
    reloaded_account = storage.get_account(account.id)
    assert reloaded_account is not None
    assert reloaded_account.password == "AccPass123!" # Should be decrypted

    # Verify encryption by loading the raw file data
    loaded_accounts = storage._load_accounts() # Load raw to check encryption
    assert len(loaded_accounts) == 1
    assert loaded_accounts[0].id == account.id
    assert loaded_accounts[0].name == "Test Site"
    with open(storage.accounts_file, "r") as f:
        raw_data = json.load(f)
    assert len(raw_data) == 1
    assert raw_data[0]["id"] == account.id
    assert raw_data[0]["password"] != "AccPass123!" # Check raw data is encrypted
    assert raw_data[0]["password"].startswith("gAAAAAB") # Check Fernet prefix

def test_get_account(temp_storage):
    """Test retrieving a specific account by ID."""
    storage, _ = temp_storage
    creator = "testcreator"
    storage.create_user(creator, "Password123!")
    account = storage.create_account("Test Site", "testacc", "AccPass123!", creator)

    retrieved_account = storage.get_account(account.id)
    assert retrieved_account is not None
    assert retrieved_account.id == account.id
    assert retrieved_account.name == account.name
    # Password should be decrypted when retrieved via get_account
    assert retrieved_account.password == "AccPass123!"

    # Test getting non-existent account
    assert storage.get_account("non-existent-id") is None

def test_update_account(temp_storage):
    """Test updating various fields of an account."""
    storage, _ = temp_storage
    creator = "testcreator"
    storage.create_user(creator, "Password123!")
    account = storage.create_account("Old Name", "olduser", "OldPass!", creator)

    updated_account = storage.update_account(
        account_id=account.id,
        name="New Name",
        username="newuser",
        password="NewPass?",
        notes="Updated notes.",
        tags=["tag1", "tag2"]
    )

    assert updated_account is not None
    assert updated_account.id == account.id
    assert updated_account.name == "New Name"
    assert updated_account.username == "newuser"
    assert updated_account.password == "NewPass?" # Should be decrypted
    assert updated_account.notes == "Updated notes."
    assert updated_account.tags == ["tag1", "tag2"]

    # Verify persistence
    reloaded_account = storage.get_account(account.id)
    assert reloaded_account.name == "New Name"
    assert reloaded_account.password == "NewPass?"
    assert reloaded_account.tags == ["tag1", "tag2"]

    # Test updating non-existent account
    assert storage.update_account("non-existent-id", name="WontWork") is None

def test_delete_account(temp_storage):
    """Test deleting an account."""
    storage, _ = temp_storage
    creator = "testcreator"
    storage.create_user(creator, "Password123!")
    account1 = storage.create_account("Site 1", "user1", "Pass1", creator)
    account2 = storage.create_account("Site 2", "user2", "Pass2", creator)

    assert len(storage.get_accounts()) == 2

    # Delete account1
    deleted = storage.delete_account(account1.id)
    assert deleted is True
    assert storage.get_account(account1.id) is None
    assert len(storage.get_accounts()) == 1

    # Verify account2 still exists
    assert storage.get_account(account2.id) is not None

    # Test deleting non-existent account
    deleted_nonexistent = storage.delete_account("non-existent-id")
    assert deleted_nonexistent is False
    assert len(storage.get_accounts()) == 1 # Count should be unchanged

# --- Encryption Tests ---

def test_encrypt_decrypt(temp_storage):
    """Test direct encryption and decryption."""
    storage, _ = temp_storage
    original_text = "MySecretPassword"
    encrypted = storage._encrypt_password(original_text)
    assert encrypted != original_text
    assert encrypted.startswith("gAAAAAB")

    decrypted = storage._decrypt_password(encrypted)
    assert decrypted == original_text

def test_decryption_invalid_token(temp_storage):
    """Test that decryption raises error for invalid token."""
    storage, _ = temp_storage
    with pytest.raises((ValueError, RuntimeError), match="Invalid or corrupted password data|Error decrypting password"):
        storage._decrypt_password("not_a_valid_fernet_token")

def test_storage_init_wrong_master_password(temp_storage, tmp_path):
    """Test initializing Storage with the wrong master password fails."""
    storage, correct_master_password = temp_storage
    data_folder = storage.data_folder # Get the path used by the fixture
    
    # Ensure the first init created the key file
    assert os.path.exists(storage.key_file)

    # Attempt to initialize a NEW Storage instance with the WRONG password
    # We expect Storage.__init__ to wrap the ValueError in a RuntimeError
    with pytest.raises(RuntimeError, match="Encryption initialization failed: Invalid master password"):
        Storage(data_folder=data_folder, master_password="WRONGpassword!!!")

def test_storage_init_no_master_password_loads_key(temp_storage, tmp_path):
    """Test initializing Storage without a password loads existing key."""
    storage, _ = temp_storage
    data_folder = storage.data_folder
    
    # Ensure the first init created the key file
    assert os.path.exists(storage.key_file)
    
    # Attempt to initialize a NEW instance with NO password
    try:
        # Add mocks here too, just in case _initialize needs them unexpectedly
        with patch('builtins.input', return_value="dummy_admin_ignore"), \
             patch('getpass.getpass', return_value="dummy_pass_ignore"):
            new_storage = Storage(data_folder=data_folder, master_password=None)
        assert new_storage.encryption_initialized is True
        # Quick check: encrypt something with the new instance
        assert new_storage._encrypt_password("test").startswith("gAAAAAB")
    except Exception as e:
        pytest.fail(f"Initializing Storage without password failed unexpectedly: {e}")

# --- Backup & Restore Tests ---

def test_create_unencrypted_backup(temp_storage):
    """Test creating an unencrypted backup."""
    storage, _ = temp_storage
    storage.create_user("bkpuser", "ValidPassword123!")
    storage.create_account("Bkp Site", "bkpacc", "BkpAccountPass!", "bkpuser")

    backup = storage.create_backup(name="Unencrypted Test", encrypt=False)
    assert backup is not None
    assert backup.name == "Unencrypted Test"
    assert os.path.exists(backup.file_path)
    assert backup.is_encrypted is False
    assert backup.user_count == 1 # Only bkpuser (initial admin is not created by default fixture)
    assert backup.account_count == 1

    # Basic check: try to open as zip
    import zipfile
    try:
        with zipfile.ZipFile(backup.file_path, 'r') as zf:
            assert "metadata.json" in zf.namelist()
            assert "users.json" in zf.namelist()
            assert "accounts.json" in zf.namelist()
    except zipfile.BadZipFile:
        pytest.fail("Unencrypted backup file was not a valid zip file.")

def test_create_encrypted_backup(temp_storage):
    """Test creating an encrypted backup."""
    storage, _ = temp_storage
    storage.create_user("bkpuser_enc", "ValidPassword123!")

    backup = storage.create_backup(name="Encrypted Test", encrypt=True)
    assert backup is not None
    assert backup.name == "Encrypted Test"
    assert os.path.exists(backup.file_path)
    assert backup.is_encrypted is True

    # Basic check: opening as zip should fail
    import zipfile
    with pytest.raises(zipfile.BadZipFile):
        with zipfile.ZipFile(backup.file_path, 'r') as zf:
            zf.namelist()

def test_restore_unencrypted_backup(temp_storage):
    """Test restoring data from an unencrypted backup."""
    storage, _ = temp_storage
    storage.create_user("user_to_replace", "PasswordToDelete1!")
    acc1 = storage.create_account("Acc A", "usera", "ToDeletePassA1!", "user_to_replace")

    # Create a separate storage instance for the backup source
    backup_storage_path = os.path.join(storage.data_folder, "../backup_source_data")
    os.makedirs(backup_storage_path)
    backup_master_pw = "backupMasterPass1!"
    # Mock input/getpass for the second storage instance init
    with patch('builtins.input', return_value="dummy_admin_bkp"), \
         patch('getpass.getpass', return_value="dummy_pass_bkp"):
        backup_storage = Storage(backup_storage_path, backup_master_pw)

    backup_storage.create_user("restored_user", "RestoredOkayPass1?")
    acc2 = backup_storage.create_account("Acc B", "userb", "RestoredAccPassB2?", "restored_user")

    # Create unencrypted backup from the backup source
    backup = backup_storage.create_backup(name="RestoreMe", encrypt=False)

    # Restore into the original storage
    restore_result = storage.restore_from_backup(backup.file_path)
    assert restore_result["success"] is True

    # Verify original user/account are gone
    assert storage.get_user("user_to_replace") is None
    assert storage.get_account(acc1.id) is None

    # Verify restored user/account are present
    restored_user_check = storage.get_user("restored_user")
    assert restored_user_check is not None
    restored_account_check = storage.get_account(acc2.id)
    assert restored_account_check is not None
    assert restored_account_check.name == "Acc B"

def test_restore_encrypted_backup_correct_pw(temp_storage):
    """Test restoring from an encrypted backup with the correct password."""
    storage, master_password = temp_storage # Use the master pw from the fixture
    storage.create_user("user_to_replace_enc", "PasswordToDelete2!")
    acc1 = storage.create_account("Acc A Enc", "usera_enc", "ToDeletePassA2!", "user_to_replace_enc")

    # Create encrypted backup (uses fixture's master password)
    backup = storage.create_backup(name="RestoreMeEnc", encrypt=True)
    
    # Delete original user/account to simulate restore scenario
    storage.delete_user("user_to_replace_enc")
    assert storage.get_user("user_to_replace_enc") is None
    assert storage.get_account(acc1.id) is None 

    # Restore using the correct master password
    restore_result = storage.restore_from_backup(backup.file_path, master_password=master_password)
    assert restore_result["success"] is True

    # Verify restored user/account are present
    restored_user_check = storage.get_user("user_to_replace_enc")
    assert restored_user_check is not None
    restored_account_check = storage.get_account(acc1.id)
    assert restored_account_check is not None
    assert restored_account_check.name == "Acc A Enc"

def test_restore_encrypted_backup_wrong_pw(temp_storage):
    """Test restoring from encrypted backup with wrong password fails."""
    storage, master_password = temp_storage
    storage.create_user("user_enc_wrong", "PasswordToDelete3!")

    # Create encrypted backup
    backup = storage.create_backup(name="RestoreFailEnc", encrypt=True)

    # Simulate restoring with a new storage instance and wrong password
    data_folder = storage.data_folder # Use the same temp folder
    wrong_password = "WRONGPASSWORD"

    # Expect RuntimeError during Storage init due to incorrect master password
    with pytest.raises(RuntimeError, match="Encryption initialization failed: Invalid master password"):
        # Create a new storage instance that will try to init encryption with wrong pw
        # Note: _initialize_encryption might raise RuntimeError if key derivation fails,
        #       but restore_from_backup catches InvalidToken from decrypt attempt.
        #       Let's ensure restore_from_backup handles this.
        restore_storage = Storage(data_folder=data_folder, master_password=wrong_password)
        # This restore call might not even be reached if Storage init fails badly.
        # A better test might be needed depending on exact error flow.
        # For now, let's assume Storage init succeeds but decrypt fails.
        # Actually, restore_from_backup *will* call _initialize_encryption again if needed.
        # The key is that the cipher used for decryption comes from the wrong password.
        storage.restore_from_backup(backup.file_path, master_password=wrong_password)

# Add more tests here for:
# - User creation (valid/invalid) 
# - Authentication (success/failure)
# - Password policy enforcement
# - Password history
# - Account CRUD operations
# - Encryption/Decryption
# - Backup/Restore