"""
Unit tests specifically for the backup and restore functionality of the Storage class.
These tests focus on comprehensive testing of backup creation, restoration, 
auto-backup functionality, and edge cases.
"""

import pytest
import os
import shutil
import json
import zipfile
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import logging
from cryptography.fernet import InvalidToken

from src.data.storage import Storage
from src.data.models import User, Account, UserRole, Backup

# Setup logger for this test module
logger = logging.getLogger(__name__)

# Fixtures

@pytest.fixture(scope="function")
def temp_storage(tmp_path):
    """Creates a temporary data directory and Storage instance for testing."""
    test_data_folder = tmp_path / "test_app_data"
    test_data_folder.mkdir()
    
    # Initial master password for tests
    master_password = "testpassword123!"
    
    # Mock input/getpass during Storage init to prevent blocking
    with patch('builtins.input', return_value="backup_admin"), \
         patch('getpass.getpass', return_value="Backup_Admin_123!"):
        # Instantiate Storage
        storage = Storage(data_folder=str(test_data_folder), master_password=master_password)
    
    # Add some test data for backup/restore tests
    storage.create_user("backup_user", "BackupUserPass123!")
    storage.create_account(
        name="Test Account 1",
        username="testuser1",
        password="TestPassword123!",
        created_by="backup_user",
        website="https://test1.example.com",
        notes="Test account 1 notes",
        tags=["test", "backup"]
    )
    
    storage.create_account(
        name="Test Account 2",
        username="testuser2",
        password="TestPassword456!",
        created_by="backup_user",
        website="https://test2.example.com",
        notes="Test account 2 notes",
        tags=["test", "important"]
    )
    
    # Yield the storage instance and password for tests to use
    yield storage, master_password, str(test_data_folder)

# Test Functions

def test_auto_backup_functionality(temp_storage):
    """Test that auto_backup creates a backup when needed."""
    storage, _, _ = temp_storage
    
    # Modify the config to enable auto backup with a 0-day interval to force it
    storage.config["backup"]["auto_backup"] = True
    storage.config["backup"]["backup_interval_days"] = 0
    storage.config["backup"]["last_backup"] = None
    
    # Call auto_backup
    backup = storage.auto_backup()
    
    # Verify backup was created
    assert backup is not None
    assert isinstance(backup, Backup)
    assert os.path.exists(backup.file_path)
    assert backup.is_encrypted is True  # Default is encrypted
    
    # Verify last_backup was updated in config
    assert storage.config["backup"]["last_backup"] is not None

def test_auto_backup_skips_when_recent(temp_storage):
    """Test that auto_backup skips when a recent backup exists."""
    storage, _, _ = temp_storage
    
    # Set a recent last_backup date
    now = datetime.now()
    storage.config["backup"]["auto_backup"] = True
    storage.config["backup"]["backup_interval_days"] = 7
    storage.config["backup"]["last_backup"] = now.isoformat()
    
    # Call auto_backup
    backup = storage.auto_backup()
    
    # Verify no backup was created
    assert backup is None

def test_auto_backup_with_rotation(temp_storage):
    """Test backup rotation when max_backups is reached."""
    storage, _, _ = temp_storage
    
    # Set up config
    storage.config["backup"]["auto_backup"] = True
    storage.config["backup"]["backup_interval_days"] = 0
    storage.config["backup"]["max_backups"] = 3
    
    # Create backup dir
    backup_dir = os.path.join(storage.data_folder, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    
    # Create 3 dummy backup files with timestamps
    dummy_backup_paths = []
    for i in range(3):
        # Create dummy backup files with clear timestamps for ordering
        timestamp = datetime.now() - timedelta(days=i)
        dummy_name = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_dummy{i}.zip"
        dummy_path = os.path.join(backup_dir, dummy_name)
        
        # Create an empty zip file as a dummy backup
        with zipfile.ZipFile(dummy_path, 'w') as _:
            pass
        
        dummy_backup_paths.append(dummy_path)
    
    # Wait a moment to ensure timestamp difference
    import time
    time.sleep(0.1)
    
    # Call auto_backup to create a new backup
    backup = storage.auto_backup()
    
    # Verify backup was created
    assert backup is not None
    
    # Verify we deleted at least one old backup (oldest)
    assert not os.path.exists(dummy_backup_paths[2])
    
    # Count total backups
    backup_files = [f for f in os.listdir(backup_dir) if f.endswith('.zip')]
    assert len(backup_files) <= 3

def test_list_backups(temp_storage):
    """Test listing backups."""
    storage, _, _ = temp_storage
    
    # Create some test backups
    backup1 = storage.create_backup(name="Backup 1", encrypt=True)
    backup2 = storage.create_backup(name="Backup 2", encrypt=False)
    
    # List backups
    backups = storage.list_backups()
    
    # Verify backups are listed
    assert len(backups) >= 2
    
    # Verify backups are sorted by creation time (newest first)
    assert backups[0].created_at >= backups[1].created_at
    
    # Verify backup properties
    assert any(b.name == "Backup 1" for b in backups)
    assert any(b.name == "Backup 2" for b in backups)
    
    # Verify encryption status
    encrypted_backups = [b for b in backups if b.is_encrypted]
    unencrypted_backups = [b for b in backups if not b.is_encrypted]
    assert len(encrypted_backups) >= 1
    assert len(unencrypted_backups) >= 1

def test_backup_metadata_integrity(temp_storage):
    """Test that backup metadata is correctly stored and can be extracted."""
    storage, _, _ = temp_storage
    
    # Create a backup
    backup_name = "Metadata Test Backup"
    backup = storage.create_backup(name=backup_name, encrypt=False)
    
    # Verify extracted metadata from the list_backups function
    backups = storage.list_backups()
    found_backup = next((b for b in backups if b.name == backup_name), None)
    
    assert found_backup is not None
    assert found_backup.id == backup.id
    assert found_backup.user_count == backup.user_count
    assert found_backup.account_count == backup.account_count
    assert found_backup.is_encrypted == backup.is_encrypted
    
    # Extract and verify metadata directly
    with zipfile.ZipFile(backup.file_path, 'r') as zf:
        assert 'metadata.json' in zf.namelist()
        with zf.open('metadata.json') as f:
            metadata = json.load(f)
            assert metadata['name'] == backup_name
            assert metadata['is_encrypted'] == False
            assert metadata['user_count'] >= 1
            assert metadata['account_count'] >= 2

def test_backup_restore_with_config_merge(temp_storage):
    """Test that restoring a backup properly merges configuration settings."""
    storage, master_password, _ = temp_storage
    
    # Modify current config
    storage.config["password_policy"]["min_length"] = 14
    storage.config["backup"]["max_backups"] = 10
    storage.save_config()
    
    # Create a backup
    backup = storage.create_backup(name="Config Test", encrypt=True)
    
    # Create a new storage with different config settings
    with tempfile.TemporaryDirectory() as tmp_dir:
        new_storage = Storage(data_folder=tmp_dir, master_password=master_password)
        
        # Modify the config to be different
        new_storage.config["password_policy"]["min_length"] = 8
        new_storage.config["backup"]["max_backups"] = 5
        new_storage.config["custom_setting"] = "new_value"  # Setting not in original
        new_storage.save_config()
        
        # Restore the backup
        restore_result = new_storage.restore_from_backup(backup.file_path, master_password=master_password)
        assert restore_result["success"] is True
        
        # Check if config was properly merged
        # Original values should be preserved if they exist in both configs
        assert new_storage.config["password_policy"]["min_length"] == 14
        assert new_storage.config["backup"]["max_backups"] == 10
        
        # New values should be preserved if they only exist in the new config
        assert "custom_setting" in new_storage.config
        assert new_storage.config["custom_setting"] == "new_value"

def test_restore_nonexistent_backup(temp_storage):
    """Test that restoring a nonexistent backup file raises FileNotFoundError."""
    storage, _, _ = temp_storage
    
    with pytest.raises(FileNotFoundError):
        storage.restore_from_backup("nonexistent_backup.zip")

def test_create_backup_with_no_accounts(temp_storage):
    """Test creating a backup when no accounts exist."""
    storage, _, _ = temp_storage
    
    # Delete all accounts
    accounts = storage.get_accounts()
    for account in accounts:
        storage.delete_account(account.id)
    
    # Create backup
    backup = storage.create_backup(name="No Accounts Backup")
    
    # Verify backup was created
    assert backup is not None
    assert backup.account_count == 0
    assert backup.user_count >= 1  # Should still have at least one user

def test_restore_corrupted_backup(temp_storage):
    """Test restoring from a corrupted backup file."""
    storage, _, _ = temp_storage
    
    # Create a valid backup
    backup = storage.create_backup(name="Corrupted Test", encrypt=False)
    
    # Corrupt the backup file by writing random data to it
    with open(backup.file_path, 'wb') as f:
        f.write(b'This is not a valid zip file')
    
    # Attempt to restore from corrupted backup
    with pytest.raises(Exception):  # Should raise some kind of exception
        storage.restore_from_backup(backup.file_path)

def test_backup_file_permissions(temp_storage):
    """Test that backup files have appropriate permissions."""
    storage, _, _ = temp_storage
    
    # Create a backup
    backup = storage.create_backup(name="Permissions Test")
    
    # Check that the backup file exists and is readable
    assert os.path.exists(backup.file_path)
    assert os.access(backup.file_path, os.R_OK)
    
    # On Unix-like systems, check that the file is not world-readable
    # (skip this check on Windows)
    import sys
    if sys.platform != "win32":
        mode = os.stat(backup.file_path).st_mode
        assert not (mode & 0o004)  # Check that world-readable bit is not set

def test_backup_with_large_dataset(temp_storage):
    """Test backup functionality with a large number of accounts."""
    storage, _, _ = temp_storage
    
    # Create multiple accounts
    for i in range(20):  # Modest number for a test
        storage.create_account(
            name=f"Large Test Account {i}",
            username=f"largeuser{i}",
            password=f"LargePassword{i}!",
            created_by="backup_user"
        )
    
    # Create backup
    backup = storage.create_backup(name="Large Dataset Test")
    
    # Verify backup was created and contains all accounts
    assert backup is not None
    assert backup.account_count >= 20  # Could be more if fixture added accounts
    
    # Check backup file size
    assert os.path.getsize(backup.file_path) > 0
    
    # Optional: Test restore to ensure large data can be restored
    # (Skipping actual implementation to keep test focused)

def test_backup_encrypted_with_custom_key(temp_storage):
    """Test creating an encrypted backup with a specific master password."""
    storage, _, data_folder = temp_storage
    
    # Create a backup
    original_backup = storage.create_backup(name="Original", encrypt=True)
    
    # Create a new storage with different master password
    custom_password = "CustomMasterPass456!"
    new_storage_path = os.path.join(data_folder, "custom_key_storage")
    os.makedirs(new_storage_path, exist_ok=True)
    
    # Create new storage with custom password
    with patch('builtins.input', return_value="custom_admin"), \
         patch('getpass.getpass', return_value="Admin_Custom_123!"):
        new_storage = Storage(data_folder=new_storage_path, master_password=custom_password)
    
    # Create a backup with the new storage
    custom_backup = new_storage.create_backup(name="Custom Key Backup", encrypt=True)
    
    # Verify that we cannot decrypt with the wrong password
    with pytest.raises((ValueError, RuntimeError, InvalidToken)):
        storage.restore_from_backup(custom_backup.file_path)
    
    # Verify that we can decrypt with the correct password
    restore_result = storage.restore_from_backup(
        custom_backup.file_path, 
        master_password=custom_password
    )
    assert restore_result["success"] is True 