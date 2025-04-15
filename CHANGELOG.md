# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.7-beta] - 2025-04-15

### Added

- Comprehensive unit tests for backup and restore functionality
- Test cases for auto-backup, backup rotation, and edge cases
- New test file dedicated to backup/restore testing

### Improved

- Expanded test coverage for error handling scenarios
- Better validation of backup metadata integrity
- Testing of backup file security aspects

## [1.2.6-beta] - 2025-04-15

### Improved

- Enhanced error messages for encryption failures
- Added more descriptive guidance in encryption-related errors
- Implemented detailed logging for password decryption failures
- Improved user feedback for backup restoration errors
- Added specific error handling for encrypted backup operations

## [1.2.5-beta] - 2025-04-15

### Enhanced

- Improved 33-byte key handling with additional validation steps
- Added better error messages for encryption key issues
- Enhanced key repair with fallback methods for difficult cases
- Implemented detailed logging during key truncation process

## [1.2.4-beta] - 2025-04-15

### Added

- Added comprehensive application summary document `account_selector_summary.md`
- Created structured TODO list to track pending tasks and improvements

### Changed

- Improved documentation organization for better contributor onboarding

## [1.2.3-beta] - 2023-04-12

### Fixed

- Fixed specific issue with 33-byte keys being rejected during encryption initialization
- Added automatic key truncation for oversized keys to ensure Fernet compatibility
- Enhanced error handling with specific solutions for common key format problems
- Improved logging messages for better diagnostics during key validation

## [1.2.2-beta] - 2023-04-12

### Fixed

- Improved fix for Fernet encryption key formatting issues
- Completely rewrote key validation and repair logic
- Enhanced the key repair utility with better error handling and diagnostics
- Added key length validation to ensure compatibility with Fernet
- Implemented proper base64 padding handling for encryption keys
- Added option to regenerate a new key if repair fails

## [1.2.1-beta] - 2025-04-12

### Fixed

- Fixed critical bug with Fernet key formatting when initializing encryption
- Added proper base64 padding for encryption keys
- Improved key validation to ensure proper format
- Added key repair utility (fix_key_format.py) for fixing improperly formatted keys in existing installations

## [1.2.0-beta] - 2025-04-12

### Security

- Removed hardcoded default master password for encryption key generation in `src/data/storage.py`.
- Removed hardcoded default admin password in `src/data/storage.py`. Application now prompts for initial admin credentials on first run.
- Removed flawed key check value logic from key generation/loading in `fix_key.py` and `src/data/storage.py`.
- `_save_accounts` in `src/data/storage.py` now raises an error if password encryption fails, preventing plaintext passwords from being saved.
- `fix_key.py` now prompts securely for a master password instead of using a hardcoded one, includes warnings, and has basic error handling.

### Fixed

- Updated `requirements.txt` to include missing `typer` and `questionary` packages.
- Ensured password history policy is consistently checked and updated in `src/data/storage.py`'s `update_user` method.
- `create_account_from_dict` in `src/data/storage.py` now checks for existing account IDs and skips duplicates during import.
- Refined exception handling in `src/data/storage.py` to use more specific exception types instead of generic `Exception`.
- Calls to private `_load_users` in `src/main.py` replaced with calls to public `get_users`.
- Fixed potential issue where backup creation failed silently in `src/data/storage.py`.

### Added

- Added persistence for user-selected accounts (stored in `User.selected_account_ids` field).
- Added public `get_users()` method to `src/data/storage.py` for better encapsulation.
- Added structured logging to file (`app_data/app.log`) and console using Python's `logging` module.
- Added initial unit tests using `pytest` for `src/data/storage.py`, covering initialization, auth, password history, CRUD, encryption, and backup/restore.
- Renamed `fix_key.py` to `_regenerate_encryption_key.py` with enhanced warnings about data loss risk.

### Removed

- Removed unused session management code (fields `session_token`, `session_expires`, `last_activity` from `User` model; methods `
