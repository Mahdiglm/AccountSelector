# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1-beta] - 2025-05-10

### Fixed

- Fixed critical bug with Fernet key formatting when initializing encryption
- Added proper base64 padding for encryption keys
- Improved key validation to ensure proper format
- Added key repair utility (fix_key_format.py) for fixing improperly formatted keys in existing installations

## [1.2.0-beta] - 2025-05-10

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

- Removed unused session management code (fields `session_token`, `session_expires`, `last_activity` from `User` model; methods `authenticate`, `verify_password`, `update_user_session`, `check_session_expired`, `check_session_idle`, `logout_user` from `storage.py`; `UserSession` class from `models.py`).
- Removed redundant `if __name__ == "__main__":` block from `src/main.py`.
- Removed `auto_logout_minutes` from default config as session logic was removed.

## [1.1.0-beta.1] - 2023-12-16

### Fixed

- Fixed Fernet encryption key generation and handling
- Improved key derivation process to ensure compatibility with cryptography library
- Enhanced overall stability of the encryption system

### Security

- Improved key management with proper key derivation
- Added backup of previous key files for recovery

## [1.1.0-beta] - 2023-12-15

### Security

- Improved key management for encryption
- Added proper error handling for encryption/decryption operations
- Implemented password policy enforcement with configurable settings
- Added auto-logout after session expiration or inactivity
- Added password expiration policy with forced password changes
- Implemented password history to prevent password reuse
- Enhanced password strength visualization with guidelines

### Fixed

- Improved error handling throughout the application
- Fixed generic exception handling with specific error types
- Enhanced input validation for all user inputs
- Added proper transaction handling for data file operations
- Fixed potential file I/O issues with context managers
- Implemented better error messages for users

### Added

- Added comprehensive backup and restore functionality
  - Encrypted backups with master password
  - Auto-backup on schedule
  - Backup rotation with configurable retention
  - Import/export backup files
  - Backup management UI
- Added password last changed tracking
- Added user session management
- Added user-specific settings
- Added account category customization
- Added metadata fields for accounts

### Changed

- Optimized search and filter operations for better performance
- Improved UI feedback during operations
- Enhanced password strength visualization with progress bar
- Restructured codebase for better maintainability
- Updated the User model with additional security fields

## [1.0.0-beta] - 2023-06-10

### Added

- Initial beta release
- User authentication with admin and regular user roles
- Role-based access control
- Account management (create, read, update, delete)
- Password strength analysis
- Secure password generation
- Import/export functionality (JSON, CSV, and text formats)
- Theme customization
- Password encryption using Fernet symmetric encryption
- Statistics dashboard
- CLI interface with visual enhancements

### Security

- Passwords for user accounts are hashed with bcrypt
- Account credentials are encrypted with Fernet symmetric encryption
- Security warnings and best practices in the UI

### Fixed

- Updated `requirements.txt` to include missing `typer` and `questionary` packages.
- Ensured password history policy is consistently checked and updated in `src/data/storage.py`'s `update_user` method.
- Renamed `fix_key.py` to `_regenerate_encryption_key.py` and significantly enhanced warnings about data loss risk.
