# Release Notes

## Version 1.2.1-beta (2025-05-10)

### Bug Fixes

- Fixed critical encryption initialization error that prevented application startup
- Corrected base64 encoding format for Fernet encryption keys
- Improved key validation and error handling
- Added utility script (fix_key_format.py) to repair existing installations with key format issues

## Version 1.2.0-beta (2025-05-10)

### Enhanced Security

- Removed all hardcoded credentials and default passwords
- Improved key management system with proper key derivation
- Enhanced error handling for encryption/decryption operations
- Added secure prompting for master password during initial setup
- Fixed potential security issues with key file handling

### Improved Reliability

- Implemented comprehensive logging system for better troubleshooting
- Added unit tests with pytest for core functionality
- Fixed issues with password history tracking
- Improved error handling throughout the application
- Prevented potential data loss during failed encryption operations

### New Features

- Added persistence for user-selected accounts
- Improved backup and restore functionality
- Enhanced logging system with file and console output
- Added dedicated error handling for encryption failures

## Version 1.1.0-beta.1 (2023-12-16)

### Fixed

- Fixed Fernet encryption key generation and handling
- Improved key derivation process to ensure compatibility with cryptography library
- Enhanced overall stability of the encryption system

### Security

- Improved key management with proper key derivation
- Added backup of previous key files for recovery

## Version 1.1.0-beta (2023-12-15)

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
