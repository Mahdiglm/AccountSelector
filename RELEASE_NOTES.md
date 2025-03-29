# Release Notes

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