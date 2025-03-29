# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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