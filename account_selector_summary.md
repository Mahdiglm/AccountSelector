# Account Selector Application Summary

## Overview

Account Selector is a secure Python-based desktop application for managing account credentials with enhanced security features, role-based access control, and comprehensive encryption.

## Core Architecture

### Entry Points

- `account_selector.py`: Main entry point that initializes logging, handles dependencies, and launches the application
- `src/main.py`: Contains the `AccountSelectorApp` class with the core application logic

### Data Layer

- `src/data/storage.py`: Implements the `Storage` class for secure data access and persistence
- `src/data/models.py`: Defines Pydantic models for `User`, `Account`, and `Backup`

## Security Features

### Encryption

- Fernet symmetric encryption (cryptography library)
- Key derivation from master password using PBKDF2 or Scrypt
- All sensitive credential data encrypted at rest

### Password Management

- bcrypt for password hashing
- Configurable password policy enforcement
- Password strength measurement and suggestions
- Password history to prevent reuse
- Secure password generation

### Access Control

- Role-based permissions (Admin vs Regular users)
- Read-only access for regular users
- Full CRUD privileges for administrators

### Data Protection

- Encrypted backup and restore functionality
- Transaction safety through temporary files
- Key file protection

## User Roles and Functions

### Admin Functions

- Browse all accounts with full credential visibility
- Create, edit, and delete accounts
- Manage users and their permissions
- Import/export account data
- View account statistics
- Configure system settings

### Regular User Functions

- Browse available accounts (read-only access)
- Select accounts to view their credentials
- View selected account credentials in read-only mode
- Change personal password and theme settings

## Technical Implementation

### Data Storage

- JSON files in app_data directory:
  - `users.json`: User data with hashed passwords
  - `accounts.json`: Account data with encrypted passwords
  - `key.bin`: Encryption salt and key
  - `config.json`: Application configuration

### Dependencies

- PySide6: UI framework
- pydantic: Data validation
- bcrypt: Password hashing
- cryptography: Encryption
- questionary: Interactive CLI prompts
- typer: CLI interface
- rich: Enhanced terminal output

### Key Features

- User authentication with secure password storage
- Account management with categories and tags
- Password analysis and generation
- Import/export in multiple formats
- Theme customization
- Statistics dashboard
- Backup system with encryption

## Recent Updates

- Fixed encryption key handling issues
- Implemented automatic key repair for oversized keys
- Enhanced key validation and error reporting
- Added persistence for user-selected accounts
- Improved security with better error handling
