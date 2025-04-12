# Account Selector

<div align="center">

![License](https://img.shields.io/github/license/Mahdiglm/AccountSelector)
![Version](https://img.shields.io/github/v/release/Mahdiglm/AccountSelector?include_prereleases)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Mahdiglm/AccountSelector/graphs/commit-activity)

Account Selector is a secure desktop application for managing and organizing account credentials with enhanced security features.

## Version 1.2.1-beta

This maintenance release includes critical fixes for encryption key handling:

- **Fixed Critical Error**: Corrected encryption key formatting issue that prevented application startup
- **Improved Stability**: Enhanced key validation and error handling
- **Key Repair Utility**: Added fix_key_format.py utility for repairing existing installations
- **Security Enhancements**: All features from 1.2.0-beta plus improved key format validation

## Version 1.2.0-beta

This beta release includes significant security enhancements, improved reliability, and additional features:

- **Enhanced Security**: Removed hardcoded credentials, improved key management, secure password handling
- **Improved Reliability**: Comprehensive logging, unit testing, better error handling
- **New Features**: Account persistence, enhanced backup functionality
- **User Experience**: Better feedback, visualizations, and error reporting

```
 █████╗  ██████╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝
███████║██║     ██║     ██║   ██║██║   ██║██╔██╗ ██║   ██║
██╔══██║██║     ██║     ██║   ██║██║   ██║██║╚██╗██║   ██║
██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
███████╗███████╗██╗     ███████╗ ██████╗████████╗ ██████╗ ██████╗
██╔════╝██╔════╝██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
███████╗█████╗  ██║     █████╗  ██║        ██║   ██║   ██║██████╔╝
╚════██║██╔══╝  ██║     ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
███████║███████╗███████╗███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

</div>

## Features

- **User Authentication**: Login and signup system with secure password storage
- **Role-Based Access Control**: Admins manage accounts, users can select/purchase them
- **Account Management**: Admin panel for creating, viewing, editing, and deleting accounts
- **User Selection**: Users can browse and select accounts to view (read-only access)
- **Password Analysis & Generation**: Analyze password strength and generate secure passwords
- **Account Categories & Tags**: Organize accounts by categories and custom tags
- **Import/Export**: Import and export accounts in JSON, CSV, and text formats
- **Theme Customization**: Choose from multiple visual themes for the interface
- **Statistics Dashboard**: View analytics on password strength, categories, and more
- **Modern UI Interface**: User-friendly interface with clear visual feedback
- **Secure Storage**: Passwords are hashed before storage and account credentials are encrypted
- **Auto-dependency Installation**: Automatically installs required dependencies on first run
- **Backup System**: Create, manage and restore from encrypted backups
- **Password Expiration**: Enforce regular password changes
- **User Sessions**: Better session management with automatic logout
- **Secure Key Management**: Encryption key derived from a master password set on first run
- **Logging**: Application events and errors logged to `app_data/app.log`
- **Unit Tested**: Core data storage logic includes automated tests (`pytest`)

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Access Control](#access-control)
- [Advanced Features](#advanced-features)
- [Data Storage](#data-storage)
- [Security Notes](#security-notes)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. Make sure you have Python 3.8+ installed
2. Clone this repository:
   ```bash
   git clone https://github.com/Mahdiglm/AccountSelector.git
   cd AccountSelector
   ```
3. Run the application - dependencies will be installed automatically:
   ```bash
   python account_selector.py
   ```

## Usage

### Default Admin Account

On the first run, if no users exist, the application will prompt you to create an initial admin account.
You will need to provide a username and a secure password.

**IMPORTANT:** _You must choose a strong password for the initial admin account._

### User Interface

<details>
<summary>Authentication Menu</summary>

- Login to existing account
- Sign up for a new account
- Exit the application
</details>

<details>
<summary>Admin Menu</summary>

- Browse All Accounts - View all accounts in the system
- Add New Account - Create new account credentials with strength analysis
- Manage Account - Edit or delete existing accounts
- Manage Users - Add, edit, or delete users
- Import/Export Accounts - Import from or export to JSON, CSV, or text files
- View Account Stats - See statistics about password strength and categories
- Change Theme - Select from various visual themes
- Change Password - Update admin password
- Logout
</details>

<details>
<summary>User Menu</summary>

- Browse Available Accounts - View and select accounts with read-only access
- View My Selected Accounts - View selected account credentials (read-only)
- Change Theme - Select from various visual themes
- Change Password - Update your user password
- Logout
</details>

## Access Control

- **Administrators** have full access to create, read, update, and delete accounts and users
- **Regular Users** can only:
  - Browse available accounts
  - Select accounts to view their credentials
  - View selected account credentials in read-only mode
  - Change their own user password
  - Cannot modify any account credentials

## Advanced Features

<details>
<summary>Password Management</summary>

- **Password Strength Analysis**: Accounts are analyzed for password strength
- **Password Suggestions**: Get suggestions to improve weak passwords
- **Password Generator**: Generate secure passwords with customizable options
- **Password Expiration**: Force regular password changes based on policy
- **Password History**: Prevent reuse of previously used passwords
- **Password Policy**: Configurable requirements for password complexity
</details>

<details>
<summary>Organization</summary>

- **Categories**: Organize accounts by predefined categories (Social, Financial, Email, etc.)
- **Tags**: Add custom tags to accounts for better organization
- **Favorites**: Mark accounts as favorites for quick access
- **Custom Categories**: Create your own account categories
</details>

<details>
<summary>Data Management</summary>

- **Import/Export**: Transfer account data between systems
- **Supported Formats**: JSON, CSV, and plain text
- **Backup System**: Create encrypted backups of all application data
- **Scheduled Backups**: Configure automatic backups on a schedule
- **Backup Rotation**: Automatically manage backup retention
- **Backup Encryption**: Secure backups with encryption
</details>

<details>
<summary>Customization</summary>

- **Themes**: Choose from multiple visual themes (Default, Dark, Light, Hacker, Ocean)
- **Account Expiry**: Set expiration dates for accounts that need renewal
- **User Settings**: Personalized settings for each user
</details>

## Data Storage

Account data is stored in JSON files in the `app_data` directory:

- `users.json`: Contains user account information with hashed passwords
- `accounts.json`: Contains encrypted stored account credentials
- `key.bin`: Contains the salt and the encrypted master key derived from the master password provided during setup. **Losing this file or forgetting the master password will result in permanent loss of access to encrypted account data.**
- `config.json`: Stores application settings like password policies and backup configuration

## Security Notes

This application stores sensitive information. For maximum security:

1. Restrict access to the computer running this application
2. Use this application only on trusted devices
3. **Set a strong, unique Master Password** during the initial setup. This password is used to protect your encryption key.
4. **Protect the `key.bin` file** located in the `app_data` directory. Do not delete or modify it manually.
5. **Regularly back up your data** using the built-in backup system. Store backups securely, especially if they are unencrypted.
6. Follow the password policy recommendations enforced by the application.
7. Change passwords regularly.
8. Log out when not using the application.

### Emergency Key Regeneration

If the master password is forgotten AND backups are unavailable, the `_regenerate_encryption_key.py` script can be run (`python _regenerate_encryption_key.py`). **WARNING:** This is a destructive operation. It will prompt for a _new_ master password and generate a _new_ encryption key, making all previously encrypted account data **permanently inaccessible**. Use with extreme caution as a last resort.

### Key Repair Utility

For users experiencing encryption initialization errors, a key repair utility is included. Run `python fix_key_format.py` to fix improper key formatting issues. This tool creates a backup of your existing key file before making any changes and validates the repaired key.

## Testing

To test the automatic dependency installation:

1. Run `python uninstall_deps.py` to uninstall dependencies
2. Run `python account_selector.py` to see the auto-install in action

### Running Unit Tests

Install development dependencies and run tests:

```bash
pip install -r requirements.txt
python -m pytest
```

## Contributing

Contributions are welcome! Please check out our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit contributions to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
