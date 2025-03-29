# Account Selector

A Python command-line application for securely managing account credentials with user and admin functionality.

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
- **Appealing CLI Interface**: Modern, colorful, and user-friendly command-line interface
- **Secure Storage**: Passwords are hashed before storage and account credentials are encrypted
- **Auto-dependency Installation**: Automatically installs required dependencies on first run

## Installation

1. Make sure you have Python 3.8+ installed
2. Clone this repository or download the source code
3. Run the application - dependencies will be installed automatically

## Usage

Run the application with:

```bash
python account_selector.py
```

The application will check for required dependencies and install them automatically on the first run.

### Default Admin Account

When first run, the application automatically creates an admin account:
- Username: `admin`
- Password: `Admin@SecureP@ss123!`

**IMPORTANT:** *It is strongly recommended to change this password immediately after the first login for security purposes.*

### User Interface

The application has different menus based on user roles:

#### Authentication Menu
- Login to existing account
- Sign up for a new account
- Exit the application

#### Admin Menu
- Browse All Accounts - View all accounts in the system
- Add New Account - Create new account credentials with strength analysis
- Manage Account - Edit or delete existing accounts
- Manage Users - Add, edit, or delete users
- Import/Export Accounts - Import from or export to JSON, CSV, or text files
- View Account Stats - See statistics about password strength and categories
- Change Theme - Select from various visual themes
- Change Password - Update admin password
- Logout

#### User Menu
- Browse Available Accounts - View and select accounts with read-only access
- View My Selected Accounts - View selected account credentials (read-only)
- Change Theme - Select from various visual themes  
- Change Password - Update your user password
- Logout

## Access Control

- **Administrators** have full access to create, read, update, and delete accounts and users
- **Regular Users** can only:
  - Browse available accounts
  - Select accounts to view their credentials
  - View selected account credentials in read-only mode
  - Change their own user password
  - Cannot modify any account credentials

## Advanced Features

### Password Management
- **Password Strength Analysis**: Accounts are analyzed for password strength
- **Password Suggestions**: Get suggestions to improve weak passwords
- **Password Generator**: Generate secure passwords with customizable options

### Organization
- **Categories**: Organize accounts by predefined categories (Social, Financial, Email, etc.)
- **Tags**: Add custom tags to accounts for better organization
- **Favorites**: Mark accounts as favorites for quick access

### Data Management
- **Import/Export**: Transfer account data between systems
- **Supported Formats**: JSON, CSV, and plain text
- **Automatic Backup**: Export feature can be used for regular backups

### Customization
- **Themes**: Choose from multiple visual themes (Default, Dark, Light, Hacker, Ocean)
- **Account Expiry**: Set expiration dates for accounts that need renewal

## Data Storage

Account data is stored in JSON files in the `app_data` directory:
- `users.json`: Contains user account information
- `accounts.json`: Contains stored credentials

## Security Note

This application stores sensitive information. While passwords for user accounts are hashed, the stored account credentials are encrypted using the Fernet symmetric encryption scheme. For maximum security, consider:

1. Restricting access to the computer running this application
2. Using this application only on trusted devices
3. Regularly backing up your credentials
4. Protecting access to the key.bin file in the app_data directory

## Testing Auto-Install

To test the automatic dependency installation:

1. Run `python uninstall_deps.py` to uninstall dependencies
2. Run `python account_selector.py` to see the auto-install in action 