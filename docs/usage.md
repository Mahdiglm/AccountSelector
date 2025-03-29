# Usage Guide

This document provides detailed instructions for using the Account Selector application.

## Getting Started

After [installation](installation.md), run the application with:

```bash
python account_selector.py
```

## Authentication

### First Login

On first run, the application creates a default admin account:
- Username: `admin`
- Password: `Admin@SecureP@ss123!`

**IMPORTANT:** Change this password immediately after first login.

### Login

1. Select "Login" from the authentication menu
2. Enter your username and password
3. If credentials are correct, you'll be logged in and see the appropriate menu based on your role

### Sign Up

Regular users can sign up as follows:
1. Select "Sign Up" from the authentication menu
2. Enter a username and password (twice for confirmation)
3. Upon successful registration, you'll be automatically logged in

## Admin Features

As an admin, you have access to the following features:

### Browse All Accounts

View all accounts in the system with their details. You can:
- See usernames and passwords
- Filter by category or tags
- Sort by various fields

### Add New Account

Create new account credentials:
1. Fill in the required information (name, username, password)
2. Add optional details like website, notes, tags
3. View the password strength analysis
4. Save the account

### Manage Account

Edit or delete existing accounts:
1. Select an account from the list
2. Choose to edit or delete
3. If editing, update the information and save

### Manage Users

Add, edit, or delete users in the system:
1. View all users
2. Change user roles (promote to admin or demote to regular user)
3. Reset user passwords
4. Delete users

### Import/Export Accounts

Transfer account data between systems:
1. Select Import or Export
2. Choose the format (JSON, CSV, or text)
3. Select the file location
4. Confirm the operation

### View Account Stats

See statistics about stored accounts:
1. Password strength distribution
2. Category distribution
3. Account creation timeline

## User Features

Regular users have limited functionality:

### Browse Available Accounts

View accounts available for selection:
1. See account names and descriptions
2. Filter by category
3. Select accounts to view credentials

### View My Selected Accounts

Access previously selected accounts:
1. View all selected accounts
2. See full credentials for these accounts
3. Filter or search within selected accounts

### Common Features

Both admin and regular users can:

### Change Password

Update your user password:
1. Enter your current password
2. Enter and confirm your new password
3. View password strength analysis
4. Save the new password

### Change Theme

Customize the user interface:
1. Select from available themes (Default, Dark, Light, Hacker, Ocean)
2. Preview and apply the selected theme

## Tips & Tricks

- Use the password generator for creating strong, random passwords
- Tag accounts for better organization
- Export accounts periodically for backup
- Mark important accounts as favorites for quick access
- Use keyboard shortcuts for faster navigation (arrow keys, Enter) 