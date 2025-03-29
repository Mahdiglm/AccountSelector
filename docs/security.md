# Security Guide

This document provides detailed information about the security features in Account Selector and how to use them effectively.

## Security Features

Account Selector includes several security features to protect your sensitive information:

### Password Hashing

User account passwords are hashed using the bcrypt algorithm before storage. This means:
- Raw passwords are never stored in the database
- Even if someone gets access to the users.json file, they cannot retrieve the original passwords
- Bcrypt includes salt generation to protect against rainbow table attacks

### Account Credential Encryption

All stored account credentials (passwords, usernames) are encrypted using Fernet symmetric encryption:
- The encryption key is stored in the `key.bin` file
- Data is encrypted before saving to the accounts.json file
- Data is decrypted only when needed for display

### Password Strength Analysis

The application analyzes password strength using multiple factors:
- Password length
- Character variety (lowercase, uppercase, digits, special characters)
- Common patterns detection
- Sequential characters detection
- Keyboard pattern detection
- Repeating character detection

### Password Generation

The secure password generator:
- Creates strong random passwords
- Guarantees inclusion of characters from each selected character set
- Allows customization of length and character types

## Security Best Practices

### Protecting Your Data

1. **Secure the key.bin file**:
   - Restrict access to the app_data directory
   - Consider encrypting this file with an additional password in high-security environments

2. **Regular backups**:
   - Export your accounts regularly
   - Store backups securely in an encrypted format

3. **Admin account security**:
   - Change the default admin password immediately after installation
   - Use a strong, unique password for the admin account
   - Consider creating a separate admin account and disabling the default

### Using Secure Passwords

1. **Password creation guidelines**:
   - Use at least 12 characters (16+ is recommended)
   - Include uppercase, lowercase, numbers, and special characters
   - Avoid common patterns and personal information
   - Use a different password for each account

2. **Password rotation**:
   - Update important passwords regularly
   - The application's password expiry feature can help track when passwords need rotation

3. **Using the password generator**:
   - Let the application generate passwords when possible
   - Use maximum complexity for critical accounts

## Security Limitations

Be aware of the following limitations:

1. **Local application security**:
   - The application runs locally and depends on the security of your operating system
   - Anyone with access to your user account on the computer could potentially access the app

2. **Memory exposure**:
   - While passwords are encrypted in storage, they are decrypted in memory when displayed
   - Advanced memory-reading malware could potentially capture passwords when displayed

3. **No multi-factor authentication**:
   - The current version doesn't support MFA for additional account security

## Reporting Security Issues

If you discover a security vulnerability:

1. Do NOT disclose it publicly in issues or discussions
2. Send details privately to the project maintainers
3. Allow time for the issue to be addressed before disclosure

## Security Roadmap

Future security improvements planned:
- Multi-factor authentication support
- Master password for application access
- Full database encryption
- Secure password sharing
- Audit logging of sensitive operations 