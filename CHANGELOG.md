# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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