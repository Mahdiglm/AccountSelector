# Installation Guide

This document provides detailed instructions for installing and setting up the Account Selector application.

## Prerequisites

Before installing Account Selector, ensure you have:

- Python 3.8 or higher installed
- pip (Python package manager)
- Git (optional, for cloning the repository)

## Installation Methods

### Method 1: Clone from GitHub (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/Mahdiglm/AccountSelector.git
   cd AccountSelector
   ```

2. Run the application:
   ```bash
   python account_selector.py
   ```
   
   The application will automatically install required dependencies on first run.

### Method 2: Download ZIP

1. Download the ZIP file from the [Releases page](https://github.com/Mahdiglm/AccountSelector/releases)
2. Extract the ZIP file to a location of your choice
3. Open a terminal or command prompt
4. Navigate to the extracted folder:
   ```bash
   cd path/to/AccountSelector
   ```
5. Run the application:
   ```bash
   python account_selector.py
   ```

## Manual Dependency Installation

If you prefer to install dependencies manually:

```bash
pip install -r requirements.txt
```

## Verifying Installation

After installation, you should be able to run the application. Upon first run, it will:

1. Create the necessary data directories
2. Set up a default admin account 
3. Present you with the login screen

The default admin credentials are:
- Username: `admin`
- Password: `Admin@SecureP@ss123!`

**Important:** Change this password immediately after your first login for security purposes.

## Troubleshooting

### Common Issues

1. **Missing dependencies**: 
   If the automatic installation fails, try manually installing dependencies:
   ```bash
   pip install rich==13.6.0 typer==0.9.0 pydantic==2.4.2 bcrypt==4.0.1 questionary==2.0.1 cryptography==41.0.4
   ```

2. **Permission issues**:
   - On Linux/Mac, you might need to use `sudo` or set up a virtual environment
   - On Windows, run the command prompt as administrator if you encounter permission issues

3. **Python version issues**:
   - Ensure you're using Python 3.8 or higher: `python --version`
   - If you have multiple Python versions, try using `python3` instead of `python`

For further assistance, please [create an issue](https://github.com/Mahdiglm/AccountSelector/issues/new/choose) on GitHub. 