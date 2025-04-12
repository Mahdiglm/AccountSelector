#!/usr/bin/env python3
"""
Account Selector - Secure Credential Management

A command-line application for managing account credentials with user and admin functionality.
"""

import os
import sys
import subprocess
import importlib.util
import logging
import time
from typing import List, Dict, Tuple

# Early setup for logging
from src.utils.logger_config import setup_logging
logger = setup_logging() # Initialize logging

def is_bundled():
    """Check if the application is running as a PyInstaller bundle"""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')

def check_and_install_dependencies():
    """
    Check if required packages are installed and install them if missing.
    Returns True if all dependencies are available (existing or newly installed).
    """
    # Skip dependency checks when running as an executable
    if is_bundled():
        return True
        
    required_packages = [
        ('rich', '13.6.0'),
        ('typer', '0.9.0'),
        ('pydantic', '2.4.2'),
        ('bcrypt', '4.0.1'),
        ('questionary', '2.0.1'),
        ('cryptography', '41.0.4')
    ]
    
    missing_packages = []
    
    print("Checking dependencies...")
    
    for package, version in required_packages:
        spec = importlib.util.find_spec(package)
        if spec is None:
            missing_packages.append(f"{package}=={version}")
            print(f"Missing package: {package}")
        else:
            print(f"✓ {package} is installed")
    
    if missing_packages:
        print("\nInstalling missing dependencies...")
        try:
            # Use pip to install missing packages
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
            print("\nAll dependencies successfully installed!")
            # Give a moment for the user to read the output
            time.sleep(1)
            return True
        except subprocess.CalledProcessError as e:
            print(f"\nError installing dependencies: {e}")
            print("\nPlease try to install them manually with: pip install -r requirements.txt")
            logger.error(f"Failed to install dependencies: {e}", exc_info=True)
            input("Press Enter to exit...")
            return False
    
    return True

if __name__ == "__main__":
    try:
        # First check and install dependencies if needed
        if not check_and_install_dependencies():
            sys.exit(1)
            
        # Make sure the directory exists for data storage
        if not os.path.exists("app_data"):
            os.makedirs("app_data")
        
        # Only import after dependencies are installed
        from src.main import AccountSelectorApp
        logger.info("Dependencies checked/installed.")
            
        # Start the application
        logger.info("Starting Account Selector...")
        app = AccountSelectorApp()
        app.start()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user (KeyboardInterrupt). Exiting.")
        print("\nExiting Account Selector. Goodbye!")
        sys.exit(0)
    except Exception as e:
        # Log the full traceback for unexpected errors
        logger.critical(f"An unexpected error occurred at the top level: {e}", exc_info=True)
        print(f"\nAn unexpected critical error occurred. Check app.log for details. Error: {e}")
        sys.exit(1) 