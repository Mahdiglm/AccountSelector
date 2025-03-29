#!/usr/bin/env python3
"""
Helper script to uninstall the Account Selector dependencies for testing purposes.
"""

import subprocess
import sys

def uninstall_dependencies():
    """Uninstall the Account Selector dependencies."""
    packages = [
        'rich',
        'typer',
        'pydantic',
        'bcrypt',
        'questionary',
        'cryptography'
    ]
    
    print("Uninstalling dependencies...")
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", package])
            print(f"Uninstalled {package}")
        except subprocess.CalledProcessError as e:
            print(f"Error uninstalling {package}: {e}")
    
    print("\nDependencies uninstalled. You can now test the auto-install feature.")
    print("Run 'python account_selector.py' to see the auto-install in action.")

if __name__ == "__main__":
    confirmation = input("This will uninstall dependencies used by Account Selector for testing purposes. Proceed? (y/n): ")
    if confirmation.lower() == 'y':
        uninstall_dependencies()
    else:
        print("Operation cancelled.") 