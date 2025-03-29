import json
import csv
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import re
import uuid


def export_to_json(accounts: List[Dict[str, Any]], filepath: str) -> str:
    """
    Export accounts to a JSON file.
    
    Args:
        accounts: List of account dictionaries
        filepath: Path to save the file
    
    Returns:
        Path to the exported file
    """
    # Ensure the file has a .json extension
    if not filepath.lower().endswith('.json'):
        filepath += '.json'
    
    # Format the data for export
    export_data = {
        "export_date": datetime.now().isoformat(),
        "accounts": accounts
    }
    
    with open(filepath, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    return filepath


def export_to_csv(accounts: List[Dict[str, Any]], filepath: str) -> str:
    """
    Export accounts to a CSV file.
    
    Args:
        accounts: List of account dictionaries
        filepath: Path to save the file
    
    Returns:
        Path to the exported file
    """
    # Ensure the file has a .csv extension
    if not filepath.lower().endswith('.csv'):
        filepath += '.csv'
    
    # Define CSV columns
    columns = ['name', 'username', 'password', 'website', 'category', 'notes', 'tags']
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        
        for account in accounts:
            # Prepare row data
            row = {
                'name': account['name'],
                'username': account['username'],
                'password': account['password'],
                'website': account.get('website', ''),
                'category': account.get('category', 'other'),
                'notes': account.get('notes', ''),
                'tags': ','.join(account.get('tags', []))
            }
            writer.writerow(row)
    
    return filepath


def import_from_json(filepath: str, username: str) -> Optional[List[Dict[str, Any]]]:
    """
    Import accounts from a JSON file.
    
    Args:
        filepath: Path to the JSON file
        username: Username of the importing user
    
    Returns:
        List of imported account dictionaries or None if import failed
    """
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Check if the file has the expected format
        if not isinstance(data, dict) or 'accounts' not in data:
            # Try to interpret the file as a direct list of accounts
            if isinstance(data, list):
                accounts = data
            else:
                return None
        else:
            accounts = data['accounts']
        
        # Prepare accounts for import
        imported_accounts = []
        for account in accounts:
            # Create a new account with required fields
            new_account = {
                'id': str(uuid.uuid4()),
                'name': account.get('name', 'Imported Account'),
                'username': account.get('username', ''),
                'password': account.get('password', ''),
                'website': account.get('website', ''),
                'notes': account.get('notes', ''),
                'category': account.get('category', 'other'),
                'tags': account.get('tags', []),
                'created_by': username,
                'created_at': datetime.now().isoformat(),
                'password_strength': 0,  # Will be calculated later
                'is_favorite': False
            }
            imported_accounts.append(new_account)
        
        return imported_accounts
    
    except Exception as e:
        print(f"Error importing JSON: {str(e)}")
        return None


def import_from_csv(filepath: str, username: str) -> Optional[List[Dict[str, Any]]]:
    """
    Import accounts from a CSV file.
    
    Args:
        filepath: Path to the CSV file
        username: Username of the importing user
    
    Returns:
        List of imported account dictionaries or None if import failed
    """
    try:
        accounts = []
        
        with open(filepath, 'r', newline='') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Create tags list if it exists
                tags = []
                if 'tags' in row and row['tags']:
                    tags = [tag.strip() for tag in row['tags'].split(',')]
                
                # Create a new account
                account = {
                    'id': str(uuid.uuid4()),
                    'name': row.get('name', 'Imported Account'),
                    'username': row.get('username', ''),
                    'password': row.get('password', ''),
                    'website': row.get('website', ''),
                    'notes': row.get('notes', ''),
                    'category': row.get('category', 'other').lower(),
                    'tags': tags,
                    'created_by': username,
                    'created_at': datetime.now().isoformat(),
                    'password_strength': 0,  # Will be calculated later
                    'is_favorite': False
                }
                accounts.append(account)
        
        return accounts
    
    except Exception as e:
        print(f"Error importing CSV: {str(e)}")
        return None


def import_from_text(filepath: str, username: str) -> Optional[List[Dict[str, Any]]]:
    """
    Import accounts from a text file with format: website,username,password.
    
    Args:
        filepath: Path to the text file
        username: Username of the importing user
    
    Returns:
        List of imported account dictionaries or None if import failed
    """
    try:
        accounts = []
        
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Try to parse the line - support both comma and tab separators
                parts = re.split(r',|\t', line)
                
                # Need at least username and password
                if len(parts) >= 2:
                    website = parts[0] if len(parts) >= 3 else ''
                    username = parts[1] if len(parts) >= 3 else parts[0]
                    password = parts[-1]
                    
                    # Create a name from website or username
                    name = website or username
                    if name.startswith('http'):
                        # Extract domain from URL
                        domain_match = re.search(r'https?://(?:www\.)?([^/]+)', name)
                        if domain_match:
                            name = domain_match.group(1)
                    
                    account = {
                        'id': str(uuid.uuid4()),
                        'name': name,
                        'username': username,
                        'password': password,
                        'website': website,
                        'notes': '',
                        'category': 'other',
                        'tags': [],
                        'created_by': username,
                        'created_at': datetime.now().isoformat(),
                        'password_strength': 0,  # Will be calculated later
                        'is_favorite': False
                    }
                    accounts.append(account)
        
        return accounts
    
    except Exception as e:
        print(f"Error importing text file: {str(e)}")
        return None