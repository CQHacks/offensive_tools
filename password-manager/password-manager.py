"""
Name: Personal Password Manager
Author: Chris Quinn
Date: 21-01-2025
Description: Secure, single-user password manager with master password 
             and grid-style display
"""

import os
import sys
import csv
import random
import string
import hashlib
import getpass
from datetime import datetime
from cryptography.fernet import Fernet

# Configuration
USER_NAME = "Chris"
CONFIG_DIR = os.path.join(os.path.expanduser('~'), '.password_manager')

# Ensure config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)

class SecurityManager:
    """Manages encryption, key generation, and master password."""
    
    @staticmethod
    def generate_master_password_hash(password):
        """Create a secure hash of the master password."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_master_password(stored_hash, input_password):
        """Verify the master password."""
        return stored_hash == SecurityManager.generate_master_password_hash(input_password)

    @staticmethod
    def setup_master_password():
        """Set up initial master password."""
        while True:
            password = getpass.getpass(f"Hello {USER_NAME}! Set up your master password: ")
            confirm = getpass.getpass("Confirm master password: ")
            
            if password == confirm:
                # Store hash, not the actual password
                hash_path = os.path.join(CONFIG_DIR, 'master.hash')
                with open(hash_path, 'w') as f:
                    f.write(SecurityManager.generate_master_password_hash(password))
                
                # Set restrictive permissions
                os.chmod(hash_path, 0o600)
                return True
            
            print("Passwords do not match. Please try again.")

    @staticmethod
    def authenticate():
        """Authenticate user with master password."""
        hash_path = os.path.join(CONFIG_DIR, 'master.hash')
        
        # Check if master password is set
        if not os.path.exists(hash_path):
            print("First time setup - let's create a master password.")
            SecurityManager.setup_master_password()
        
        # Authenticate
        attempts = 3
        while attempts > 0:
            input_password = getpass.getpass(f"Welcome {USER_NAME}. Enter master password: ")
            
            with open(hash_path, 'r') as f:
                stored_hash = f.read().strip()
            
            if SecurityManager.verify_master_password(stored_hash, input_password):
                return True
            
            attempts -= 1
            print(f"Incorrect password. {attempts} attempts remaining.")
        
        print("Too many failed attempts. Exiting.")
        sys.exit(1)

class PasswordManager:
    """Manages password storage and retrieval."""
    
    @staticmethod
    def get_password_length():
        """Prompt for and validate password length."""
        while True:
            try:
                length = int(input("Enter password length (8-30): ").strip())
                if 8 <= length <= 30:
                    return length
                print("Please enter a number between 8 and 30.")
            except ValueError:
                print("Please enter a valid number.")

    @staticmethod
    def generate_password(length=12):
        """Generate a complex random password of specified length."""
        characters = string.digits + string.punctuation + string.ascii_letters
        while True:
            password = ''.join(random.choice(characters) for _ in range(length))
            if (any(c.isupper() for c in password) and 
                any(c.islower() for c in password) and 
                any(c.isdigit() for c in password) and 
                any(c in string.punctuation for c in password)):
                return password

    @staticmethod
    def store_password(account, username, password):
        """Store a password securely."""
        storage_path = os.path.join(CONFIG_DIR, 'passwords.csv')
        
        # Check if file exists, create with headers if not
        file_exists = os.path.exists(storage_path)
        
        with open(storage_path, 'a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(['Account', 'Username', 'Password', 'Timestamp'])
            
            writer.writerow([
                account, 
                username, 
                password, 
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ])
        
        print(f"Password for {account} stored successfully.")

    @staticmethod
    def display_passwords():
        """Display passwords in a grid format."""
        storage_path = os.path.join(CONFIG_DIR, 'passwords.csv')
        
        # Check if file exists
        if not os.path.exists(storage_path):
            print("No passwords stored yet.")
            return
        
        # Read passwords
        with open(storage_path, 'r') as file:
            reader = list(csv.reader(file))
            
            # Check if there are any passwords after headers
            if len(reader) <= 1:
                print("No passwords stored yet.")
                return
            
            headers = reader[0]  # Headers
            rows = reader[1:]    # Actual data
            
            # Determine column widths
            col_widths = {
                'Account': max(len('Account'), max(len(str(row[0])) for row in rows)) + 2,
                'Username': max(len('Username'), max(len(str(row[1])) for row in rows)) + 2,
                'Password': max(len('Password'), max(len(str(row[2])) for row in rows)) + 2
            }
            
            # Print top border
            print('', '-' * (sum(col_widths.values()) + 6), '')
            
            # Print header
            print('|', end=' ')
            print(f"{'Account'.ljust(col_widths['Account'])}|", end=' ')
            print(f"{'Username'.ljust(col_widths['Username'])}|", end=' ')
            print(f"{'Password'.ljust(col_widths['Password'])}|")
            
            # Print separator
            print('', '-' * (sum(col_widths.values()) + 6), '')
            
            # Print rows
            for row in rows:
                print('|', end=' ')
                print(f"{str(row[0]).ljust(col_widths['Account'])}|", end=' ')
                print(f"{str(row[1]).ljust(col_widths['Username'])}|", end=' ')
                print(f"{str(row[2]).ljust(col_widths['Password'])}|")
            
            # Print bottom border
            print('', '-' * (sum(col_widths.values()) + 6), '')

    @staticmethod
    def edit_password():
        """Edit an existing password entry."""
        storage_path = os.path.join(CONFIG_DIR, 'passwords.csv')
        
        # Check if file exists
        if not os.path.exists(storage_path):
            print("No passwords stored yet.")
            return
        
        # Read existing passwords
        with open(storage_path, 'r') as file:
            reader = list(csv.reader(file))
        
        # Check if there are any passwords
        if len(reader) <= 1:
            print("No passwords stored yet.")
            return
        
        # Display existing accounts
        print("\nExisting Accounts:")
        for i, row in enumerate(reader[1:], 1):
            print(f"{i}. {row[0]} (Username: {row[1]})")
        
        # Select account to edit
        while True:
            try:
                choice = int(input("\nEnter the number of the account to edit: "))
                if 1 <= choice <= len(reader) - 1:
                    # Adjust for 0-indexing and header row
                    selected_row = reader[choice]
                    break
                print("Invalid selection. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
        
        # Edit options
        print("\nWhat would you like to edit?")
        print("1. Account Name")
        print("2. Username")
        print("3. Password")
        print("4. Cancel")
        
        edit_choice = input("Enter your choice: ").strip()
        
        if edit_choice == '1':
            # Edit account name
            new_account = input("Enter new account name: ").strip()
            selected_row[0] = new_account
            print("Account name updated.")
        elif edit_choice == '2':
            # Edit username
            new_username = input("Enter new username: ").strip()
            selected_row[1] = new_username
            print("Username updated.")
        elif edit_choice == '3':
            # Edit password
            generate_choice = input("Generate a new password? (y/n): ").strip().lower()
            
            if generate_choice == 'y':
                # Generate new password
                length = PasswordManager.get_password_length()
                new_password = PasswordManager.generate_password(length)
                print(f"Generated Password: {new_password}")
            else:
                # Manual password entry
                new_password = getpass.getpass("Enter new password: ")
            
            selected_row[2] = new_password
            print("Password updated.")
        else:
            print("Edit cancelled.")
            return
        
        # Update timestamp
        selected_row[3] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Write updated data back to file
        with open(storage_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(reader)
        
        print("Entry updated successfully.")

def main_menu():
    """Main application menu."""
    while True:
        print("\n--- Personal Password Manager ---")
        print("1. Add New Password")
        print("2. View Stored Passwords")
        print("3. Generate Random Password")
        print("4. Edit Existing Password")
        print("5. Exit")

        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                account = input("Enter account name: ").strip()
                username = input("Enter username: ").strip()
                
                # Option to use generated or manual password
                use_generated = input("Use generated password? (y/n): ").strip().lower()
                if use_generated == 'y':
                    length = PasswordManager.get_password_length()
                    password = PasswordManager.generate_password(length)
                    print(f"Generated Password: {password}")
                else:
                    password = getpass.getpass("Enter password: ")
                
                PasswordManager.store_password(account, username, password)

            elif choice == "2":
                PasswordManager.display_passwords()

            elif choice == "3":
                # Generate and display a random password
                length = PasswordManager.get_password_length()
                generated_pw = PasswordManager.generate_password(length)
                print(f"Generated Password: {generated_pw}")

            elif choice == "4":
                PasswordManager.edit_password()

            elif choice == "5":
                print("Exiting Password Manager.")
                break

            else:
                print("Invalid choice. Please try again.")

        except Exception as e:
            print(f"An error occurred: {e}")

def main():
    """Main application entry point."""
    # Authenticate user
    SecurityManager.authenticate()
    
    # Start main menu
    main_menu()

if __name__ == "__main__":
    main()