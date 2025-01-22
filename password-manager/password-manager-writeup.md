# Personal Password Manager: Comprehensive Technical Documentation

## Overview
This Personal Password Manager is a secure, single-user Python application designed to manage passwords locally with robust security features. The script demonstrates advanced Python programming concepts, including object-oriented design, secure password management, and user authentication.

## Project Structure

### Key Components
- **Security Management**: Handles user authentication and encryption
- **Password Management**: Provides core functionality for password operations
- **User Interface**: Offers an interactive command-line interface

## Detailed Component Breakdown

### 1. Security Manager Class
```python
class SecurityManager:
```
#### Purpose
The `SecurityManager` class is responsible for all security-related operations, including:
- Master password creation
- Password authentication
- Secure password hashing

#### Key Methods

##### `generate_master_password_hash(password)`
```python
@staticmethod
def generate_master_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()
```
- **Functionality**: Creates a secure SHA-256 hash of the master password
- **Security Benefits**:
  - Prevents storing plain-text passwords
  - One-way hashing makes password recovery impossible
  - Consistent with cryptographic best practices

##### `setup_master_password()`
```python
@staticmethod
def setup_master_password():
    # Password creation and confirmation logic
```
- **Process**:
  1. Prompts user to create a master password
  2. Requires password confirmation
  3. Stores password hash in a secure, permission-restricted file
- **Security Features**:
  - Prevents empty passwords
  - Ensures password match before storing
  - Sets restrictive file permissions (0o600)

##### `authenticate()`
```python
@staticmethod
def authenticate():
    # Master password authentication logic
```
- **Authentication Flow**:
  1. Checks if master password is set
  2. Provides first-time setup if no password exists
  3. Allows 3 login attempts
  4. Exits application after failed attempts
- **Security Measures**:
  - Limits login attempts
  - Provides clear user feedback
  - Prevents unauthorized access

### 2. Password Manager Class
```python
class PasswordManager:
```
#### Purpose
Handles all password-related operations, including:
- Password generation
- Password storage
- Password display
- Password editing

#### Key Methods

##### `get_password_length()`
```python
@staticmethod
def get_password_length():
    # Validates user input for password length
```
- **Features**:
  - Enforces password length between 8-30 characters
  - Provides input validation
  - Handles potential input errors

##### `generate_password(length=12)`
```python
@staticmethod
def generate_password(length=12):
    # Generates a complex random password
```
- **Complexity Requirements**:
  - Includes digits, punctuation, uppercase, and lowercase characters
  - Ensures password meets complexity standards
  - Generates truly random passwords

##### `store_password(account, username, password)`
```python
@staticmethod
def store_password(account, username, password):
    # Securely stores password in CSV file
```
- **Storage Mechanism**:
  - Creates CSV file if not exists
  - Adds timestamp to each entry
  - Stores account, username, and password
  - Provides user feedback

##### `display_passwords()`
```python
@staticmethod
def display_passwords():
    # Displays passwords in a formatted grid
```
- **Display Features**:
  - Dynamic column width calculation
  - Formatted grid output
  - Handles cases with no stored passwords
  - Provides clean, readable interface

##### `edit_password()`
```python
@staticmethod
def edit_password():
    # Allows editing of existing password entries
```
- **Editing Capabilities**:
  - Select entry by account
  - Edit account name, username, or password
  - Option to generate new password
  - Updates timestamp on modification

### 3. Main Application Flow

#### `main_menu()`
```python
def main_menu():
    # Primary user interaction loop
```
- **Menu Options**:
  1. Add New Password
  2. View Stored Passwords
  3. Generate Random Password
  4. Edit Existing Password
  5. Exit

#### `main()`
```python
def main():
    # Application entry point
```
- **Startup Sequence**:
  1. Authenticate user
  2. Launch main menu

## Security Considerations

### Authentication
- Master password hash stored securely
- Limited login attempts
- No plain-text password storage

### Password Generation
- Cryptographically secure random generation
- Enforced complexity requirements
- Customizable length

### Data Storage
- Passwords stored in user's home directory
- Restricted file permissions
- CSV format for portability

## Potential Improvements
- Clipboard integration
- Password export/import
- Enhanced logging
- Two-factor authentication

## Cybersecurity Portfolio Highlights
- Secure password management
- User authentication implementation
- Cryptographic hashing
- Secure random generation
- Input validation
- Error handling

## Technologies Used
- Python 3
- `hashlib` for secure hashing
- `cryptography` for encryption
- `csv` for data storage
- `getpass` for secure input
- `os` for file and permission management

## Conclusion
This Personal Password Manager demonstrates a comprehensive approach to local password management, emphasizing security, usability, and robust design principles.