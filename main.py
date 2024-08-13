import sys
import curses
import json
import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# ----- Encryption Manager -----
class EncryptionManager:
    def __init__(self, password):
        # Derive a key from the password
        self.key = hashlib.sha256(password.encode()).digest()
        self.backend = default_backend()

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt(self, ciphertext):
        raw_data = base64.b64decode(ciphertext)
        iv = raw_data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(raw_data[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode('utf-8')

# ----- User Management -----
class UserManager:
    def __init__(self, json_file):
        self.json_file = json_file
        if not os.path.exists(json_file):
            with open(json_file, 'w') as file:
                json.dump({}, file)
        self.users = self.load_users()
    
    def load_users(self):
        with open(self.json_file, 'r') as file:
            return json.load(file)
    
    def save_users(self):
        with open(self.json_file, 'w') as file:
            json.dump(self.users, file)
    
    def create_user(self, username, password):
        if username in self.users:
            return False
        
        encryption_manager = EncryptionManager(password)
        password_hash = encryption_manager.key
        
        self.users[username] = {'password_hash': base64.b64encode(password_hash).decode('utf-8')}
        self.save_users()
        return True
    
    def authenticate(self, username, password):
        if username not in self.users:
            return False
        
        stored_hash = base64.b64decode(self.users[username]['password_hash'])
        encryption_manager = EncryptionManager(password)
        return encryption_manager.key == stored_hash
    
    def get_user_password(self, username):
        return base64.b64decode(self.users[username]['password_hash']) if username in self.users else None

# ----- Password Database -----
class PasswordDatabase:
    def __init__(self, json_file, encryption_manager):
        self.json_file = json_file
        self.encryption_manager = encryption_manager
        if not os.path.exists(json_file):
            with open(json_file, 'w') as file:
                json.dump({}, file)
        self.passwords = self.load_passwords()

    def load_passwords(self):
        with open(self.json_file, 'r') as file:
            return json.load(file)

    def save_passwords(self):
        with open(self.json_file, 'w') as file:
            json.dump(self.passwords, file)

    def add_password(self, service, username, password):
        encrypted_password = self.encryption_manager.encrypt(password)
        self.passwords[service] = {'username': username, 'password': encrypted_password}
        self.save_passwords()

    def retrieve_password(self, service):
        if service in self.passwords:
            record = self.passwords[service]
            record['password'] = self.encryption_manager.decrypt(record['password'])
            return record
        return None

    def delete_password(self, service):
        if service in self.passwords:
            del self.passwords[service]
            self.save_passwords()
            return True
        return False

# ----- UI Functions -----
def start_screen(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Welcome to the Password Manager")
    stdscr.addstr(2, 0, "1. Login")
    stdscr.addstr(3, 0, "2. Create a new user")
    stdscr.addstr(4, 0, "3. Exit")
    stdscr.refresh()
    return stdscr.getch()

def login_screen(stdscr, user_manager):
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter your username: ")
    username = stdscr.getstr().decode('utf-8')

    stdscr.addstr(1, 0, "Enter your password: ")
    password = stdscr.getstr().decode('utf-8')

    if user_manager.authenticate(username, password):
        return username
    else:
        stdscr.addstr(3, 0, "Invalid credentials. Press any key to return to the main menu.")
        stdscr.refresh()
        stdscr.getch()
        return None

def create_user_screen(stdscr, user_manager):
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter your desired username: ")
    username = stdscr.getstr().decode('utf-8')

    stdscr.addstr(1, 0, "Enter your desired password: ")
    password = stdscr.getstr().decode('utf-8')

    if user_manager.create_user(username, password):
        stdscr.addstr(3, 0, "User created successfully! Press any key to login.")
    else:
        stdscr.addstr(3, 0, "User creation failed (username might already exist). Press any key to return to the main menu.")
    
    stdscr.refresh()
    stdscr.getch()

def mainMenu(stdscr, username, password_db):
    menu = ['1. Add Password', '2. Retrieve Password', '3. Delete Password', '4. Logout']
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(menu):
            x = w//2 - len(row)//2
            y = h//2 - len(menu)//2 + idx
            stdscr.addstr(y, x, row)

        key = stdscr.getch()
        
        if key == ord('1'):
            addPassword(stdscr, password_db)
        elif key == ord('2'):
            retrievePassword(stdscr, password_db)
        elif key == ord('3'):
            deletePassword(stdscr, password_db)
        elif key == ord('4'):
            break

def addPassword(stdscr, password_db):
    curses.echo()
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter service/website name: ")
    service = stdscr.getstr().decode('utf-8')
    
    stdscr.addstr(1, 0, "Enter username: ")
    username = stdscr.getstr().decode('utf-8')
    
    stdscr.addstr(2, 0, "Enter password: ")
    password = stdscr.getstr().decode('utf-8')
    
    password_db.add_password(service, username, password)
    
    stdscr.addstr(3, 0, "Password added successfully!")
    stdscr.refresh()
    stdscr.getch()

def retrievePassword(stdscr, password_db):
    curses.echo()
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter service/website name to retrieve password: ")
    service = stdscr.getstr().decode('utf-8')
    
    record = password_db.retrieve_password(service)
    
    if record:
        stdscr.addstr(2, 0, f"Username: {record['username']}")
        stdscr.addstr(3, 0, f"Password: {record['password']}")
    else:
        stdscr.addstr(2, 0, "No record found.")
    
    stdscr.refresh()
    stdscr.getch()

def deletePassword(stdscr, password_db):
    curses.echo()
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter service/website name to delete: ")
    service = stdscr.getstr().decode('utf-8')
    
    success = password_db.delete_password(service)
    
    if success:
        stdscr.addstr(2, 0, "Password deleted successfully.")
    else:
        stdscr.addstr(2, 0, "No record found.")
    
    stdscr.refresh()
    stdscr.getch()

def main(stdscr):
    user_manager = UserManager('users.json')
    while True:
        key = start_screen(stdscr)
        
        if key == ord('1'):
            username = login_screen(stdscr, user_manager)
            if username:
                # Initialize the encryption manager with the user's password
                password_db = PasswordDatabase('passwords.json', EncryptionManager(user_manager.get_user_password(username)))
                mainMenu(stdscr, username, password_db)
        elif key == ord('2'):
            create_user_screen(stdscr, user_manager)
        elif key == ord('3'):
            break

if __name__ == "__main__":
    curses.wrapper(main)
