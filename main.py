import sys
import curses
import json
import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class EncryptionManager:
    def __init__(self, key_or_password):
        if isinstance(key_or_password, str):
            self.key = hashlib.sha256(key_or_password.encode()).digest()
        elif isinstance(key_or_password, bytes):
            self.key = key_or_password
        else:
            raise ValueError("Key or password must be a string or bytes object.")
        self.backend = default_backend()

    def encrypt(self, plainText):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        paddedData = padder.update(plainText.encode()) + padder.finalize()

        cipherText = encryptor.update(paddedData) + encryptor.finalize()
        return base64.b64encode(iv + cipherText).decode('utf-8')

    def decrypt(self, cipherText):
        rawData = base64.b64decode(cipherText)
        iv = rawData[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        paddedPlainText = decryptor.update(rawData[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plainText = unpadder.update(paddedPlainText) + unpadder.finalize()

        return plainText.decode('utf-8')


class UserManager:
    def __init__(self, jsonFile):
        self.jsonFile = jsonFile
        if not os.path.exists(jsonFile):
            with open(jsonFile, 'w') as file:
                json.dump({}, file)
        self.users = self.loadUsers()
    
    def loadUsers(self):
        with open(self.jsonFile, 'r') as file:
            return json.load(file)
    
    def saveUsers(self):
        with open(self.jsonFile, 'w') as file:
            json.dump(self.users, file)
    
    def createUser(self, username, password):
        if username in self.users:
            return False
        
        encryptionManager = EncryptionManager(password)
        masterPassword = encryptionManager.key
        
        self.users[username] = {'masterPassword': base64.b64encode(masterPassword).decode('utf-8')}
        self.saveUsers()
        return True
    
    def authenticate(self, username, password):
        if username not in self.users:
            return False
        
        storedHash = base64.b64decode(self.users[username]['masterPassword'])
        encryptionManager = EncryptionManager(password)
        return encryptionManager.key == storedHash
    
    def getUserPassword(self, username):
        return base64.b64decode(self.users[username]['masterPassword']) if username in self.users else None
    
    


class PasswordDatabase:
    def __init__(self, jsonFile, encryptionManager):
        self.jsonFile = jsonFile
        self.encryptionManager = encryptionManager
        if not os.path.exists(jsonFile):
            with open(jsonFile, 'w') as file:
                json.dump({}, file)
        self.passwords = self.loadPasswords()

    def loadPasswords(self):
        with open(self.jsonFile, 'r') as file:
            return json.load(file)

    def savePasswords(self):
        with open(self.jsonFile, 'w') as file:
            json.dump(self.passwords, file)

    def addPassword(self, service, username, password):
        encryptedPassword = self.encryptionManager.encrypt(password)
        encryptedUsername = self.encryptionManager.encrypt(username)
        self.passwords[service] = {'username': encryptedUsername, 'password': encryptedPassword}
        self.savePasswords()

    def retrievePassword(self, service):
        if service in self.passwords:
            record = self.passwords[service]
            record['password'] = self.encryptionManager.decrypt(record['password'])
            record['username'] = self.encryptionManager.decrypt(record['username'])
            return record
        return None
    
    def deletePassword(self, service):
        if service in self.passwords:
            del self.passwords[service]
            self.savePasswords()
            return True
        return False


def startScreen(stdscr):
    stdscr.clear()
    stdscr.addstr(0, 0, "Welcome to the Password Manager")
    stdscr.addstr(2, 0, "1. Login")
    stdscr.addstr(3, 0, "2. Create a new user")
    stdscr.addstr(4, 0, "3. Exit")
    stdscr.refresh()
    return stdscr.getch()


def loginScreen(stdscr, userManager):
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter your username: ")
    username = stdscr.getstr().decode('utf-8')

    stdscr.addstr(1, 0, "Enter your password: ")
    password = stdscr.getstr().decode('utf-8')

    if userManager.authenticate(username, password):
        return username
    else:
        stdscr.addstr(3, 0, "Invalid credentials. Press any key to return to the main menu.")
        stdscr.refresh()
        stdscr.getch()
        return None


def createUserScreen(stdscr, userManager):
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter your desired username: ")
    username = stdscr.getstr().decode('utf-8')

    stdscr.addstr(1, 0, "Enter your desired password: ")
    password = stdscr.getstr().decode('utf-8')

    if userManager.createUser(username, password):
        stdscr.addstr(3, 0, "User created successfully! Press any key to login.")
    else:
        stdscr.addstr(3, 0, "User creation failed (username might already exist). Press any key to return to the main menu.")
    
    stdscr.refresh()
    stdscr.getch()


def mainMenu(stdscr, userName, passwordDb):
    menu = ['1. Add Password', '2. Retrieve Password', '3. Delete Password', '4. Logout']
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(menu):
            x = w // 2 - len(row) // 2
            y = h // 2 - len(menu) // 2 + idx
            stdscr.addstr(y, x, row)

        key = stdscr.getch()
        
        if key == ord('1'):
            addPassword(stdscr, passwordDb)
        elif key == ord('2'):
            retrievePassword(stdscr, passwordDb)
        elif key == ord('3'):
            deletePassword(stdscr, passwordDb)
        elif key == ord('4'):
            break


def addPassword(stdscr, passwordDb):
    curses.echo()
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter service/website name: ")
    service = stdscr.getstr().decode('utf-8')
    
    stdscr.addstr(1, 0, "Enter username: ")
    username = stdscr.getstr().decode('utf-8')
    
    stdscr.addstr(2, 0, "Enter password: ")
    password = stdscr.getstr().decode('utf-8')
    
    passwordDb.addPassword(service, username, password)
    
    stdscr.addstr(3, 0, "Password added successfully!")
    stdscr.refresh()
    stdscr.getch()


def retrievePassword(stdscr, passwordDb):
    curses.echo()
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter service/website name to retrieve password: ")
    service = stdscr.getstr().decode('utf-8')
    
    record = passwordDb.retrievePassword(service)
    
    if record:
        stdscr.addstr(2, 0, f"Username: {record['username']}")
        stdscr.addstr(3, 0, f"Password: {record['password']}")
    else:
        stdscr.addstr(2, 0, "No record found.")
    
    stdscr.refresh()
    stdscr.getch()


def deletePassword(stdscr, passwordDb):
    curses.echo()
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter service/website name to delete: ")
    service = stdscr.getstr().decode('utf-8')
    
    success = passwordDb.deletePassword(service)
    
    if success:
        stdscr.addstr(2, 0, "Password deleted successfully.")
    else:
        stdscr.addstr(2, 0, "No record found.")
    
    stdscr.refresh()
    stdscr.getch()


def main(stdscr):
    userManager = UserManager('users.json')
    while True:
        key = startScreen(stdscr)
        
        if key == ord('1'):
            username = loginScreen(stdscr, userManager)
            if username:
                passwordDb = PasswordDatabase('passwords.json', EncryptionManager(userManager.getUserPassword(username)))
                mainMenu(stdscr, username, passwordDb)
        elif key == ord('2'):
            createUserScreen(stdscr, userManager)
        elif key == ord('3'):
            break


if __name__ == "__main__":
    curses.wrapper(main)
