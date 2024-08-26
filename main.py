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
        encryptedService = self.encryptionManager.encrypt(service)
        self.passwords[encryptedService] = {'username': encryptedUsername, 'password': encryptedPassword}
        self.savePasswords()

    def retrievePassword(self, service):
        
        if service in self.passwords:
            record = self.passwords[service]
            return {
                'username': self.encryptionManager.decrypt(record['username']),
                'password': self.encryptionManager.decrypt(record['password'])
            }
        return None
    
    def deletePassword(self, service):
        encrypted_service = self.encryptionManager.encrypt(service)
        if encrypted_service in self.passwords:
            del self.passwords[encrypted_service]
            self.savePasswords()
            return True
        return False
    
    def getServices(self):
        return [self.encryptionManager.decrypt(service) for service in self.passwords]


def showServices(stdscr, passwordDb):
    services = passwordDb.getServices()
    encrypted_services = list(passwordDb.passwords.keys())
    current_row = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, service in enumerate(services):
            x = w // 2 - len(service) // 2
            y = h // 2 - len(services) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, service, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, service)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(services)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(services)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            return encrypted_services[current_row]
        elif key == 27: 
            break

    return None


def startScreen(stdscr):
    menu = ["1. Login", "2. Create a new user", "3. Exit"]
    current_row = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(menu):
            x = w // 2 - len(row) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, row, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, row)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(menu)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(menu)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            return current_row
        elif key == 27:  # Escape key
            break

    return None


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
    current_row = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(menu):
            x = w // 2 - len(row) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, row, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, row)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(menu)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(menu)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if current_row == 0:
                addPassword(stdscr, passwordDb)
            elif current_row == 1:
                retrievePassword(stdscr, passwordDb)
            elif current_row == 2:
                deletePassword(stdscr, passwordDb)
            elif current_row == 3:
                break
        elif key == 27:  # Escape key
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
    service = showServices(stdscr, passwordDb)

    if service:
        record = passwordDb.retrievePassword(service)
        stdscr.clear()
        if record:
            stdscr.addstr(1, 0, f"Username: {record['username']}")
            stdscr.addstr(2, 0, f"Password: {record['password']}")
        else:
            stdscr.addstr(0, 0, "No record found.")
            stdscr.addstr(1, 0, service)
        stdscr.refresh()
        stdscr.getch()


def deletePassword(stdscr, passwordDb):
    service = showServices(stdscr, passwordDb)

    if service:
        success = passwordDb.deletePassword(service)
        stdscr.clear()
        if success:
            stdscr.addstr(0, 0, "Password deleted successfully.")
        else:
            stdscr.addstr(0, 0, "No record found.")
        stdscr.refresh()
        stdscr.getch()


def main(stdscr):
    userManager = UserManager('users.json')
    while True:
        option = startScreen(stdscr)
        
        if option == 0:
            username = loginScreen(stdscr, userManager)
            if username:
                passwordDb = PasswordDatabase('passwords.json', EncryptionManager(userManager.getUserPassword(username)))
                mainMenu(stdscr, username, passwordDb)
        elif option == 1:
            createUserScreen(stdscr, userManager)
        elif option == 2:
            break


if __name__ == "__main__":
    curses.wrapper(main)
