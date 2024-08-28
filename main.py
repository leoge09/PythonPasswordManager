import random
import re
import sys
import curses
import json
import os
import hashlib
import string
import base64
import getpass
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class EncryptionManager:
    """
    Manages the encryption and decryption of all the data that needs to be encoded
    """
    def __init__(self, key_or_password):
        if isinstance(key_or_password, str):
            self.key = hashlib.sha256(key_or_password.encode()).digest()
        elif isinstance(key_or_password, bytes):
            self.key = key_or_password
        else:
            raise ValueError("Key or password must be a string or bytes object.")
        self.backend = default_backend()

    def encrypt(self, plainText):
        """
        Encryption with AES algorithm
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        paddedData = padder.update(plainText.encode()) + padder.finalize()

        cipherText = encryptor.update(paddedData) + encryptor.finalize()
        return base64.b64encode(iv + cipherText).decode('utf-8')

    def decrypt(self, cipherText):
        """
        Decryption
        """
        rawData = base64.b64decode(cipherText)
        iv = rawData[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        paddedPlainText = decryptor.update(rawData[16:]) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plainText = unpadder.update(paddedPlainText) + unpadder.finalize()

        return plainText.decode('utf-8')


class UserManager:
    """
    Manages most of the functions for the creation and reaching of the Users
    """
    def __init__(self, jsonFile):
        self.jsonFile = jsonFile
        if not os.path.exists(jsonFile):
            with open(jsonFile, 'w') as file:
                json.dump({}, file)
        self.users = self.loadUsers()
    
    def loadUsers(self):
        """
        Loading Users from Json file
        """
        with open(self.jsonFile, 'r') as file:
            return json.load(file)
    
    def saveUsers(self):
        """
        Saving Users in Json file
        """
        with open(self.jsonFile, 'w') as file:
            json.dump(self.users, file)
    
    def createUser(self, username, password):
        """
        Manages the creation of a new user
        """
        if username in self.users:
            return False
        
        encryptionManager = EncryptionManager(password)
        masterPassword = encryptionManager.key
        
        self.users[username] = {'masterPassword': base64.b64encode(masterPassword).decode('utf-8')}
        self.saveUsers()
        return True
    
    def authenticate(self, username, password):
        """
        checks if the user is registered
        """
        if username not in self.users:
            return False
        
        storedHash = base64.b64decode(self.users[username]['masterPassword'])
        encryptionManager = EncryptionManager(password)
        return encryptionManager.key == storedHash
    
    def getUserPassword(self, username):
        """
        gets the Masterpassword of the current user
        """
        return base64.b64decode(self.users[username]['masterPassword']) if username in self.users else None
    
class PasswordDatabase:
    """
    Mangages the passwords in the actual passwordmanager
    """
    def __init__(self, jsonFile, encryptionManager):
        self.jsonFile = jsonFile
        self.encryptionManager = encryptionManager
        if not os.path.exists(jsonFile):
            with open(jsonFile, 'w') as file:
                json.dump({}, file)
        self.passwords = self.loadPasswords()

    def loadPasswords(self):
        """
        Load the Json file for the current User
        """
        with open(self.jsonFile, 'r') as file:
            return json.load(file)

    def savePasswords(self):
        """
        Save the Json file for the current User
        """
        with open(self.jsonFile, 'w') as file:
            json.dump(self.passwords, file)

    def addPassword(self, service, username, password, note, timeNow):
        """
        Encrypts the Data for saving
        """
        encryptedPassword = self.encryptionManager.encrypt(password)
        encryptedUsername = self.encryptionManager.encrypt(username)
        encryptedService = self.encryptionManager.encrypt(service)
        encryptedTime = self.encryptionManager.encrypt(timeNow)
        self.passwords[encryptedService] = {'username': encryptedUsername, 'password': encryptedPassword, 'note': note, 'time': encryptedTime}
        self.savePasswords()

    def retrievePassword(self, service):
        """
        Decrypts and returns the data for retrieving the password, username, note and time
        """
        if service in self.passwords:
            record = self.passwords[service]
            return {
                'username': self.encryptionManager.decrypt(record['username']),
                'password': self.encryptionManager.decrypt(record['password']),
                'note':     (record['note']),
                'time':     self.encryptionManager.decrypt(record['time'])
            }
        return None
    
    def deletePassword(self, service):
        """
        Delete a password
        """
        if service in self.passwords:
            del self.passwords[service]
            self.savePasswords()
            return True
        return False
    
    def isInstance(self, service):
        """
        Checks if the service is already registered
        """
        if service in self.passwords:
            return True
        else:
            return False
    
    def getServices(self):
        """
        Returns all services in decrypted form
        """
        return [self.encryptionManager.decrypt(service) for service in self.passwords]
    
    def decryptService(self, service):
        """
        Returns one decrypted service
        """
        return self.encryptionManager.decrypt(service)
    
def addNotes(stdscr):
    """
    Adding notes to the password
    """
    menu = ["yes", "no"]
    current_row = 0
    
    while True:
        stdscr.clear()
        stdscr.addstr(0,0, "Do you want to add a note to the password?")
        h, w = stdscr.getmaxyx()

        for idx, service in enumerate(menu):
            x = w // 2 - len(service) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, service, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, service)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(menu)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(menu)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if current_row == 0:
                stdscr.clear()
                stdscr.addstr(0,0,"Note: ")
                note = stdscr.getstr().decode('utf-8')
                stdscr.refresh()
                return note
            elif current_row == 1:
                return ""      
        elif key == 27: 
            break

    return None

def customPassword(stdscr):
    curses.start_color()
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    passwordSafe = True

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Enter you´r desired password: ")
        password = stdscr.getstr().decode('utf-8')

        if passwordSafe:
            if len(password) < 8 or len(password) > 30:
                stdscr.addstr(2, 0, "A safe password should be between 8 and 20 Characters!", curses.color_pair(2))
                passwordSafe = False
            
            if not re.search(r"[A-Z]", password):
                stdscr.addstr(3, 0, "The password should contain at least one uppercase letter!", curses.color_pair(2))
                passwordSafe = False
                
            if not re.search(r"[a-z]", password):
                stdscr.addstr(4, 0, "The password should contain at least one lowercase letter!", curses.color_pair(2))
                passwordSafe = False
               
            if not re.search(r"[0-9]", password):
                stdscr.addstr(5, 0, "The password should contain at least one number!", curses.color_pair(2))
                passwordSafe = False
                
            if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                stdscr.addstr(6, 0, "The password should contain at least one special letter!", curses.color_pair(2))
                passwordSafe = False
            
            if passwordSafe:
                stdscr.addstr(3, 0, "Your password is safe and has been added successfully!")
            stdscr.getch()

        if not passwordSafe:
            current_row = 0
            menu = ['Yes', 'No']
            while True:
                stdscr.clear()
                stdscr.addstr(0, 0, "Your password is not safe, do you want to edit it with the Guidelines?")
                h, w = stdscr.getmaxyx()

                for idx, service in enumerate(menu):
                    x = w // 2 - len(service) // 2
                    y = h // 2 - len(menu) // 2 + idx
                    if idx == current_row:
                        stdscr.addstr(y, x, service, curses.A_REVERSE)
                    else:
                        stdscr.addstr(y, x, service)

                stdscr.refresh()

                key = stdscr.getch()

                if key == curses.KEY_UP:
                    current_row = (current_row - 1) % len(menu)
                elif key == curses.KEY_DOWN:
                    current_row = (current_row + 1) % len(menu)
                elif key == curses.KEY_ENTER or key in [10, 13]:
                    if current_row == 0:
                        password = safePassword(stdscr, password)
                        break
                    elif current_row == 1:
                        break
                elif key == 27: 
                    break
        
        stdscr.clear()
        return password

def safePassword(stdscr, password):

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Enter you´r desired password: ")
        password = stdscr.getstr().decode('utf-8')
        if len(password) < 8 or len(password) > 30:
            stdscr.addstr(2, 0, "The password has to be between 8 and 20 caracters! Try again")
            stdscr.getch()
            continue
        if not re.search(r"[A-Z]", password):
            stdscr.addstr(2, 0, "The password has to contain at least one uppercase letter! Try again")
            stdscr.getch()
            continue
        if not re.search(r"[a-z]", password):
            stdscr.addstr(2, 0, "The password has to contain at least one lowercase letter! Try again")
            stdscr.getch()
            continue
        if not re.search(r"[0-9]", password):
            stdscr.addstr(2, 0, "The password has to contain at least one number! Try again")
            stdscr.getch()
            continue
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            stdscr.addstr(2, 0, "The password has to contain at least one special letter! Try again")
            stdscr.getch()
            continue

        break

    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Green text on black background
    stdscr.clear()
    stdscr.addstr(2, 0, "Your password is Safe!", curses.color_pair(1))
    stdscr.getch()

    return password

    

def getTime():
    """
    Returnign time as String
    """
    time = datetime.now()
    timeString = time.strftime("%Y-%m-%d %H:%M:%S")

    return timeString

def changeInfo(stdscr, passwordDb):
    """
    Handles the modification of information and forwards to the appropriate function. 
    """
    encrypted_service = showServices(stdscr, passwordDb)
    if passwordDb.isInstance(encrypted_service):
       current_row = 0
       menu = ["Password","Username","Note","Cancel"]

       while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Which part do you want to change?")
        h, w = stdscr.getmaxyx()

        for idx, service in enumerate(menu):
            x = w // 2 - len(service) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, service, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, service)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(menu)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(menu)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if current_row == 0:
                changePassword(stdscr, passwordDb, encrypted_service)
                break
            elif current_row == 1:
                changeUsername(stdscr, passwordDb, encrypted_service)
                break
            elif current_row == 2:
                changeNote(stdscr, passwordDb, encrypted_service)
                break
            elif current_row == 3:
                break
        elif key == 27: 
            break

    return None

def changePassword(stdscr, passwordDb, service):
    """
    Changing the password
    """
    curses.echo()
    stdscr.clear()
    newPassword = customPassword(stdscr)
    decryptedService = passwordDb.decryptService(service)
    time = getTime()


    if passwordDb.isInstance(service):
        record = passwordDb.retrievePassword(service)
        passwordDb.addPassword(decryptedService, record['username'], newPassword, record['note'], time)
        passwordDb.deletePassword(service)
        stdscr.addstr(1, 0, "Password updated successfully.")
    else:
        stdscr.addstr(1, 0, "Service not found.")

    stdscr.refresh()
    stdscr.getch()

def changeUsername(stdscr, passwordDb, service):
    """
    Changes the Username
    """
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter new username: ")
    new_username = stdscr.getstr().decode('utf-8')
    decryptedService = passwordDb.decryptService(service)
    time = getTime()

    if passwordDb.isInstance(service):
        record = passwordDb.retrievePassword(service)
        passwordDb.addPassword(decryptedService, new_username, record['password'], record['note'], time)
        passwordDb.deletePassword(service)
        stdscr.addstr(1, 0, "Username updated successfully.")
    else:
        stdscr.addstr(1, 0, "Service not found.")

    stdscr.refresh()
    stdscr.getch()

def changeNote(stdscr, passwordDb, service):
    """
    Changes the note
    """
    curses.echo()
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter new note: ")
    new_note = stdscr.getstr().decode('utf-8')
    decryptedService = passwordDb.decryptService(service)
    time = getTime()

    if passwordDb.isInstance(service):
        record = passwordDb.retrievePassword(service)
        passwordDb.addPassword(decryptedService, record['username'], record['password'], new_note, time)
        passwordDb.deletePassword(service)
        stdscr.addstr(1, 0, "Note updated successfully.")
    else:
        stdscr.addstr(1, 0, "Service not found.")

    stdscr.refresh()
    stdscr.getch()


def passwordSelector(stdscr):
    """
    Handles the basics of automatic password creation
    """
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "How many characters should your password include? (8-30)")
        stdscr.refresh()

        try:
            length = int(stdscr.getstr().decode('utf-8'))
            if 8 <= length <= 30:
                break 
            else:
                stdscr.addstr(2, 0, "Please enter a number between 8 and 20.")
        except ValueError:
            stdscr.addstr(2, 0, "Invalid input. Please enter a number.")
        
        stdscr.refresh()
        stdscr.getch() 

    current_row = 0
    stdscr.clear()
    menu = ["Strong Password", "Medium Password"]

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, service in enumerate(menu):
            x = w // 2 - len(service) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, service, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, service)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(menu)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(menu)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            return passwordGenerator(current_row, length)
        elif key == 27: 
            break

    return None

def passwordGenerator(safetyLevel, length):
    """
    Generates the automatic password
    """
    if safetyLevel == 0:
        caracters = string.ascii_letters + string.digits + string.punctuation
    
    elif safetyLevel == 1:
        caracters = string.ascii_letters + string.digits

    else:
        return None
    
    password = ''.join(random.choice(caracters) for _ in range(length))
    return password
    

def showServices(stdscr, passwordDb):
    """
    shows the services that are registered
    """
    services = passwordDb.getServices()
    encrypted_services = list(passwordDb.passwords.keys())
    current_row = 0

    if len(encrypted_services) < 1 :
        stdscr.clear()
        stdscr.addstr(0,0, "No passwords registered! Add one and try again.")
        stdscr.refresh()
        stdscr.getch()
        return None

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
    """
    Starting screen
    """
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
        elif key == 27:  
            break

    return None


def loginScreen(stdscr, userManager):
    """
    Login screen
    """
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
    """
    Create user screen
    """
    curses.echo()
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Enter your desired username: ")
        username = stdscr.getstr().decode('utf-8')
        if len(username) < 1 :
            stdscr.clear()
            stdscr.addstr(0,0, "Your username has to have at least one letter! Try again")
            stdscr.getch()
            continue

        password = customPassword(stdscr)
        break

    if userManager.createUser(username, password):
        stdscr.addstr(3, 0, "User created successfully! Press any key to login.")
    else:
        stdscr.addstr(3, 0, "User creation failed (username might already exist). Press any key to return to the main menu.")
    
    stdscr.refresh()
    stdscr.getch()


def mainMenu(stdscr, userName, passwordDb):
    """
    Main menu screen
    """
    menu = ['Add Password', 'Retrieve Password', 'Delete Password', 'Change Info', 'Logout']
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
                changeInfo(stdscr, passwordDb)
            elif current_row == 4:
                break
        elif key == 27:  # Escape key
            break


def addPassword(stdscr, passwordDb):
    """
    Handles the creation of a new password
    """
    curses.echo()
    
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Enter service/website: ")
        service = stdscr.getstr().decode('utf-8')
        if len(service) < 1 :
            stdscr.clear()
            stdscr.addstr(0,0, "Your service has to have at least one letter! Try again")
            stdscr.getch()
            continue
        break

    services = passwordDb.getServices() 
    if service in services:
        current_row = 0
        menu = ["Yes", "No"]
        while True:
            stdscr.clear()
            stdscr.addstr(1, 0, "This Service is already Registered! Do you want to Change the info?")
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
                    changeInfo(stdscr, passwordDb)
                    return
                elif current_row == 1:
                    stdscr.clear()
                    return
            elif key == 27:  # Escape key
                break
 
    while True:
        stdscr.addstr(0, 0, "Enter your desired username: ")
        username = stdscr.getstr().decode('utf-8')
        if len(username) < 1 :
            stdscr.clear()
            stdscr.addstr(0,0, "Your username has to have at least one letter! Try again")
            stdscr.getch()
            continue
        break
    
    passwordMenu = ["Enter Custom Password", "Generate Password"]
    current_row = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(passwordMenu):
            x = w // 2 - len(row) // 2
            y = h // 2 - len(passwordMenu) // 2 + idx
            if idx == current_row:
                stdscr.addstr(y, x, row, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, row)

        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            current_row = (current_row - 1) % len(passwordMenu)
        elif key == curses.KEY_DOWN:
            current_row = (current_row + 1) % len(passwordMenu)
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if current_row == 0:
                password = customPassword(stdscr)
                break
            elif current_row == 1:
                password = passwordSelector(stdscr)
                break
        elif key == 27:  # Escape key
            break
    
    note = addNotes(stdscr)

    timeNow = getTime()
    
    passwordDb.addPassword(service, username, password, note, timeNow)
    stdscr.clear()
    stdscr.addstr(2,0, f"The password '{password}' for '{service}' has been added successfully!")
    stdscr.refresh()
    stdscr.getch()


def retrievePassword(stdscr, passwordDb):
    """
    Retrieving the password
    """
    service = showServices(stdscr, passwordDb)

    if service:
        record = passwordDb.retrievePassword(service)
        stdscr.clear()
        if record:
            stdscr.addstr(1, 0, f"Username: {record['username']}")
            stdscr.addstr(2, 0, f"Password: {record['password']}")
            stdscr.addstr(3, 0, f"Note:     {record['note']}")
            stdscr.addstr(5, 0, f"Creation/changing date: {record['time']}")
        else:
            stdscr.addstr(0, 0, "No record found.")
            stdscr.addstr(1, 0, service)
        stdscr.refresh()
        stdscr.getch()


def deletePassword(stdscr, passwordDb):
    """
    Deleting a password"""
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
    """
    Main function
    """
    userManager = UserManager('users.json')
    while True:
        option = startScreen(stdscr)
        
        if option == 0:
            username = loginScreen(stdscr, userManager)
            if username:
                passwordDb = PasswordDatabase(f'{username}_passwords.json', EncryptionManager(userManager.getUserPassword(username)))
                mainMenu(stdscr, username, passwordDb)
        elif option == 1:
            createUserScreen(stdscr, userManager)
        elif option == 2:
            break


if __name__ == "__main__":
    curses.wrapper(main)
