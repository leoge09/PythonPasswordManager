import sys
import curses
from database import PasswordDatabase
from encryption import EncryptionManager

def mainMenu(stdscr):
    stdscr.clear()
    
    # Initialisiere den EncryptionManager und die PasswordDatabase
    encryption_manager = EncryptionManager(master_password="YourMasterPassword")  # Master-Passwort sollte sicherer gehandhabt werden
    db = PasswordDatabase(encryption_manager)

    menu = ['1. Add Password', '2. Retrieve Password', '3. Delete Password', '4. Exit']
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(menu):
            x = w // 2 - len(row) // 2
            y = h // 2 - len(menu) // 2 + idx
            stdscr.addstr(y, x, row)

        key = stdscr.getch()
        
        if key == ord('1'):
            addPassword(stdscr, db)
        elif key == ord('2'):
            retrievePassword(stdscr, db)
        elif key == ord('3'):
            deletePassword(stdscr, db)
        elif key == ord('4'):
            break
    
    stdscr.refresh()
    stdscr.getch()

def addPassword(stdscr, db):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter the site:")
    curses.echo()
    site = stdscr.getstr(1, 0).decode('utf-8')
    
    stdscr.addstr(2, 0, "Enter the username:")
    username = stdscr.getstr(3, 0).decode('utf-8')
    
    stdscr.addstr(4, 0, "Enter the password:")
    password = stdscr.getstr(5, 0).decode('utf-8')
    
    db.add_password(site, username, password)
    
    stdscr.clear()
    stdscr.addstr(0, 0, "Password added successfully!")
    stdscr.refresh()
    stdscr.getch()

def retrievePassword(stdscr, db):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter the site:")
    curses.echo()
    site = stdscr.getstr(1, 0).decode('utf-8')
    
    password = db.retrieve_password(site)
    
    stdscr.clear()
    if password:
        stdscr.addstr(0, 0, f"Password for {site}: {password}")
    else:
        stdscr.addstr(0, 0, "Site not found!")
    stdscr.refresh()
    stdscr.getch()

def deletePassword(stdscr, db):
    stdscr.clear()
    stdscr.addstr(0, 0, "Enter the site:")
    curses.echo()
    site = stdscr.getstr(1, 0).decode('utf-8')
    
    if db.delete_password(site):
        stdscr.addstr(2, 0, "Password deleted successfully!")
    else:
        stdscr.addstr(2, 0, "Site not found!")
    stdscr.refresh()
    stdscr.getch()

if __name__ == "__main__":
    curses.wrapper(mainMenu)
