import sys
import curses

def main_menu(stdscr):
    # Clear screen
    stdscr.clear()
    
    menu = ['1. Add Password', '2. Retrieve Password', '3. Delete Password', '4. Exit']
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        for idx, row in enumerate(menu):
            x = w//2 - len(row)//2
            y = h//2 - len(menu)//2 + idx
            stdscr.addstr(y, x, row)

        key = stdscr.getch()
        
        if key == ord('1'):
            add_password(stdscr)
        elif key == ord('2'):
            retrieve_password(stdscr)
        elif key == ord('3'):
            delete_password(stdscr)
        elif key == ord('4'):
            break
    
    stdscr.refresh()
    stdscr.getch()

def add_password(stdscr):
    # Placeholder for adding password functionality
    stdscr.clear()
    stdscr.addstr(0, 0, "Add Password functionality not implemented yet.")
    stdscr.refresh()
    stdscr.getch()

def retrieve_password(stdscr):
    # Placeholder for retrieving password functionality
    stdscr.clear()
    stdscr.addstr(0, 0, "Retrieve Password functionality not implemented yet.")
    stdscr.refresh()
    stdscr.getch()

def delete_password(stdscr):
    # Placeholder for deleting password functionality
    stdscr.clear()
    stdscr.addstr(0, 0, "Delete Password functionality not implemented yet.")
    stdscr.refresh()
    stdscr.getch()

if __name__ == "__main__":
    curses.wrapper(main_menu)
