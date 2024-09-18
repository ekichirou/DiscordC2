import os

def show_current_directory():
    current_directory = os.getcwd()
    return(f"[+] Working directory: {current_directory}")

if __name__ == "__main__":
    global output
    output = show_current_directory()