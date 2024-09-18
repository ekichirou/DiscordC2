import os
import sys

def create_folder(folder_path):
    try:
        os.makedirs(folder_path)
        return(f"[+] Folder: {folder_path} created successfully.")
    except OSError as e:
        return("Unable to create folder. %s" % e)
    except:
        return("Unexpected error:", sys.exc_info())

if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     print("Usage: python create_folder.py <folder_path>")
    #     sys.exit(1)
    global output

    folder_path = args[0]
    output = create_folder(folder_path)