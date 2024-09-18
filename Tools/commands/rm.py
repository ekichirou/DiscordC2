import os
import shutil
import sys

def delete_file(file_path):
    try:
        os.remove(file_path)
        return(f"[+] File {file_path} has deleted successfully.")
    except OSError as e:
        return("Unable to delete file. %s" % e)
    except:
        return("Unexpected error:", sys.exc_info())

def delete_folder(folder_path):
    try:
        shutil.rmtree(folder_path)
        return(f"[+] Folder {folder_path} has deleted successfully.")
    except OSError as e:
        return("Unable to delete folder. %s" % e)
    except:
        return("Unexpected error:", sys.exc_info())

if __name__ == "__main__":
    # if len(sys.argv) < 2:
    #     print("Usage:")
    #     print("To delete file: python delete.py <file_path>")
    #     print("To delete folder: python delete.py <folder_path>")
    #     sys.exit(1)
    global output
    path = args[0]

    if os.path.isfile(path):
        output =  delete_file(path)
    elif os.path.isdir(path):
        output =  delete_folder(path)
    else:
        output =  print("Path does not exist or is not a file or folder.")