import os, clr
clr.AddReference('System.IO')
from System import IO

def list_files_and_folders_in_directory(directory):
    entries = IO.Directory.GetFileSystemEntries(directory)
    return entries

def list_files(directory):
    if not os.path.exists(directory):
        raise FileNotFoundError(f"```Directory '{directory}' does not exist.```")
    
    entries = list_files_and_folders_in_directory(directory)
    entries_str = "\n".join(entries)
    
    return entries_str

if __name__ == "__main__":
    global output
    directory = args[0]
    output = list_files(directory)
    pass