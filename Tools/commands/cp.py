import shutil,sys

def copy_file(file_from, file_to):
    try:
        shutil.copy(file_from, file_to)
        return (f"[+] Copied file: {file_from} to {file_to}.")
    except IOError as e:
        return ("Unable to copy file. %s" % e)
    except:
        return ("Unexpected error:", sys.exc_info())


if __name__ == "__main__":
    global output
    file_from = args[0]
    file_to = args[1]

    output = copy_file(file_from, file_to)