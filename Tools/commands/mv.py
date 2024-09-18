import shutil,sys

def move_file(file_from, file_to):
    try:
        shutil.move(file_from, file_to)
        return (f"[+] Moved file: {file_from} to {file_to}.")
    except IOError as e:
        return ("Unable to move file. %s" % e)
    except:
        return ("Unexpected error:", sys.exc_info())


if __name__ == "__main__":
    global output
    file_from = args[0]
    file_to = args[1]

    output = move_file(file_from, file_to)