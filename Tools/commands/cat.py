
def read_file_contents(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            contents = file.read()
            return contents
    except FileNotFoundError:
        return f"Error: File '{file_path}' not found."

if __name__ == "__main__":
    global output
    file_path = args[0]
    output = read_file_contents(file_path)
    pass