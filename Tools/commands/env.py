import os

def get_environment_variables():
    return dict(os.environ)

if __name__ == "__main__":
    global output
    environment_variables = get_environment_variables()
    output = ('\n'.join([f"{key}: {value}" for key, value in environment_variables.items()]))