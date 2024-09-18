import clr
clr.AddReference('System')
from System import Environment

def whoami():
    domain = Environment.UserDomainName
    username = Environment.UserName
    return f"{domain}\\{username}"

if __name__ == '__main__':
    global output
    output = whoami()