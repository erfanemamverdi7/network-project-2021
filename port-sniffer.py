import socket
import re

print("Welcome!!")

def check_ip(Ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

    if(re.search(regex, Ip)):
        return True
    else:
        return False


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def scan(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        print("Port open: " + str(port))
        s.close()
    except:
        print("Port closed: " + str(port))

print("Enter host:")
host = input()	

min = 0
max = 65353

ports = []

print("Enter call type: ")
print("1. all ports ")
print("2. reserved ports ")
print("3. question ")
type = input()

while True:
    if check_ip(host) == False and is_valid_hostname(host) == False:
        print("Invalid host. Enter anohter: ")
        host = input()
    else:
        break

if type == '1':
    ports = list(range(min, max + 1))
if type == '2':
    print("Enter min port: ")
    min = int(input())
    print("Enter max port: ")
    max = int(input())
    ports = list(range(min, max + 1))

for port in range(ports):
    scan(host, int(port))    