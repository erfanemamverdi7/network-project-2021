import socket
print("Welcome!!")

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