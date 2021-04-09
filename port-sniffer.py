import socket
import re
import threading


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
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        print("Port open: " + str(port))
        s.close()
    except:
        print("Port closed: " + str(port))


done = 1
current = -1


def thread_function(host):
    global current
    current += 1
    if(current < len(ports)):
        scan(host, ports[current])
        global done
        done += 1
        if done != len(ports):
            thread_function(host)


min = 0
max = 65353
threads_count = 1000
timeout = 5
threads = []

print("Welcome!!")
print("Enter host:")
host = input()

while True:
    if check_ip(host) == False and is_valid_hostname(host) == False:
        print("Invalid host. Enter anohter: ")
        host = input()
    else:
        break

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

print("Enter timeout: (default=5sec)")
temp = input()
if temp != "":
    threads_count = int(temp)

if type != "3":
    print("Enter number of threads: (max=1000)")
    temp = input()
    if temp != "":
        if int(temp) > 1000:
            threads_count = 1000
        else:
            threads_count = int(temp)
    for t in range(threads_count):
        threads.append(threading.Thread(target=thread_function, args=(host,)))

    for t in range(threads_count):
        threads[t].start()

    for t in range(threads_count):
        threads[t].join()

else:
    while True:
        print("Enter port: ")
        port = input()
        scan(host, int(port))
