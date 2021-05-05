import os
import select
import socket
import struct
import sys
import time
import getopt
import signal
import threading

default_timer = time.time
ICMP_ECHO = 8
ICMP_MAX_RECV = 2048
MAX_SLEEP = 1000
COUNT = 4
result = []
threads = []


def calculate_checksum(source_string):
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2
    if countTo < len(source_string):
        loByte = source_string[len(source_string) - 1]
        sum += loByte
    sum &= 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)
    return answer


def is_valid_ip4_address(addr):
    parts = addr.split(".")
    if not len(parts) == 4:
        return False
    for part in parts:
        try:
            number = int(part)
        except ValueError:
            return False
        if number > 255 or number < 0:
            return False
    return True


def to_ip(addr):
    if is_valid_ip4_address(addr):
        return addr
    return socket.gethostbyname(addr)


class Ping(object):
    def __init__(self, destination, timeout=1000, packet_size=55):
        self.own_id = os.getpid()
        self.destination = destination
        self.timeout = timeout
        self.packet_size = packet_size

        try:
            self.dest_ip = to_ip(self.destination)
        except socket.gaierror as e:
            self.unknown_host(e)
        else:
            self.start()

        self.seq_number = 0
        self.send_count = 0
        self.receive_count = 0
        self.min_time = 999999999
        self.max_time = 0.0
        self.total_time = 0.0

    def start(self):
        msg = "ping %s (%s)" % (
            self.destination, self.dest_ip)
        print(msg)
        time.sleep(0.5)

    def unknown_host(self, e):
        msg = "\nping: Unknown host: %s (%s)\n" % (
            self.destination, e.args[1])
        print(msg)

    def log_success(self, delay, ip, packet_size, ip_header, icmp_header):
        if ip == self.destination:
            from_info = ip
        else:
            from_info = "%s (%s)" % (self.destination, ip)
        msg = "Reply from %s: time=%.1fms seq=%d" % (
            from_info, delay, icmp_header["seq_number"] + 1)
        print(msg)

    def failed(self):
        msg = "Request timed out."
        print(msg)

    def finish_ping(self):
        lost_count = self.send_count - self.receive_count
        lost_rate = float(lost_count) / self.send_count * 100.0

        msg = "<%s> -- <%d> packets transmitted, <%d> packets received, <%0.1f%%> packet loss" % (
            self.destination or self.dest_ip, self.send_count, self.receive_count, lost_rate)
        result.append(msg)

    def header2dict(self, names, struct_format, data):
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    def run(self):
        while True:
            delay = self.do()

            self.seq_number += 1
            if self.seq_number >= COUNT:
                break

            if delay == None:
                delay = 0

            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay) / 1000.0)

        self.finish_ping()

    def do(self):
        current_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        current_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        send_time = self.send_one_ping(current_socket)
        if send_time == None:
            return
        self.send_count += 1

        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_one_ping(
            current_socket)
        current_socket.close()

        if receive_time:
            self.receive_count += 1
            delay = (receive_time - send_time) * 1000.0
            self.total_time += delay
            if self.min_time > delay:
                self.min_time = delay
            if self.max_time < delay:
                self.max_time = delay

            self.log_success(delay, ip, packet_size, ip_header, icmp_header)
            return delay
        else:
            self.failed()

    def send_one_ping(self, current_socket):
        checksum = 0

        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )

        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
            padBytes += [(i & 0xff)]
        data = bytes(padBytes)

        checksum = calculate_checksum(header + data)

        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )

        packet = header + data

        send_time = default_timer()

        try:
            current_socket.sendto(packet, (self.destination, 1))
        except socket.error:
            current_socket.close()
            return

        return send_time

    def receive_one_ping(self, current_socket):
        timeout = self.timeout / 1000.0

        while True:
            select_start = default_timer()
            inputready, outputready, exceptready = select.select(
                [current_socket], [], [], timeout)
            select_duration = (default_timer() - select_start)
            if inputready == []:
                return None, 0, 0, 0, 0

            packet_data, address = current_socket.recvfrom(ICMP_MAX_RECV)

            icmp_header = self.header2dict(
                names=[
                    "type", "code", "checksum",
                    "packet_id", "seq_number"
                ],
                struct_format="!BBHHH",
                data=packet_data[20:28]
            )

            receive_time = default_timer()

            if icmp_header["packet_id"] == self.own_id:
                ip_header = self.header2dict(
                    names=[
                        "version", "type", "length",
                        "id", "flags", "ttl", "protocol",
                        "checksum", "src_ip", "dest_ip"
                    ],
                    struct_format="!BBHHHBBHII",
                    data=packet_data[:20]
                )
                packet_size = len(packet_data) - 28
                ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
                return receive_time, packet_size, ip, ip_header, icmp_header

            timeout = timeout - select_duration
            if timeout <= 0:
                return None, 0, 0, 0, 0


def ping(hostname, timeout=1000, packet_size=55, *args, **kwargs):
    p = Ping(hostname, timeout, packet_size, *args, **kwargs)
    return p.run()


def signal_handler(signal, frame):
    print("\n--------- Statistics ---------")
    for item in result:
        print(item)
    sys.exit(0)


def main(argv):
    signal.signal(signal.SIGINT, signal_handler)
    time_out = 0
    pack_size = 0
    try:
        opts, args = getopt.getopt(argv, "ht:s:", ["timeout=", "size="])
    except getopt.GetoptError:
        print('test.py -t <timeout> -s <packet_size>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('test.py -t <timeout> -s <packet_size>')
            sys.exit()
        elif opt in ("-t", "--timeout"):
            time_out = arg
        elif opt in ("-s", "--size"):
            pack_size = arg
    host = input("Enter hosts and ips: \n")
    host = host.split()
    for t in range(len(host)):
        threads.append(threading.Thread(
            target=ping, args=(host[t], time_out, pack_size, )))

    for t in range(len(host)):
        threads[t].start()

    for t in range(len(host)):
        threads[t].join()

    while True:
        time.sleep(0)
    # ping(host, timeout=time_out or 1000, packet_size=pack_size or 55)


if __name__ == "__main__":
    main(sys.argv[1:])
