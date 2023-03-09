#!/usr/bin/python3

# Author: Chris Martinez
# Version: 1.0
# Date: 5 March 2023
# Description: Customize network scanner modeled after netdiscover

"""Command Line Customize Network Scanner.
This module scans the current network for clients similar to netdiscover:
    - Obtains address from user via command line (-a or --addr)
    - Handles command line args no provided or incomplete
    - Uses the modules: argparse, scapy, warnings (to filter deprecated warnings)

Simple usage example below::

    ns = network_scanner.Network_Scanner()
    addr = ns.get_addr()
    clients_discovered = ns.scan(addr)
    ns.print_clients_discovered(clients_discovered)

"""

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import argparse
import subprocess
import scapy.all as scapy


class Network_Scanner:
    # ========================
    # Class Attributes
    # ========================
    addr = ""

    # ========================
    # Constructors
    # ========================
    def __init__(self, addr="10.0.2.0/24"):
          self.addr = addr

    # ========================
    # Methods
    # ========================
    def get_addr(self):
        """Gets argument from the command line: addr
        returns the ip or ip range to be searched
        """
        parser = argparse.ArgumentParser()
        parser.add_argument("-a", "--addr", dest="addr", help="IP Address to be scanned")
        args = parser.parse_args()

        if not args.addr:
            parser.error("[-] Must specifiy ip address to be scanned, use --help for more info")
        
        self.addr = args.addr

        return self.addr

    @staticmethod
    def scan(ip):
        """Scans ip or ip range for clients
        returns a list of dictionaries containing discovered clients; key=="ip", value=="mac"
        """
        arp_request = scapy.ARP(pdst=ip) 
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast/arp_request
        answered = scapy.srp(arp_req_broadcast, timeout=1)[0]
        clients_discovered = [{"ip": ans[1].psrc, "mac": ans[1].hwsrc} for ans in answered]
        
        return clients_discovered

    @staticmethod
    def print_clients_discovered(clients_discovered):
        """Prints out discovered clients
        Expects a list of dictionaries as the input; the return value of scan()
        """
        print("IP\t\t\tMAC Address")
        print("-----------------------------------------")

        for client in clients_discovered:
            print(f'{client["ip"]}\t\t{client["mac"]}')
