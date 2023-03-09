#!/usr/bin/python3
import network_scanner

ns = network_scanner.Network_Scanner()
addr = ns.get_addr()
clients_discovered = ns.scan(addr)
ns.print_clients_discovered(clients_discovered)