import socket
import argparse
import os
os.sys.path.append('/usr/lib/python3/dist-packages')
import threading
import re
import subprocess
from scapy.all import *
from scapy.layers.inet import *

BUFFER = 4096
WRAP_END_INDEX = 43


def get_mac(ip_address):
    responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src
    return None

def get_gw(device):
    route_result = subprocess.run(["ip", "r"], stdout=subprocess.PIPE).stdout.decode('utf-8')
    print(route_result)
    ip = re.findall('default via ([0-9\.]+) dev {0}'.format(device), str(route_result))[0]
    return ip


def write_to_tunnel(server_ip, real_iface, gw_mac, packet):
    wrap_layer = Ether(dst=gw_mac)/IP(src='192.168.1.154', dst=server_ip) / ICMP()
    new_packet = raw(wrap_layer) + packet
    sendp(IP(new_packet), iface=real_iface)


def read_from_tunnel(real_iface):
    packet = sniff(count=1, filter='icmp', iface=real_iface)[0]
    message = raw(packet)[WRAP_END_INDEX:]
    print(repr(Ether(message)))
    return message

def write_to_virtual_interface(tunnel_iface, packet):
    sendp(Ether(packet), iface=tunnel_iface)


def get_args():
    parser = argparse.ArgumentParser(description='connects to a icmp-tunnel server.')
    parser.add_argument('server_ip', type=str)
    parser.add_argument('tunnel_iface', type=str)
    parser.add_argument('real_iface', type=str)
    return parser.parse_args()


def get_packet(tunnel_iface):
    packet = sniff(count=1, iface=tunnel_iface)[0]
    return raw(packet)


def main():
    args = get_args()
    gw_ip = get_gw(args.real_iface)
    gw_mac = get_mac(gw_ip)

    while True:
        packet = get_packet(args.tunnel_iface)
        write_to_tunnel(args.server_ip, args.real_iface, gw_mac, packet)
        recv_packet = read_from_tunnel(args.real_iface)
        write_to_virtual_interface(args.tunnel_iface, recv_packet)

if __name__ == '__main__':
    main()
