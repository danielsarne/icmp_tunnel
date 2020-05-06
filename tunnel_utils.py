import socket
from scapy.layers.inet import IP, ICMP
from scapy.all import send, raw, sniff
from scapy.all import *

BUFFER = 4096
WRAP_END_INDEX = 29
def write_to_tunnel(server_ip, packet):
    wrap_layer = IP(dst=server_ip) / ICMP()
    packet = raw(wrap_layer) + packet
    send(IP(packet))

def read_from_tunnel(tunnel_socket, real_iface):
    packet = sniff(count=1, filter='icmp', iface=real_iface)
    message = raw(packet)[WRAP_END_INDEX:]
    return message

def get_mac(ip_address):
    responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2, retry=10)
    for s,r in responses:
        return r[Ether].src
    return None
