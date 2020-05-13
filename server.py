from scapy.all import *
import threading
from tunnel_utils import *
import argparse

ICMP_REQUEST_LENGTH = 100
ICMP_REPLY_CODE = 6
WRAP_END_INDEX = 42
ETHER_LEN = 14

def write_to_tunnel(server_ip, real_iface, gw_mac, packet):
    wrap_layer = Ether(dst=gw_mac) / IP(dst=server_ip) / ICMP()
    new_packet = raw(wrap_layer) + packet
    print(repr(new_packet))
    sendp(IP(new_packet), iface=real_iface)


def read_from_tunnel():
    packet = sniff(count=1, filter='icmp')[0]
    message = raw(packet)[WRAP_END_INDEX:]
    print(Ether(message))
    return message


def get_client_request(packet):
    user = packet[IP].src
    return (user, IP(raw(packet)[WRAP_END_INDEX + ETHER_LEN:]))


def send_to_user(user, packet) :
    packet[IP].dst = user
    print(repr(packet))
    send(IP(dst=user)/ICMP(code=ICMP_REPLY_CODE)/packet)

def send_request(packet):
    new_packet = IP(dst=packet[IP].dst)/packet.payload
    send(new_packet)


def main():
    while True:
        responses_queue = []
        requests_queue = []
        packets = sniff(count=1, filter='ip dst 192.168.1.164')

        for i, packet in enumerate(packets):
            if len(raw(packet)) > ICMP_REQUEST_LENGTH \
            and ICMP in packet \
            and packet[ICMP].code == 0:
                requests_queue.append(get_client_request(packets.pop(i)))
                user = requests_queue[0][0]
        responses_queue = packets

        [send_request(packet) for user, packet in requests_queue]
        [send_to_user(user, packet) for packet in responses_queue]


if __name__ == '__main__':
    main()
