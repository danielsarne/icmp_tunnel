from scapy.all import *
from tunnel_utils import *
import argparse

ICMP_REQUEST_LENGTH = 60
ICMP_REPLY_CODE = 6
WRAP_END_INDEX = 43
ETHER_LEN = 14

def write_to_tunnel(server_ip, real_iface, gw_mac, packet):
    wrap_layer = Ether(dst=gw_mac) / IP(src='192.168.1.154', dst=server_ip) / ICMP()
    new_packet = raw(wrap_layer) + packet
    sendp(IP(new_packet), iface=real_iface)


def read_from_tunnel(real_iface):
    packet = sniff(count=1, filter='icmp', iface=real_iface)[0]
    message = raw(packet)[WRAP_END_INDEX:]
    print(repr(Ether(message)))
    return message


def get_args():
    parser = argparse.ArgumentParser(description='a proxy server that handles icmp tunnel requests.')
    parser.add_argument('real_iface', type=str)
    return parser


def get_client_request(real_iface):
    while True:
        packet = sniff(count=1, iface=real_iface, filter='icmp')[0]
        if len(raw(packet)) > ICMP_REQUEST_LENGTH and packet[ICMP].code == 0:
            user = packet[IP].src
            return (user, IP(raw(packet)[WRAP_END_INDEX + ETHER_LEN:]))

def get_response(request):
    request[IP].src = '192.168.1.154'
    responses, un = sr(request)
    return [response[1] for response in responses]

def send_to_user(user, packets) :
    for packet in packets:
        packet[IP].dst = user
        send(IP(src='192.168.1.154', dst=user)/ICMP(code=ICMP_REPLY_CODE)/packet)



def main():
    args = get_args()
    while True:
        user, request = get_client_request(args.real_iface)
        response_packets = get_response(request)
        send_to_user(user, response_packets)

if __name__ == '__main__':
    main()
