from ebpforgery import forge_ippers
# from scapy import Ether, IP, UDP
from scapy.all import *

def test_udp_unreachable():
    pkt = Ether() / IP(dst='127.0.0.1') / UDP(dport=12345)