# from scapy import send, IP, ICMP
from scapy.all import *

def test_icmp():
    # resp = send(IP(dst="192.168.31.1")/ICMP())
    ans, unans = sr(IP(dst="192.168.31.0/24")/ICMP(), timeout=3)
    import pdb; pdb.set_trace()