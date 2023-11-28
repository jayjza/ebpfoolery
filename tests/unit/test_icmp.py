# # from scapy import send, IP, ICMP
# from scapy.all import *

# def test_icmp():
#     # resp = send(IP(dst="192.168.31.1")/ICMP())
#     ans, unans = sr(IP(dst="192.168.31.0/24")/ICMP(), timeout=3)
#     import pdb; pdb.set_trace()



import pytest
from scapy.all import *

def test_icmp_echo_response(device_under_test):
    """
    This test is equivalent to the ICMP echo test done by NMAP
    """
    icmp_probe_packet = (Ether() / 
                         IP (dst=str(device_under_test.IP), flags="DF") / 
                         ICMP(type=8, code=9, seq = 295))

    print("Sending: {}".format(repr(icmp_probe_packet)))
    resp = srp1(icmp_probe_packet, iface="ens192", timeout=1)        # TODO: Fix the interface name
    print(repr(resp))


    icmp_probe_packet = (Ether() / 
                         IP (dst=str(device_under_test.IP), flags="DF", tos=4) / 
                         ICMP(type=8, code=0, seq = 296))

    print("Sending: {}".format(repr(icmp_probe_packet)))
    resp = srp1(icmp_probe_packet, iface="ens192", timeout=1)        # TODO: Fix the interface name
    print(repr(resp))

    assert False