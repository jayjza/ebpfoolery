import pytest
from scapy.all import *

def test_udp_unreachable(device_under_test):
    """
    This test is equivalent to the ICMP echo test done by NMAP
    """
    udp_probe_packet = (Ether() / 
                        IP (dst=str(device_under_test.IP), flags="DF") / 
                        UDP(sport=RandShort(), dport=510))

    print("Sending: {}".format(repr(udp_probe_packet)))
    resp = srp1(udp_probe_packet, iface=device_under_test.interface, timeout=1)        # TODO: Fix the interface name
    print(repr(resp))


    assert False