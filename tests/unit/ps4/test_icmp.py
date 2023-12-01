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
                         ICMP(type=8, code=9, seq = 295) /
                         ("\x00"*120)
                         )

    print("Sending: {}".format(repr(icmp_probe_packet)))
    resp = srp1(icmp_probe_packet, iface=device_under_test.interface, timeout=1)        # TODO: Fix the interface name
    print(repr(resp))


    assert IP in resp, "No IP layer found in response"
    assert ICMP in resp, "NO ICMP layer found in response"
    assert resp[IP].ttl == 64, "Incorrect TTL in IP packet"
    assert resp[IP].flags == 0, "Incorrect flags set in IP packet"
    # assert resp[IP].len == 28, "Incorrect length of IP reply"         # This should actually be 28 (no payload, when looking at a win2016 server)
    assert resp[ICMP].type == 0, "Incorrect ICMP response type"
    assert resp[ICMP].code == 9, "Incorrect ICMP response code"
    assert resp[ICMP].seq == 295, "Incorrect ICMP sequence number"


    icmp_probe_packet = (Ether() / 
                         IP (dst=str(device_under_test.IP), flags="DF", tos=4) / 
                         ICMP(type=8, code=0, seq = 296) /
                         ("\x00"*150)
                         )

    print("Sending: {}".format(repr(icmp_probe_packet)))
    resp = srp1(icmp_probe_packet, iface=device_under_test.interface, timeout=1)        # TODO: Fix the interface name
    print(repr(resp))

    assert IP in resp, "No IP layer found in response"
    assert ICMP in resp, "NO ICMP layer found in response"
    assert resp[IP].ttl == 128, "Incorrect TTL in IP packet"
    assert resp[IP].flags == 0, "Incorrect flags set in IP packet"
    # assert resp[IP].len == 28, "Incorrect length of IP reply"         # This should actually be 28 (no payload, when looking at a win2016 server)
    assert resp[ICMP].type == 0, "Incorrect ICMP response type"
    assert resp[ICMP].code == 0, "Incorrect ICMP response code"
    assert resp[ICMP].seq == 296, "Incorrect ICMP sequence number"

    