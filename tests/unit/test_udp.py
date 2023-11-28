import pytest
from scapy.all import *

def test_udp_unreachable(device_under_test):
    """
    This test is equivalent to the ICMP echo test done by NMAP
    """
    udp_probe_packet = (Ether() / 
                        IP (dst=str(device_under_test.IP), flags="DF") / 
                        UDP(sport=RandShort(), dport=510) /
                        ('\x43'*300)
                        )

    print("Sending: {}".format(repr(udp_probe_packet)))
    resp = srp1(udp_probe_packet, iface=device_under_test.interface, timeout=1)        # TODO: Fix the interface name
    print(repr(resp))

    assert IP in resp, "No IP layer found in response"
    assert ICMP in resp, "NO ICMP layer found in response"
    assert resp[IP].ttl == 128, "Incorrect TTL in IP packet"
    assert resp[IP].flags == 0, "Incorrect flags set in IP packet"
    assert resp[IP].len == 356, "Incorrect length of IP reply"         # This should actually be 28 (no payload, when looking at a win2016 server)
    assert resp[ICMP].type == 3, "Incorrect ICMP response type"
    assert resp[ICMP].code == 3, "Incorrect ICMP response code"

    assert IPerror in resp, "Original IP payload not included in ICMP response"
    assert UDPerror in resp, "Original UDP payload not included in ICMP response"
