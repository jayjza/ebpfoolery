import time
import pytest
import struct
from scapy.all import *

def current_milli_time():
    # return round(time.time() * 1000)
    return time.time_ns() / 1000000

# Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted. The window field is 1.

# Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL. The window field is 63.

# Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640). The window field is 4.

# Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 4.

# Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 16.

# Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field is 512.

sequence_probes = [
    pytest.param(           # Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted. The window field is 1.
        1,  # Window Field
        [   # TCP Options
            ('WScale', 10),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 1460)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
        ],
        {
            'IP' : {

            },
            'TCP' : {
                'window': 8192,
                'flags': 'SA',
                'options': [('MSS', 1460), ('NOP', None), ('WScale', 8), ('SAckOK', b'')],
            }
        },
        id='Packet_1'
    ),
    pytest.param(           # Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL. The window field is 63.
        63,  # Window Field
        [   # TCP Options
            ('MSS', struct.pack('>H', 1400)),
            ('WScale', 0),
            ('SAckOK', b''),
            ('Timestamp', (4294967295, 0)),
            ('EOL', b''),
        ],
        {
            'IP' : {

            },
            'TCP' : {
                'window': 8192,
                'flags': 'SA',
                'options': [('MSS', 1460), ('NOP', None), ('WScale', 8), ('SAckOK', b'')],
            }
        },
        id='Packet_2'
    ),
    pytest.param(           # Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640). The window field is 4.
        4,  # Window Field
        [   # TCP Options
            ('Timestamp', (4294967295, 0)),
            ('NOP', b''),
            ('NOP', b''),
            ('WScale', 5),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 640)),
        ],
        {
            'IP' : {

            },
            'TCP' : {
                'window': 8192,
                'flags': 'SA',
                'options': [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None)],
            }
        },
        id='Packet_3'
    ),
    pytest.param(           # Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 4.
        4,  # Window Field
        [   # TCP Options
            ('SAckOK', b''),
            ('Timestamp', (4294967295, 0)),
            ('WScale', 10),
            ('EOL', b''),
        ],
        {
            'IP' : {

            },
            'TCP' : {
                'window': 8192,
                'flags': 'SA',
                'options': [('MSS', 1460), ('NOP', None), ('WScale', 8), ('SAckOK', b'')],
            }
        },
        id='Packet_4'
    ),
    pytest.param(           # Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 16.
        16,  # Window Field
        [   # TCP Options
            ('MSS', struct.pack('>H', 536)),
            ('SAckOK', b''),
            ('Timestamp', (4294967295, 0)),
            ('WScale', 10),
            ('EOL', b''),
        ],
        {
            'IP' : {

            },
            'TCP' : {
                'window': 8192,
                'flags': 'SA',
                'options': [('MSS', 1460), ('NOP', None), ('WScale', 8), ('SAckOK', b'')],
            }
        },
        id='Packet_5'
    ),
    pytest.param(           # Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field is 512.
        512,  # Window Field
        [   # TCP Options
            ('MSS', struct.pack('>H', 265)),
            ('SAckOK', b''),
            ('Timestamp', (4294967295, 0)),
        ],
        {
            'IP' : {

            },
            'TCP' : {
                'window': 8192,
                'flags': 'SA',
                'options': [('MSS', 1460), ('SAckOK', b'')],
            }
        },
        id='Packet_6'
    ),
]

@pytest.mark.parametrize('window_field, tcp_options, response', sequence_probes)
def test_nmap_sequence_generation(device_under_test, window_field, tcp_options, response):
    """
    This test sends a sequence probe the same as nmap does and check that the response is correct
    """
    tcp_probe_packet = Ether() / IP (dst=str(device_under_test.IP)) / TCP(sport=RandShort(), dport=12345, flags='S', window=window_field, options=tcp_options)

    print("Sending: {}".format(repr(tcp_probe_packet)))
    timestamp = current_milli_time()
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert IP in resp, "No IP layer found in response"
    assert TCP in resp, "No TCP layer found in response"

    for field, value in response['TCP'].items():
        if field == 'Timestamp':
            assert resp[TCP].getfieldval(field) == timestamp
        else:
            assert resp[TCP].getfieldval(field) == value


def test_nmap_T2(device_under_test):
    """
    Tests NMAP T2 response.
    T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
        window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted
    """
    tcp_options = [
            ('WScale', 10),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 265)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
    ]

    tcp_probe_packet = (
        Ether() /
        IP (dst=str(device_under_test.IP),
            flags="DF") /
        TCP(sport=RandShort(),
            dport=12345,
            flags=0,
            window=128,
            options=tcp_options)
    )

    print("Sending: {}".format(repr(tcp_probe_packet)))
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert resp is None, "Excpected no response but received {}".format(repr(resp))

def test_nmap_T3(device_under_test):
    """
    Tests NMAP T3 response.
    T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.
        window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted
    """
    tcp_options = [
            ('WScale', 10),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 265)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
    ]

    tcp_probe_packet = (
        Ether() /
        IP (dst=str(device_under_test.IP)) /
        TCP(sport=RandShort(),
            dport=12345,
            flags="SFUP",
            window=256,
            options=tcp_options)
    )

    print("Sending: {}".format(repr(tcp_probe_packet)))
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert resp is None, "Excpected no response but received {}".format(repr(resp))

def test_nmap_T4(device_under_test):
    """
    Tests NMAP T4 response.
    T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
        window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted
    """
    tcp_options = [
            ('WScale', 10),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 265)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
    ]

    tcp_probe_packet = (
        Ether() /
        IP (dst=str(device_under_test.IP),
            flags="DF") /
        TCP(sport=RandShort(),
            dport=12345,
            flags='A',
            window=1024,
            options=tcp_options)
    )

    print("Sending: {}".format(repr(tcp_probe_packet)))
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert resp is None, "Excpected no response but received {}".format(repr(resp))

def test_nmap_T5(device_under_test):
    """
    Tests NMAP T5 response.
    T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
        window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted
    """
    tcp_options = [
            ('WScale', 10),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 265)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
    ]

    tcp_probe_packet = (
        Ether() /
        IP (dst=str(device_under_test.IP)) /
        TCP(sport=RandShort(),
            dport=12345,
            flags='A',
            window=31337,
            options=tcp_options)
    )

    print("Sending: {}".format(repr(tcp_probe_packet)))
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert IP in resp, "No IP layer found in response"
    assert TCP in resp, "No TCP layer found in response"

    assert resp[IP].ttl == 128, "Incorrect TTL"
    assert resp[IP].flags == "DF", "Incorrect IP Flags"
    assert resp[TCP].window == 0, "Incorrect TCP Window"
    assert resp[TCP].seq == 0, "Incorrect TCP Sequence"
    assert resp[TCP].flags == "RA", "Incorect TCP Flags"

def test_nmap_T6(device_under_test):
    """
    Tests NMAP T6 response.
    T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.


        window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted
    """
    tcp_options = [
            ('WScale', 10),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 265)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
    ]

    tcp_probe_packet = (
        Ether() /
        IP (dst=str(device_under_test.IP),
            flags="DF") /
        TCP(sport=RandShort(),
            dport=12345,
            flags='A',
            window=32768,
            options=tcp_options)
    )

    print("Sending: {}".format(repr(tcp_probe_packet)))
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert resp is None, "Excpected no response but received {}".format(repr(resp))

def test_nmap_T7(device_under_test):
    """
    Tests NMAP T7 response.
    T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port. The IP DF bit is not set.
        window scale (10), NOP, MSS (265), Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted
    """
    tcp_options = [
            ('WScale', 15),
            ('NOP', b''),
            ('MSS', struct.pack('>H', 265)),
            ('Timestamp', (4294967295, 0)),
            ('SAckOK', b''),
    ]

    tcp_probe_packet = (
        Ether() /
        IP (dst=str(device_under_test.IP)) /
        TCP(sport=RandShort(),
            dport=12345,
            flags='FPU',
            window=65535,
            options=tcp_options)
    )

    print("Sending: {}".format(repr(tcp_probe_packet)))
    resp = srp1(tcp_probe_packet, iface=device_under_test.interface, timeout=1)
    print(repr(resp))

    assert resp is None, "Excpected no response but received {}".format(repr(resp))
