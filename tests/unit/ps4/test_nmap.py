import nmap

def test_nmap_OS_scan(device_under_test):
    nm = nmap.PortScanner()
    result = nm.scan(str(device_under_test.IP), arguments='-O')
    assert result['scan']['192.168.31.158']['osmatch'][0]['osclass'][0] == {
        'type': 'general purpose', 'vendor': 'Microsoft',
        'osfamily': 'Windows', 'osgen': '2016', 'accuracy': '99',
        'cpe': ['cpe:/o:microsoft:windows_server_2016']}