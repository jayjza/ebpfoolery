import nmap

def test_nmap_OS_scan(device_under_test):
    nm = nmap.PortScanner()
    result = nm.scan(str(device_under_test.IP), arguments='-O')
    assert result['scan']['192.168.31.158']['osmatch'][0]['osclass'][0]['vendor'] == 'Microsoft'
    assert result['scan']['192.168.31.158']['osmatch'][0]['osclass'][0]['osgen'] == '2016'
    assert result['scan']['192.168.31.158']['osmatch'][0]['osclass'][0]['osfamily'] == 'Windows'
    assert result['scan']['192.168.31.158']['osmatch'][0]['osclass'][0]['cpe'] == ['cpe:/o:microsoft:windows_server_2016']