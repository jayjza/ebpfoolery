import pytest
# import nmap
import ipaddress


# Local Imports


from . import common


def pytest_addoption(parser):
    parser.addoption(
        "--device-under-test",
        action="store",
        type=ipaddress.ip_address,
        help="IP address of the device under test")



@pytest.fixture(scope="session")
def device_under_test(request):
    device_ip = request.config.getoption('--device-under-test')

    dut = common.DUT(
        IP=device_ip
    )

    yield dut