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

    parser.addoption(
        "--interface",
        action="store",
        default="ens160",
        help="Interface to send the packets out")


@pytest.fixture(scope="session")
def device_under_test(request):
    # device_ip = request.config.getoption('--device-under-test')

    dut = common.DUT(
        IP=request.config.getoption('--device-under-test'),
        interface=request.config.getoption('--interface'),
    )

    yield dut