import os

import pytest

from ensure_vpn import ensure_vpn, ensure_vpn_decorator
from ensure_vpn.exceptions import VPNNotConnectedException
from ensure_vpn.constants import PROTONVPN_SERVER_FILE_PATH

providers = (
    "expressvpn",
    "hidemyass",
    "hotspotshield",
    "ivpn",
    "mullvad",
    "nordvpn",
    "privateinternetaccess",
    "protonvpn",
    "surfshark",
    "vyprvpn",
)
custom_ips = ("217.138.222.100", "217.138.222.0/24")

if os.path.isfile(PROTONVPN_SERVER_FILE_PATH):
    os.remove(PROTONVPN_SERVER_FILE_PATH)


# @pytest.mark.vcr(record_mode="none")
@pytest.mark.parametrize("ip_or_provider", providers + custom_ips)
def test_disconnected(ip_or_provider: str):
    try:
        ensure_vpn(ip_or_provider)
        pytest.fail()
    except VPNNotConnectedException as e:
        assert e.actual_ip is not None


# TODO manually edit VCR cassettes to add fake responses for missing providers
@pytest.mark.vcr(record_mode="none")
@pytest.mark.parametrize("ip_or_provider", ("mullvad", "protonvpn") + custom_ips)
def test_connected(ip_or_provider: str):
    ensure_vpn(ip_or_provider)


@pytest.mark.vcr(record_mode="none")
def test_decorator():
    @ensure_vpn_decorator("mullvad")
    def func():
        return 1

    try:
        func()
        pytest.fail()
    except VPNNotConnectedException as e:
        assert e.actual_ip is not None
