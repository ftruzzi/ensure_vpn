import pytest

from ensure_vpn import ensure_vpn, ensure_vpn_decorator
from ensure_vpn.exceptions import VPNNotConnectedException

providers = ("mullvad", "nordvpn", "protonvpn")
custom_ips = ("217.138.222.100", "217.138.222.0/24")

@pytest.mark.vcr(record_mode="none")
@pytest.mark.parametrize("ip_or_provider", providers + custom_ips)
def test_disconnected(ip_or_provider: str):
    try:
        ensure_vpn(ip_or_provider)
        pytest.fail()
    except VPNNotConnectedException:
        pass


# TODO play with VCR to add fake NordVPN response
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
    except VPNNotConnectedException:
        pass
