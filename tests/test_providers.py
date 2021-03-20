import pytest

from ensure_vpn import ensure_vpn, ensure_vpn_decorator
from ensure_vpn.exceptions import VPNNotConnectedException

providers = ("mullvad", "nordvpn")

@pytest.mark.vcr(record_mode="none")
@pytest.mark.parametrize("provider", providers)
def test_disconnected(provider: str):
    try:
        ensure_vpn(provider)
        pytest.fail()
    except VPNNotConnectedException:
        pass

# TODO play with VCR to add fake NordVPN response
@pytest.mark.vcr(record_mode="none")
@pytest.mark.parametrize("provider", ["mullvad"])
def test_connected(provider: str):
    ensure_vpn(provider)

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
