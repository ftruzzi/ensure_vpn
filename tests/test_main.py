import pytest

from ensure_vpn import ensure_vpn
from ensure_vpn.exceptions import EnsureVPNException

def test_unknown_vpn():
    try:
        ensure_vpn("unknown")
        pytest.fail()
    except EnsureVPNException:
        pass

def test_no_vpn_specified():
    try:
        ensure_vpn()
        pytest.fail()
    except TypeError:
        pass