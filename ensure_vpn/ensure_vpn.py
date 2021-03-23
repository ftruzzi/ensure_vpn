from ipaddress import AddressValueError

from returns.pipeline import is_successful

from .exceptions import EnsureVPNException, VPNNotConnectedException
from .providers import CustomVPN, MullvadVPN, NordVPN

providers = [CustomVPN, MullvadVPN, NordVPN]


def ensure_vpn(ip_or_provider: str) -> None:
    try:
        selected_provider = CustomVPN(ip_or_provider)
    except AddressValueError:
        selected_providers = [
            p for p in providers if p.name.lower() == ip_or_provider.strip().lower()  # type: ignore
        ]
        if len(selected_providers) != 1:
            raise EnsureVPNException(
                f"No or too many VPN providers found (results: {selected_providers})"
            )

        selected_provider = selected_providers[0]  # type: ignore

    wrapped_result = selected_provider.validate()
    if is_successful(wrapped_result):
        result = wrapped_result.unwrap()
        if result.is_connected is False:
            raise VPNNotConnectedException(
                f"You are not connected to {selected_provider.name}. Found IP: {str(result.actual_ip.network_address)}",
                actual_ip=result.actual_ip,
            )

        return

    raise wrapped_result.failure()


def ensure_vpn_decorator(provider: str):
    def _ensure_vpn_decorator(f):
        def wrapper(*args, **kwargs):
            ensure_vpn(provider)
            return f(*args, **kwargs)

        return wrapper

    return _ensure_vpn_decorator
