from returns.pipeline import is_successful

from .exceptions import EnsureVPNException, VPNNotConnectedException
from .providers import MullvadVPN, NordVPN

providers = [MullvadVPN, NordVPN]


def ensure_vpn(provider: str) -> None:
    selected_providers = [
        p for p in providers if p.name.lower() == provider.strip().lower()  # type: ignore
    ]
    if len(selected_providers) != 1:
        raise EnsureVPNException(
            f"No or too many VPN providers found (results: {selected_providers})"
        )

    selected_provider = selected_providers[0]
    wrapped_result = selected_provider.validate()
    if is_successful(wrapped_result):
        result = wrapped_result.unwrap()
        if result == False:
            raise VPNNotConnectedException(
                f"You are not connected to {selected_provider.name}."
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
