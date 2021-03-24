import abc
from ipaddress import IPv4Network
from typing import List
import requests

from requests.exceptions import RequestException
from returns.result import Result, safe

from .checkers import APIChecker, EnsureVPNResult, IPChecker, USER_AGENT


def get_dict_values(key, d):
    if not d:
        return None
    if hasattr(d, "items"):
        for k, v in d.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                for result in get_dict_values(key, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in get_dict_values(key, d):
                        yield result


class VPNProvider(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Name of the VPN provider
        """
        raise NotImplementedError("Every VPN provider must have a name.")

    @abc.abstractmethod
    def validate(self) -> Result[EnsureVPNResult, Exception]:
        """
        @safe-wrapped validation function.
        """
        raise NotImplementedError("Every VPN provider must have a validation function.")


class MullvadVPN(VPNProvider):
    name = "Mullvad"

    @staticmethod
    @safe
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url="https://ipv4.am.i.mullvad.net/json",
            validation_func=lambda json: EnsureVPNResult(
                json["mullvad_exit_ip"] is True, json["ip"]  # type: ignore
            ),
        )
        return checker.run()


class NordVPN(VPNProvider):
    name = "NordVPN"

    @staticmethod
    @safe
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url="https://nordvpn.com/wp-admin/admin-ajax.php",
            params={"action": "get_user_info_data"},
            validation_func=lambda json: EnsureVPNResult(
                json["status"] is True, json["ip"]  # type: ignore
            ),
        )
        return checker.run()


class CustomVPN(VPNProvider):
    name = ""
    ip_checkers = [
        "ifconfig.me",
        "icanhazip.com",
        "ipinfo.io/ip",
        "api.ipify.org",
        "ident.me",
    ]

    def __init__(self, wanted_ip: str) -> None:
        self.name = wanted_ip
        self.wanted_ip = IPv4Network(wanted_ip)

    @safe
    def validate(self) -> EnsureVPNResult:
        checker = IPChecker(
            validation_func=lambda actual_ip: EnsureVPNResult(
                is_connected=IPv4Network(self.wanted_ip).overlaps(
                    IPv4Network(actual_ip.strip())
                ),
                actual_ip=actual_ip.strip(),
            ),
        )

        return checker.run()


class ProtonVPN(VPNProvider):
    name = "ProtonVPN"

    # TODO cache results, re-fetch if failed
    @staticmethod
    def _fetch_servers() -> List[str]:
        return requests.get(
            "https://api.protonmail.ch/vpn/logicals", headers={"User-Agent": USER_AGENT}
        ).json()

    @staticmethod
    @safe
    def validate() -> EnsureVPNResult:
        servers = ProtonVPN._fetch_servers()
        checker = IPChecker(
            validation_func=lambda actual_ip: EnsureVPNResult(
                is_connected=actual_ip.strip()
                in list(get_dict_values("ExitIP", servers)),
                actual_ip=actual_ip.strip(),
            )
        )

        return checker.run()
