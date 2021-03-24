import abc

from ipaddress import IPv4Network
from typing import List

import requests

from returns.result import Result, safe

from .checkers import APIChecker, EnsureVPNResult, IPChecker
from .constants import (
    MULLVAD_CHECKER_URL,
    NORDVPN_CHECKER_URL,
    PROTONVPN_SERVER_URL,
    USER_AGENT,
)
from .helpers import get_dict_values


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
            url=MULLVAD_CHECKER_URL,
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
            url=NORDVPN_CHECKER_URL,
            params={"action": "get_user_info_data"},
            validation_func=lambda json: EnsureVPNResult(
                json["status"] is True, json["ip"]  # type: ignore
            ),
        )
        return checker.run()


class CustomVPN(VPNProvider):
    name = ""

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
            PROTONVPN_SERVER_URL, headers={"User-Agent": USER_AGENT}
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
