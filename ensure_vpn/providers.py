import abc
import os
import json
import time

from ipaddress import IPv4Network
from os.path import isfile
from typing import List, Tuple

import requests

from returns.result import Result, safe

from .checkers import APIChecker, EnsureVPNResult, IPChecker
from .constants import (
    MULLVAD_CHECKER_URL,
    NORDVPN_CHECKER_URL,
    PROTONVPN_SERVER_URL,
    PROTONVPN_SERVER_FILE_PATH,
    USER_AGENT,
)
from .helpers import get_dict_values, is_today


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
            validation_func=lambda json: json["mullvad_exit_ip"] is True,
            ip_func=lambda json: json["ip"],
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
            validation_func=lambda json: json["status"] is True,
            ip_func=lambda json: json["ip"],
        )
        return checker.run()


class CustomVPN(VPNProvider):
    name = ""

    def __init__(self, wanted_ip: str) -> None:
        self.name = wanted_ip
        self.wanted_ip = IPv4Network(wanted_ip)

    @safe
    def validate(self) -> EnsureVPNResult:
        checker = IPChecker(validation_func=lambda ip: self.wanted_ip.overlaps(ip))
        return checker.run()


class ProtonVPN(VPNProvider):
    name = "ProtonVPN"

    @staticmethod
    def _fetch_servers() -> List[str]:
        json = requests.get(
            PROTONVPN_SERVER_URL, headers={"User-Agent": USER_AGENT}
        ).json()
        return list(get_dict_values("ExitIP", json))

    @staticmethod
    def _get_servers(fetch_servers: bool = False) -> Tuple[List[str], bool]:
        """
        Returns ProtonVPN server list from file or network
        """
        if (
            fetch_servers is True
            or not isfile(PROTONVPN_SERVER_FILE_PATH)
            or not is_today(time.ctime(os.path.getmtime(PROTONVPN_SERVER_FILE_PATH)))
        ):
            servers = ProtonVPN._fetch_servers()
            with open(PROTONVPN_SERVER_FILE_PATH, "w") as f:
                json.dump(servers, f)
            return servers, True

        return json.load(open(PROTONVPN_SERVER_FILE_PATH, "r")), False

    @staticmethod
    @safe
    def validate() -> EnsureVPNResult:
        servers, were_fetched = ProtonVPN._get_servers()
        checker = IPChecker(
            validation_func=lambda ip: str(ip.network_address) in servers
        )

        result = checker.run()
        if result.is_connected or were_fetched:
            return result

        # if the check failed with cached server file, retry with new server list
        servers, _ = ProtonVPN._get_servers(fetch_servers=True)
        return checker.run()
