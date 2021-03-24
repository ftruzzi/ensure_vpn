import abc
import os
import json
import time
import re

from ipaddress import IPv4Address, IPv4Network
from os.path import isfile
from typing import List, Tuple
from bs4 import BeautifulSoup  # type: ignore

import requests

from .checkers import APIChecker, EnsureVPNResult, IPChecker, WebChecker
from .constants import (
    HIDEMYASS_CHECKER_URL,
    IVPN_CHECKER_URL,
    MULLVAD_CHECKER_URL,
    NORDVPN_CHECKER_URL,
    PIA_CHECKER_URL,
    PROTONVPN_SERVER_URL,
    PROTONVPN_SERVER_FILE_PATH,
    SURFSHARK_CHECKER_URL,
    USER_AGENT,
    VYPRVPN_CHECKER_URL,
)
from .helpers import get_dict_values, is_today, parse_ip_from_string


class VPNProvider(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Name of the VPN provider
        """
        raise NotImplementedError("Every VPN provider must have a name.")

    @abc.abstractmethod
    def validate(self) -> EnsureVPNResult:
        """
        IP/connection validation function.
        """
        raise NotImplementedError("Every VPN provider must have a validation function.")


class CustomVPN(VPNProvider):
    name = ""
    negated = False

    def __init__(self, wanted_ip: str) -> None:
        self.name = wanted_ip
        self.wanted_ip = IPv4Network(wanted_ip)

    def validate(self) -> EnsureVPNResult:
        checker = IPChecker(
            validation_func=lambda ip: self.wanted_ip.overlaps(IPv4Network(ip))
        )
        return checker.run()


class HideMyAssVPN(VPNProvider):
    name = "HideMyAss"

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url=HIDEMYASS_CHECKER_URL,
            validation_func=lambda json: json["isInVpnTunnel"] is True,
            ip_func=lambda _: IPChecker._get_current_ip(),
        )
        return checker.run()


class MullvadVPN(VPNProvider):
    name = "Mullvad"

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url=MULLVAD_CHECKER_URL,
            validation_func=lambda json: json["mullvad_exit_ip"] is True,
            ip_func=lambda json: IPv4Address(json["ip"]),
        )
        return checker.run()


class NordVPN(VPNProvider):
    name = "NordVPN"

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url=NORDVPN_CHECKER_URL,
            params={"action": "get_user_info_data"},
            validation_func=lambda json: json["status"] is True,
            ip_func=lambda json: IPv4Address(json["ip"]),
        )
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
    def validate() -> EnsureVPNResult:
        servers, were_fetched = ProtonVPN._get_servers()
        checker = IPChecker(validation_func=lambda ip: str(ip) in servers)

        result = checker.run()
        if result.is_connected or were_fetched:
            return result

        # if the check failed with cached server file, retry with new server list
        servers, _ = ProtonVPN._get_servers(fetch_servers=True)
        return checker.run()


class SurfsharkVPN(VPNProvider):
    name = "Surfshark"

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url=SURFSHARK_CHECKER_URL,
            validation_func=lambda json: json["secured"] is True,
            ip_func=lambda json: IPv4Address(json["ip"]),
        )
        return checker.run()


class VyprVPN(VPNProvider):
    name = "VyprVPN"

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = APIChecker(
            url=VYPRVPN_CHECKER_URL,
            validation_func=lambda json: json["connected"] is True,
            ip_func=lambda json: IPv4Address(json["ip"]),
        )
        return checker.run()


class IVPN(VPNProvider):
    name = "IVPN"

    @staticmethod
    def validation_func(soup: BeautifulSoup) -> bool:
        # TODO validate with actual IVPN connection
        text = (
            soup.select_one("div.connection-status__content span").text.strip().lower()
        )
        if "not connected" in text:
            return False

        if "connected" in text:
            return True

        return False

    @staticmethod
    def ip_func(soup: BeautifulSoup) -> IPv4Address:
        ip_el = next(
            filter(
                lambda el: "ip address" in el.text.lower(),
                soup.select("div.connection-status__content div"),
            )
        )
        ip_addr = parse_ip_from_string(ip_el.text)
        return IPv4Address(ip_addr)

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = WebChecker(
            url=IVPN_CHECKER_URL,
            validation_func=IVPN.validation_func,
            ip_func=IVPN.ip_func,
        )
        return checker.run()


class PrivateInternetAccessVPN(VPNProvider):
    name = "privateinternetaccess"

    @staticmethod
    def validation_func(soup: BeautifulSoup) -> bool:
        # TODO validate with actual IVPN connection
        text = soup.select_one(".topbar__list").text.strip().lower()
        return "not protected" not in text

    @staticmethod
    def ip_func(soup: BeautifulSoup) -> IPv4Address:
        ip_el = soup.select_one(".topbar__item-ip")
        ip_addr = parse_ip_from_string(ip_el.text)
        return IPv4Address(ip_addr)

    @staticmethod
    def validate() -> EnsureVPNResult:
        checker = WebChecker(
            url=PIA_CHECKER_URL,
            validation_func=PrivateInternetAccessVPN.validation_func,
            ip_func=PrivateInternetAccessVPN.ip_func,
        )

        return checker.run()