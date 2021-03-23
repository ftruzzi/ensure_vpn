import abc
from ipaddress import IPv4Network

from requests.exceptions import RequestException
from returns.result import Result, safe

from .checkers import APIChecker, EnsureVPNResult


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
        result = None
        while result is None:
            try:
                checker = APIChecker(
                    url=f"https://{self.ip_checkers[0]}",
                    headers={"User-Agent": "curl/7.75"},
                    validation_func=lambda actual_ip: EnsureVPNResult(
                        is_connected=IPv4Network(self.wanted_ip).overlaps(
                            IPv4Network(actual_ip.strip())
                        ),
                        actual_ip=actual_ip.strip(),
                    ),
                )
                result = checker.run()
            except RequestException:
                self.ip_checkers = self.ip_checkers[1:]

        return result
