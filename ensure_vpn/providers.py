import abc

from returns.result import Result, safe

from .checkers import APIChecker


class VPNProvider(abc.ABC):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Name of the VPN provider
        """
        raise NotImplementedError("Every VPN provider must have a name.")

    @staticmethod
    @abc.abstractmethod
    def validate() -> Result[bool, Exception]:
        """
        @safe-wrapped validation function that returns True/False whether or not the user is connected to the VPN provider.
        """
        raise NotImplementedError("Every VPN provider must have a validation function.")


class MullvadVPN(VPNProvider):
    name = "Mullvad"

    @staticmethod
    @safe
    def validate() -> bool:
        checker = APIChecker(
            url="https://ipv4.am.i.mullvad.net/json",
            validation_func=lambda json: json["mullvad_exit_ip"] == True,
        )
        return checker.run()


class NordVPN(VPNProvider):
    name = "NordVPN"

    @staticmethod
    @safe
    def validate() -> bool:
        checker = APIChecker(
            url="https://nordvpn.com/wp-admin/admin-ajax.php",
            params={"action": "get_user_info_data"},
            validation_func=lambda json: json["status"] == True,
        )
        return checker.run()
