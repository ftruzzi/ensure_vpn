import abc
from ipaddress import IPv4Network

from json import JSONDecodeError
from typing import Any, Callable, Union

import requests

ENSURE_VPN_VERSION = "0.2.0"
USER_AGENT = f"ensure_vpn-v{ENSURE_VPN_VERSION} github.com/ftruzzi/ensure_vpn/"


class EnsureVPNResult:
    def __init__(self, is_connected: bool, actual_ip: Union[str, IPv4Network]):
        self.is_connected = is_connected
        if isinstance(actual_ip, str):
            actual_ip = IPv4Network(actual_ip)
        self.actual_ip = actual_ip


class VPNChecker(abc.ABC):
    @abc.abstractmethod
    def run(self) -> EnsureVPNResult:
        raise NotImplementedError("Every checker must have a `run` method.")


class APIChecker(VPNChecker):
    """
    requests-based checker that performs HTTP requests.
    """

    def __init__(
        self,
        *,
        url: str,
        validation_func: Callable[[Any], EnsureVPNResult],
        **request_args,
    ):
        """requests-based checker that performs HTTP requests.

        Args:
            url (str): URL to perform a GET request to
            request_args (dict): args passed to requests.request call
            validation_func (Callable[[str, dict], EnsureVPNResult]): function that validates the fetched text/JSON response
        """
        self.url = url
        self.request_args = request_args
        self.validation_func = validation_func

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    @staticmethod
    def _get_response(response: requests.Response) -> Union[dict, str]:
        response.raise_for_status()
        try:
            return response.json()
        except JSONDecodeError:
            return response.text

    def run(self) -> EnsureVPNResult:
        """Runs checker, fetching and validating data

        Returns:
            EnsureVPNResult: return value of validation function
        """
        response = APIChecker._get_response(
            self.session.request(method="GET", url=self.url, **self.request_args)
        )
        return self.validation_func(response)
