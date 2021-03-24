import abc

from ipaddress import IPv4Network
from json import JSONDecodeError
from typing import Any, Callable, Union

import requests
from requests.exceptions import RequestException

from .constants import IP_CHECKERS, USER_AGENT


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
        validation_func: Callable[[Any], bool],
        ip_func: Callable[[Any], str],
        **request_args,
    ):
        """requests-based checker that performs HTTP requests.

        Args:
            url (str): URL to perform a GET request to
            request_args (dict): args passed to requests.request call
            validation_func (Callable[[Any], bool]): checks response to validate connection
            ip_func (Callable[[Any], str]): retrieves actual IP from response
        """
        self.url = url
        self.request_args = request_args
        self.validation_func = validation_func
        self.ip_func = ip_func

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
            EnsureVPNResult: contains check result and actual IP
        """
        response = APIChecker._get_response(
            self.session.request(method="GET", url=self.url, **self.request_args)
        )

        return EnsureVPNResult(
            is_connected=self.validation_func(response),
            actual_ip=self.ip_func(response),
        )


class IPChecker(VPNChecker):
    def __init__(
        self,
        *,
        validation_func: Callable[[IPv4Network], bool],
    ):
        self.ip_checkers = IP_CHECKERS
        self.validation_func = validation_func

    def run(self) -> EnsureVPNResult:
        actual_ip = None
        while actual_ip is None:
            try:
                actual_ip = (
                    APIChecker(
                        url=f"https://{self.ip_checkers[0]}",
                        headers={"User-Agent": "curl/7.75"},
                        validation_func=lambda x: x,
                        ip_func=lambda x: x.strip(),
                    )
                    .run()
                    .actual_ip
                )
            except RequestException:
                self.ip_checkers = self.ip_checkers[1:]

        return EnsureVPNResult(
            is_connected=self.validation_func(actual_ip), actual_ip=actual_ip
        )
