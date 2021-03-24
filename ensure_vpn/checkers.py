import abc

from ipaddress import IPv4Address, IPv4Network
from json import JSONDecodeError
from typing import Any, Callable, Union

import requests

from bs4 import BeautifulSoup  # type: ignore
from requests.exceptions import RequestException

from .constants import IP_CHECKERS, USER_AGENT


class EnsureVPNResult:
    def __init__(self, is_connected: bool, actual_ip: Union[str, IPv4Address]):
        self.is_connected = is_connected
        if isinstance(actual_ip, str):
            actual_ip = IPv4Address(actual_ip)
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
        ip_func: Callable[[Any], IPv4Address],
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
        validation_func: Callable[[IPv4Address], bool],
    ):
        self.validation_func = validation_func

    @staticmethod
    def _get_current_ip() -> IPv4Address:
        ip_checkers = IP_CHECKERS

        actual_ip = None
        while actual_ip is None:
            try:
                actual_ip = (
                    APIChecker(
                        url=f"https://{ip_checkers[0]}",
                        headers={"User-Agent": "curl/7.75"},
                        validation_func=lambda x: x,
                        ip_func=lambda x: x.strip(),
                    )
                    .run()
                    .actual_ip
                )
                return actual_ip

            except RequestException:
                ip_checkers = ip_checkers[1:]

    def run(self) -> EnsureVPNResult:
        actual_ip = IPChecker._get_current_ip()
        return EnsureVPNResult(
            is_connected=self.validation_func(actual_ip), actual_ip=actual_ip
        )


class WebChecker(VPNChecker):
    """
    BeautifulSoup-based checker for website parsing.
    """

    def __init__(
        self,
        *,
        url: str,
        validation_func: Callable[[BeautifulSoup], bool],
        ip_func: Callable[[BeautifulSoup], IPv4Address],
        **request_args,
    ):
        """BeautifulSoup-based checker for website parsing.

        Args:
            url (str): URL to perform a GET request to
            request_args (dict): args passed to requests.request call
            validation_func (Callable[[BeautifulSoup], bool]): checks soup to validate connection
            ip_func (Callable[[BeautifulSoup], str]): retrieves actual IP from soup
        """
        self.url = url
        self.request_args = request_args
        self.validation_func = validation_func
        self.ip_func = ip_func

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def run(self) -> EnsureVPNResult:
        """Runs checker, fetching and validating data

        Returns:
            EnsureVPNResult: contains check result and actual IP
        """
        soup = BeautifulSoup(
            APIChecker._get_response(
                self.session.request(method="GET", url=self.url, **self.request_args)
            ), features="html.parser"
        )

        return EnsureVPNResult(
            is_connected=self.validation_func(soup),
            actual_ip=self.ip_func(soup),
        )
