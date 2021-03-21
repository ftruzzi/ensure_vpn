import abc

from typing import Any, Callable, Dict

import requests

ENSURE_VPN_VERSION = "0.1.1"
USER_AGENT = f"ensure_vpn-v{ENSURE_VPN_VERSION} github.com/ftruzzi/ensure_vpn/"


class VPNChecker(abc.ABC):
    @abc.abstractmethod
    def run(self) -> bool:
        raise NotImplementedError("Every checker must have a `run` method.")


class APIChecker(VPNChecker):
    """
    requests-based checker that performs HTTP requests.
    """

    def __init__(
        self,
        *,
        url: str,
        validation_func: Callable[[Dict[Any, Any]], bool],
        **request_args,
    ):
        """requests-based checker that performs HTTP requests.

        Args:
            url (str): URL to perform a GET request to
            request_args (dict): args passed to requests.request call
            validation_func (Callable[[Dict[Any, Any]], bool]): function that validates the fetched JSON response
        """
        self.url = url
        self.request_args = request_args
        self.validation_func = validation_func

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    @staticmethod
    def _get_json_response(response: requests.Response) -> dict:
        response.raise_for_status()
        return response.json()

    def run(self) -> bool:
        """Runs checker, fetching and validating data

        Returns:
            bool: return value of validation function
        """
        response = APIChecker._get_json_response(
            self.session.request(method="GET", url=self.url, **self.request_args)
        )
        return self.validation_func(response)
