from ipaddress import IPv4Network


class EnsureVPNException(Exception):
    pass


class VPNNotConnectedException(EnsureVPNException):
    def __init__(self, message: str, actual_ip: IPv4Network = None):
        super().__init__(message)
        self.actual_ip = actual_ip
