ENSURE_VPN_VERSION = "0.2.0"
USER_AGENT = f"ensure_vpn-v{ENSURE_VPN_VERSION} github.com/ftruzzi/ensure_vpn/"

MULLVAD_CHECKER_URL = "https://ipv4.am.i.mullvad.net/json"
NORDVPN_CHECKER_URL = "https://nordvpn.com/wp-admin/admin-ajax.php"
PROTONVPN_SERVER_URL = "https://api.protonmail.ch/vpn/logicals"

IP_CHECKERS = [
    "ifconfig.me",
    "icanhazip.com",
    "ipinfo.io/ip",
    "api.ipify.org",
    "ident.me",
]
