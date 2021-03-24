import os

ENSURE_VPN_VERSION = "0.4.0"
USER_AGENT = f"ensure_vpn-v{ENSURE_VPN_VERSION} github.com/ftruzzi/ensure_vpn/"

HIDEMYASS_CHECKER_URL = "https://my.hidemyass.com/vpnbackend/isInVpnTunnel"
MULLVAD_CHECKER_URL = "https://ipv4.am.i.mullvad.net/json"
NORDVPN_CHECKER_URL = "https://nordvpn.com/wp-admin/admin-ajax.php"
PROTONVPN_SERVER_URL = "https://api.protonmail.ch/vpn/logicals"
PROTONVPN_SERVER_FILE_PATH = os.path.join(
    os.path.dirname(__file__), "proton_servers.json"
)

IP_CHECKERS = [
    "ifconfig.me",
    "icanhazip.com",
    "ipinfo.io/ip",
    "api.ipify.org",
    "ident.me",
]
