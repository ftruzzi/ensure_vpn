A Python function to ensure you are connected to your favorite VPN before running your script or function. It just raises an exception if you're not connected.

## Supported VPN providers
- Mullvad (`"mullvad"`)
- NordVPN (`"nordvpn"`)
- Custom IP

Add your own!

## Installation
```
pip install ensure-vpn
```

## Usage

Import the function and run it as the first thing in your script:

```python
from ensure_vpn import ensure_vpn

ensure_vpn("mullvad") # raises VPNNotConnectedException if you're not connected.

# rest of your script goes here
```

You can also use a custom IP or subnet:
```python
ensure_vpn("2.235.200.110") # or e.g. "2.235.200.0/24"
```

You can also use the decorator to run the check every time before running a specific function. This is to make sure you don't run untrusted code if you lose your VPN connection after starting your program.

Note that this can be resource intensive depending on how often you call your function so it may slow down your program considerably or get you rate-limited by the services used by this script.

```python
from ensure_vpn import ensure_vpn_decorator

@ensure_vpn_decorator("nordvpn")
def do_stuff():
    # ...

do_stuff() # VPN is checked every time you call do_stuff
```
