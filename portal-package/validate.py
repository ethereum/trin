from web3 import Web3
from eth_utils import to_hex
import sys

# list all the http ports from participant services
ports = [
    53167,
    53792,
    53834,
]

# expected content keys from bridge mode "single:b1"
# expected_keys = [
    # '0x0088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6',
    # '0x0188e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6',
    # skip receipts since they're empty ("0x")
    # '0x0288e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6',
    # '0x035ec1ffb8c3b146f42606c74ced973dc16ec5a107c0345858c343fc94780b4218'
# ]


missing_keys = False

for port in ports:
    w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}"))
    for key in expected_keys:
        req = w3.provider.make_request("portal_historyLocalContent", [key])
        if req["result"] == "0x":
            print(f"Key {key} not found on port {port}")
            missing_keys = True

# if missing_keys:
    # print("Some keys are missing, see above logs")
# else:
    # print("All expected keys found")

