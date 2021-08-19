import web3
from pathlib import Path

def ipc(method, params=None):
    # put whatever path your trin ipc file is located at
    ipc_path = Path("/tmp/trin-jsonrpc.ipc")
    ipc_provider = web3.IPCProvider(ipc_path)
    ipc_w3 = web3.Web3(ipc_provider)
    return ipc_provider.make_request(method, params)

print(ipc('discv5_nodeInfo'))
