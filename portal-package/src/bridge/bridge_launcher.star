constants = import_module("../utils/constants.star")

def launch(
    plan,
    service_name,
    image,
    mode,
    private_key,
    min_cpu,
    max_cpu,
    min_mem,
    max_mem,
    bootnode_enrs,
):
    secrets = read_file("../../.secrets.json")
    secrets = json.decode(secrets)

    bridge = plan.add_service(
        name = service_name,
        config =  ServiceConfig(
            image = image,
            ports = {
                "utp": PortSpec(
                    number = 9009,
                    transport_protocol = "UDP",
                    wait = "15s"
                )
            },
            env_vars = {
                "RUST_LOG": "info,portal_bridge=debug,surf=warn",
                "PANDAOPS_CLIENT_ID": secrets["PANDAOPS_CLIENT_ID"],
                "PANDAOPS_CLIENT_SECRET": secrets["PANDAOPS_CLIENT_SECRET"],
                "BASE_EL_ENDPOINT": "https://reth-lighthouse.mainnet.na1.ethpandaops.io/",
            },
            min_cpu = min_cpu,
            max_cpu = max_cpu,
            min_memory = min_mem,
            max_memory = max_mem,
            private_ip_address_placeholder = constants.PRIVATE_IP_ADDRESS_PLACEHOLDER,
            entrypoint = [
                "/usr/bin/portal-bridge",
                "--node-count=1",
                "--executable-path=/usr/bin/trin",
                "--epoch-accumulator-path=./portal-accumulators",
                "--network=history",
                "--external-ip={}".format(constants.PRIVATE_IP_ADDRESS_PLACEHOLDER),
                "--bootnodes={}".format(bootnode_enrs),
                "--mode={}".format(mode),
                "trin"
            ],
        ),
    )

    return bridge
