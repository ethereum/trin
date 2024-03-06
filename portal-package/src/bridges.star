constants = import_module("./utils/constants.star")
bridge_launcher = import_module("./bridge/bridge_launcher.star")
trin = import_module("./trin/trin_launcher.star")
fluffy = import_module("./fluffy/fluffy_launcher.star")

def launch(
    plan,
    bridges,
    bootnode_enrs
):
    num_bridges = len(bridges)
    plan.print("Launching {} bridges".format(num_bridges))
    launchers = {
        constants.CLIENT_TYPE.bridge: bridge_launcher.launch,
    }

    all_contexts = []
    for index, bridge in enumerate(bridges):
        client_type = bridge.client_type
        launch_method = launchers[client_type]

        service_name = "bridge-{}-{}".format(client_type, index)
        context = launch_method(
            plan,
            service_name,
            bridge.image,
            bridge.mode,
            bridge.private_key,
            bridge.min_cpu,
            bridge.max_cpu,
            bridge.min_mem,
            bridge.max_mem,
            bootnode_enrs
        )
        all_contexts.append(context)
    plan.print("Successfully launched network with {} bridges".format(num_bridges))
    return all_contexts
