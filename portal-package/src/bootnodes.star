constants = import_module("./utils/constants.star")
trin = import_module("./trin/trin_launcher.star")
fluffy = import_module("./fluffy/fluffy_launcher.star")
enr_utils = import_module("./utils/enr.star")

def launch(
    plan,
    bootnodes,
):
    num_bootnodes = len(bootnodes)
    plan.print("Launching {} bootnodes".format(num_bootnodes))

    launchers = {
        constants.CLIENT_TYPE.trin: trin.launch,
        constants.CLIENT_TYPE.fluffy: fluffy.launch,
    }

    all_contexts = []
    bootnode_enrs = []
    bootnodes_flag = "none"
    for index, bootnode in enumerate(bootnodes):
        client_type = bootnode.client_type
        launch_method = launchers[client_type]

        service_name = "bootnode-{}-{}".format(client_type, index)
        context = launch_method(
            plan,
            service_name,
            bootnode.image,
            bootnode.private_key,
            bootnode.min_cpu,
            bootnode.max_cpu,
            bootnode.min_mem,
            bootnode.max_mem,
            bootnodes_flag,
        )
        all_contexts.append(context)
        enr = enr_utils.get_enr_for_node(plan, service_name, "http")
        plan.print("ENR for node '{}': {}".format(service_name, enr))
        bootnode_enrs.append(enr)
        bootnodes_flag = ",".join(bootnode_enrs)

    plan.print("Successfully launched {} bootnodes".format(num_bootnodes))
    plan.print("CLI flag for all bootnodes: {}".format(bootnodes_flag))

    if len(bootnode_enrs) == 0:
        bootnode_enrs = "none"
    else:
        bootnode_enrs = ",".join(bootnode_enrs)
    return (all_contexts, bootnode_enrs)
