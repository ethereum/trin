constants = import_module("./utils/constants.star")
trin = import_module("./trin/trin_launcher.star")
fluffy = import_module("./fluffy/fluffy_launcher.star")

def launch(
    plan,
    participants,
    bootnode_enrs,
):
    num_participants = len(participants)
    plan.print("Launching network with {} participants".format(num_participants))

    launchers = {
        constants.CLIENT_TYPE.trin: trin.launch,
        constants.CLIENT_TYPE.fluffy: fluffy.launch,
        # constants.CLIENT_TYPE.ultralight: ultralight.launch,
    }

    all_contexts = []
    for index, participant in enumerate(participants):
        client_type = participant.client_type
        # if client_type not in launchers:
            # raise Exception("Unrecognized client type '{0}'".format(client_type))
        launch_method = launchers[client_type]

        service_name = "participant-{}-{}".format(client_type, index)
        context = launch_method(
            plan,
            service_name,
            participant.image,
            participant.private_key,
            participant.min_cpu,
            participant.max_cpu,
            participant.min_mem,
            participant.max_mem,
            bootnode_enrs
        )
        all_contexts.append(context)
    plan.print("Successfully launched network with {} participants".format(num_participants))
    return all_contexts
