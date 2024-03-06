participants = import_module("./src/participants.star")
bridges = import_module("./src/bridges.star")
bootnodes = import_module("./src/bootnodes.star")
glados = import_module("./src/glados.star")
input_parser = import_module("./src/utils/input_parser.star")
prometheus = import_module("./src/prometheus/prometheus_launcher.star")
grafana = import_module("./src/grafana/grafana_launcher.star")

def run(plan, args={}):
    args_with_right_defaults = input_parser.input_parser(plan, args)

    num_bridges = len(args_with_right_defaults.bridges)
    num_bootnodes = len(args_with_right_defaults.bootnodes)
    num_participants = len(args_with_right_defaults.participants)
    plan.print(
        "Launching network with {} participants, {} bridges, {} bootnodes".format(
            num_participants, num_bridges, num_bootnodes
        )
    )

    (all_bootnodes, bootnode_enrs) = bootnodes.launch(
        plan,
        args_with_right_defaults.bootnodes,
    )

    all_participants = participants.launch(
        plan,
        args_with_right_defaults.participants,
        bootnode_enrs,
    )

    all_bridges = bridges.launch(
        plan,
        args_with_right_defaults.bridges,
        bootnode_enrs,
    )

    plan.print(
        "Launched network with {} participants, {} bridges, {} bootnodes".format(
            num_participants, num_bridges, num_bootnodes
        )
    )

    plan.print("Launching glados")

    glados_service = glados.launch(
        plan,
        args_with_right_defaults.glados,
        bootnode_enrs,
    )

    plan.print("Launched glados, Launching prometheus...")
    prometheus_private_url = prometheus.launch_prometheus(
        plan,
        # todo: node metrics
        # todo: add bridges/bootnodes
        # todo: support fluffy
        all_participants,
    )

    plan.print("Launched Prometheus, Launching grafana...")
    grafana_datasource_config_template = read_file(
        "/static_files/grafana-config/templates/datasource.yml.tmpl"
    )
    grafana_dashboards_config_template = read_file(
        "/static_files/grafana-config/templates/dashboard-providers.yml.tmpl"
    )
    grafana.launch_grafana(
        plan,
        grafana_datasource_config_template,
        grafana_dashboards_config_template,
        prometheus_private_url,
    )
    plan.print("Successfully launched grafana")
