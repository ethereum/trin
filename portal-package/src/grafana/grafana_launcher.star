SERVICE_NAME = "grafana"

IMAGE_NAME = "grafana/grafana-enterprise:9.5.12"

HTTP_PORT_ID = "http"
HTTP_PORT_NUMBER_UINT16 = 3000

DATASOURCE_CONFIG_REL_FILEPATH = "datasources/datasource.yml"

# this is relative to the files artifact root
DASHBOARD_PROVIDERS_CONFIG_REL_FILEPATH = "dashboards/dashboard-providers.yml"

CONFIG_DIRPATH_ENV_VAR = "GF_PATHS_PROVISIONING"

GRAFANA_CONFIG_DIRPATH_ON_SERVICE = "/config"
GRAFANA_DASHBOARDS_DIRPATH_ON_SERVICE = "/dashboards"
GRAFANA_DASHBOARDS_FILEPATH_ON_SERVICE = GRAFANA_DASHBOARDS_DIRPATH_ON_SERVICE

USED_PORTS = {
    HTTP_PORT_ID: PortSpec(
        number = HTTP_PORT_NUMBER_UINT16,
        transport_protocol = "TCP",
        application_protocol = "http",
    )
}

# Grafana config (from static_files)
GRAFANA_CONFIG_DIRPATH = "/grafana-config"
STATIC_FILES_DIRPATH = "/static_files"
GRAFANA_DATASOURCE_CONFIG_TEMPLATE_FILEPATH = (
    STATIC_FILES_DIRPATH + GRAFANA_CONFIG_DIRPATH + "/templates/datasource.yml.tmpl"
)
GRAFANA_DASHBOARD_PROVIDERS_CONFIG_TEMPLATE_FILEPATH = (
    STATIC_FILES_DIRPATH
    + GRAFANA_CONFIG_DIRPATH
    + "/templates/dashboard-providers.yml.tmpl"
)
GRAFANA_DASHBOARDS_CONFIG_DIRPATH = (
    STATIC_FILES_DIRPATH + GRAFANA_CONFIG_DIRPATH + "/dashboards"
)

# The min/max CPU/memory that grafana can use
MIN_CPU = 0
MAX_CPU = 1000
MIN_MEMORY = 128
MAX_MEMORY = 2048


def launch_grafana(
    plan,
    datasource_config_template,
    dashboard_providers_config_template,
    prometheus_private_url,
):
    (
        grafana_config_artifacts_uuid,
        grafana_dashboards_artifacts_uuid,
    ) = get_grafana_config_dir_artifact_uuid(
        plan,
        datasource_config_template,
        dashboard_providers_config_template,
        prometheus_private_url,
    )

    config = ServiceConfig(
        image=IMAGE_NAME,
        ports=USED_PORTS,
        env_vars={
            CONFIG_DIRPATH_ENV_VAR: GRAFANA_CONFIG_DIRPATH_ON_SERVICE,
            "GF_AUTH_ANONYMOUS_ENABLED": "true",
            "GF_AUTH_ANONYMOUS_ORG_ROLE": "Admin",
            "GF_AUTH_ANONYMOUS_ORG_NAME": "Main Org.",
            "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH": "/dashboards/default.json",
        },
        files={
            GRAFANA_CONFIG_DIRPATH_ON_SERVICE: grafana_config_artifacts_uuid,
            GRAFANA_DASHBOARDS_DIRPATH_ON_SERVICE: grafana_dashboards_artifacts_uuid,
        },
        min_cpu=MIN_CPU,
        max_cpu=MAX_CPU,
        min_memory=MIN_MEMORY,
        max_memory=MAX_MEMORY,
    )

    plan.add_service(SERVICE_NAME, config)


def get_grafana_config_dir_artifact_uuid(
    plan,
    datasource_config_template,
    dashboard_providers_config_template,
    prometheus_private_url,
):
    datasource_data = {"PrometheusURL": prometheus_private_url}
    datasource_template_and_data = struct(template=datasource_config_template, data=datasource_data)

    dashboard_providers_data = {"DashboardsDirpath": GRAFANA_DASHBOARDS_DIRPATH_ON_SERVICE}
    dashboard_providers_template_and_data = struct(template=dashboard_providers_config_template, data=dashboard_providers_data)

    template_and_data_by_rel_dest_filepath = {}
    template_and_data_by_rel_dest_filepath[
        DATASOURCE_CONFIG_REL_FILEPATH
    ] = datasource_template_and_data
    template_and_data_by_rel_dest_filepath[
        DASHBOARD_PROVIDERS_CONFIG_REL_FILEPATH
    ] = dashboard_providers_template_and_data

    grafana_config_artifacts_name = plan.render_templates(
        template_and_data_by_rel_dest_filepath, name="grafana-config"
    )

    grafana_dashboards_artifacts_name = plan.upload_files(
        GRAFANA_DASHBOARDS_CONFIG_DIRPATH, name="grafana-dashboards"
    )

    return (
        grafana_config_artifacts_name,
        grafana_dashboards_artifacts_name,
    )
