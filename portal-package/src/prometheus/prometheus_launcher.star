prometheus = import_module("github.com/kurtosis-tech/prometheus-package/main.star")
constants = import_module("../utils/constants.star")

EXECUTION_CLIENT_TYPE = "execution"
BEACON_CLIENT_TYPE = "beacon"
VALIDATOR_CLIENT_TYPE = "validator"

METRICS_INFO_NAME_KEY = "name"
METRICS_INFO_URL_KEY = "url"
METRICS_INFO_PATH_KEY = "path"
METRICS_INFO_ADDITIONAL_CONFIG_KEY = "config"

PROMETHEUS_DEFAULT_SCRAPE_INTERVAL = "15s"

# The min/max CPU/memory that prometheus can use
MIN_CPU = 0
MAX_CPU = 1000
MIN_MEMORY = 128
MAX_MEMORY = 2048


def launch_prometheus(
    plan,
    all_participants,
):
    metrics_jobs = get_metrics_jobs(
        all_participants,
    )
    prometheus_url = prometheus.run(
        plan, metrics_jobs, MIN_CPU, MAX_CPU, MIN_MEMORY, MAX_MEMORY
    )

    return prometheus_url


def get_metrics_jobs(
    all_participants,
):
    metrics_jobs = []
    for context in all_participants:
        if context.client_name == constants.CLIENT_TYPE.trin:
            labels = {
                "service": context.service_name,
            }
            metrics_jobs.append(
                new_metrics_job(
                    job_name=context.metrics_info[METRICS_INFO_NAME_KEY],
                    endpoint=context.metrics_info[METRICS_INFO_URL_KEY],
                    metrics_path=context.metrics_info[METRICS_INFO_PATH_KEY],
                    labels=labels,
                    scrape_interval=PROMETHEUS_DEFAULT_SCRAPE_INTERVAL,
                )
            )

    return metrics_jobs


def new_metrics_job(
    job_name,
    endpoint,
    metrics_path,
    labels,
    scrape_interval=PROMETHEUS_DEFAULT_SCRAPE_INTERVAL,
):
    return {
        "Name": job_name,
        "Endpoint": endpoint,
        "MetricsPath": metrics_path,
        "Labels": labels,
        "ScrapeInterval": scrape_interval,
    }
