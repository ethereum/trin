pub mod dashboard;
use clap::{Args, Parser};

use dashboard::grafana::{GrafanaAPI, DASHBOARD_TEMPLATES};

#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "trin-cli",
    version = "0.0.1",
    author = "Ethereum Foundation",
    about = "Portal Network command line utilities"
)]
enum Trin {
    CreateDashboard(DashboardConfig),
}

#[derive(Args, Debug, PartialEq)]
#[command(name = "create-dashboard")]
#[allow(clippy::enum_variant_names)]
struct DashboardConfig {
    #[arg(default_value = "http://localhost:3000")]
    grafana_address: String,

    #[arg(default_value = "admin")]
    grafana_username: String,

    #[arg(default_value = "admin")]
    grafana_password: String,

    #[arg(default_value = "http://host.docker.internal:9090")]
    prometheus_address: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Trin::parse() {
        Trin::CreateDashboard(dashboard_config) => create_dashboard(dashboard_config),
    }
}

fn create_dashboard(dashboard_config: DashboardConfig) -> Result<(), Box<dyn std::error::Error>> {
    let grafana = GrafanaAPI::new(
        dashboard_config.grafana_username,
        dashboard_config.grafana_password,
        dashboard_config.grafana_address,
    );

    let prometheus_uid = grafana.create_datasource(
        "prometheus".to_string(),
        "prometheus".to_string(),
        dashboard_config.prometheus_address,
    )?;

    // Create a dashboard from each pre-defined template
    for template_path in DASHBOARD_TEMPLATES.iter() {
        let dashboard_url = grafana.create_dashboard(template_path, &prometheus_uid)?;
        println!("Dashboard successfully created: {dashboard_url}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trin_with_create_dashboard() {
        let trin = Trin::parse_from([
            "test",
            "create-dashboard",
            "http://localhost:8787",
            "username",
            "password",
            "http://docker:9090",
        ]);
        assert_eq!(
            trin,
            Trin::CreateDashboard(DashboardConfig {
                grafana_address: "http://localhost:8787".to_string(),
                grafana_username: "username".to_string(),
                grafana_password: "password".to_string(),
                prometheus_address: "http://docker:9090".to_string(),
            })
        );
    }
}
