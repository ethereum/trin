use base64;
use nanotemplate::template;
use serde::Deserialize;
use std::fs;
use ureq;

pub const DASHBOARD_TEMPLATES: &[&str] =
    &["./trin-cli/src/dashboard/collected-metrics-dashboard.json.template"];

pub struct GrafanaAPI {
    basic_auth_string: String,
    address: String,
}

impl GrafanaAPI {
    pub fn new(username: String, password: String, address: String) -> Self {
        let basic_auth_string = format!("{username}:{password}");
        let basic_auth_string = base64::encode(basic_auth_string);
        let basic_auth_string = format!("Basic {basic_auth_string}");

        Self {
            basic_auth_string,
            address,
        }
    }

    pub fn create_datasource(
        &self,
        datasource_type: String,
        name: String,
        url: String,
    ) -> Result<String, anyhow::Error> {
        let datasource_api_url = format!("{}/{}", self.address, "api/datasources/");

        let datasource_creation_response = ureq::post(&datasource_api_url[..])
            .set("Authorization", &self.basic_auth_string)
            .send_json(ureq::json!({
                "name": name,
                "type": datasource_type,
                "access": "proxy",
                "url": url,
                "basicAuth": false,
            }))?;

        let response: DatasourceCreationResponse = datasource_creation_response.into_json()?;
        Ok(response.datasource.uid)
    }

    pub fn create_dashboard(
        &self,
        template_path: &str,
        prometheus_uid: &str,
    ) -> Result<String, anyhow::Error> {
        let filled_in_template =
            GrafanaAPI::interpolate_dashboard_config(template_path, prometheus_uid)?;
        let dashboard_json: serde_json::Value = serde_json::from_str(&filled_in_template[..])?;

        let dashboard_api_url = format!("{}/{}", self.address, "api/dashboards/db/");
        let dashboard_creation_response: DashboardCreationResponse =
            ureq::post(&dashboard_api_url[..])
                .set("Authorization", &self.basic_auth_string)
                .send_json(ureq::json!({ "dashboard": dashboard_json }))?
                .into_json()?;

        let full_dashboard_url = format!("{}{}", self.address, dashboard_creation_response.url);
        Ok(full_dashboard_url)
    }

    fn interpolate_dashboard_config(
        template_path: &str,
        prometheus_uid: &str,
    ) -> Result<String, anyhow::Error> {
        // Open docs/metrics_dashboard.json
        // Fill in template with uid
        let template_string = fs::read_to_string(template_path)?;
        let populated_template = template(
            &template_string[..],
            [
                ("prometheus_uid", prometheus_uid),
                ("", "{}"), // The templating library picks up an empty json object as a placeholder,
                            // so replace it with another empty json object.
            ],
        )?;
        Ok(populated_template)
    }
}

// Structs representing responses to API calls
#[derive(Deserialize)]
struct DatasourceCreationResponse {
    datasource: DatasourceInfo,
}
#[derive(Deserialize)]
struct DatasourceInfo {
    uid: String,
}

#[derive(Deserialize)]
struct DashboardCreationResponse {
    url: String,
}
