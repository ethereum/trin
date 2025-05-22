use std::{env, time::Duration};

use anyhow::{anyhow, bail};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE},
    Client, IntoUrl, Request, Response,
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, RequestBuilder};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use tracing::error;
use url::Url;

pub const JSON_CONTENT_TYPE: &str = "application/json";
pub const SSZ_CONTENT_TYPE: &str = "application/octet-stream";
pub const ACCEPT_PRIORITY: &str = "application/octet-stream;q=1.0,application/json;q=0.9";
pub const JSON_ACCEPT_PRIORITY: &str = "application/json;q=1";

#[derive(Debug, Clone, Copy)]
pub enum ContentType {
    Json,
    Ssz,
}

#[derive(Debug, Clone)]
pub struct ClientWithBaseUrl {
    client: ClientWithMiddleware,
    base_url: Url,
}

impl ClientWithBaseUrl {
    pub fn new(
        url: Url,
        request_timeout: u64,
        content_type: ContentType,
    ) -> anyhow::Result<ClientWithBaseUrl> {
        let mut headers = HeaderMap::new();
        match content_type {
            ContentType::Json => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
            }
            ContentType::Ssz => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static(SSZ_CONTENT_TYPE));
                headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_PRIORITY));
            }
        }

        let authentication_headers = get_authorization_headers(url.clone())?;
        for (key, value) in authentication_headers {
            headers.insert(key, value);
        }

        // Add retry middleware
        let reqwest_client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(request_timeout))
            .build()
            .map_err(|err| anyhow!("Failed to build HTTP client {err:?}"))?;
        let client = ClientBuilder::new(reqwest_client)
            .with(RetryTransientMiddleware::new_with_policy(
                ExponentialBackoff::builder().build_with_max_retries(3),
            ))
            .build();

        Ok(Self {
            client,
            base_url: url,
        })
    }

    pub fn client(&self) -> &ClientWithMiddleware {
        &self.client
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn get<U: IntoUrl>(&self, url: U) -> anyhow::Result<RequestBuilder> {
        let url = self.base_url.join(url.as_str())?;
        Ok(self.client.get(url))
    }

    pub fn post<U: IntoUrl>(&self, url: U) -> anyhow::Result<RequestBuilder> {
        let url = self.base_url.join(url.as_str())?;
        Ok(self.client.post(url))
    }

    pub async fn execute(&self, request: Request) -> Result<Response, reqwest_middleware::Error> {
        self.client.execute(request).await
    }
}

pub fn get_authorization_headers(url: Url) -> anyhow::Result<Vec<(HeaderName, HeaderValue)>> {
    let mut headers = vec![];
    if let Some(host) = url.host_str() {
        if host.contains("pandaops.io") {
            let client_id = env::var("PANDAOPS_CLIENT_ID").unwrap_or_else(|_| {
                error!("Pandaops provider detected without PANDAOPS_CLIENT_ID set");
                "null".to_string()
            });

            let client_secret = env::var("PANDAOPS_CLIENT_SECRET").unwrap_or_else(|_| {
                error!("Pandaops provider detected without PANDAOPS_CLIENT_SECRET set");
                "null".to_string()
            });

            headers.push((
                HeaderName::from_static("cf-access-client-id"),
                HeaderValue::from_str(&client_id)?,
            ));
            headers.push((
                HeaderName::from_static("cf-access-client-secret"),
                HeaderValue::from_str(&client_secret)?,
            ));
        }
    } else {
        bail!("Failed to find host string");
    }
    Ok(headers)
}
