//! One-way Slack notifications for the existing Warpgate ticket approval UI.
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::{Value, json};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{SlackApprovalsConfig, WarpgateConfig};
use warpgate_db_entities::TicketRequest::TicketRequestStatus;
use warpgate_db_entities::{Target, TicketRequest};

use crate::Services;

struct SlackClient {
    config: SlackApprovalsConfig,
    http: reqwest::Client,
    api_url: url::Url,
}

impl SlackClient {
    fn new(config: SlackApprovalsConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            api_url: url::Url::parse("https://slack.com/api/")?,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    async fn post(&self, text: &str, request_url: &url::Url) -> anyhow::Result<()> {
        let response = self
            .http
            .post(self.api_url.join("chat.postMessage")?)
            .bearer_auth(self.config.bot_token.expose_secret())
            .json(&json!({
                "channel": self.config.channel_id,
                "text": format!("{text}\nReview request in Warpgate: {request_url}"),
                "mrkdwn": false, "parse": "none", "link_names": false,
                "unfurl_links": false, "unfurl_media": false,
                "blocks": [
                    {"type": "section", "text": {"type": "plain_text", "text": text}},
                    {"type": "section", "text": {
                        "type": "mrkdwn", "verbatim": true,
                        "text": format!("<{request_url}|Review request in Warpgate>"),
                    }},
                ],
            }))
            .send()
            .await?;
        response.error_for_status_ref()?;
        let result: Value = response.json().await?;
        if result.get("ok").and_then(Value::as_bool) != Some(true) {
            bail!(
                "Slack notification failed: {}",
                result
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown_error"),
            );
        }
        Ok(())
    }
}

/// Use the configured public origin, never a requester-controlled Host header.
fn request_url(config: &WarpgateConfig, request_id: Uuid) -> anyhow::Result<url::Url> {
    let host = config
        .external_host_name()
        .context("Slack ticket notifications require the existing external_host configuration")?;
    let mut url = url::Url::parse(&format!("https://{host}"))?;
    let port = config
        .store
        .http
        .external_port
        .unwrap_or_else(|| config.store.http.listen.port());
    url.set_port(Some(port))
        .map_err(|()| anyhow::anyhow!("Invalid Warpgate public port"))?;
    url.set_path("/@warpgate/admin");
    url.set_fragment(Some(&format!(
        "/status/requests?ticket_request={request_id}"
    )));
    Ok(url)
}

fn message_text(username: &str, request: &TicketRequest::Model, target: &Target::Model) -> String {
    let duration = request.requested_duration_seconds.map_or_else(
        || "Unlimited by current policy".into(),
        |d| format!("{d} seconds"),
    );
    let text = format!(
        "Warpgate ticket request {}\nRequester: {username}\nTarget: {} ({:?})\nDuration: {duration}\nReason: {}",
        request.id, target.name, target.kind, request.description,
    );
    let text = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    // Slack section text is limited to 3000 characters. Keep the link separate
    // so a long reason/name cannot hide the actual request URL.
    text.chars().take(3000).collect()
}

/// Best-effort delivery: request creation never waits for Slack.
pub fn notify(
    services: &Services,
    username: &str,
    request: &TicketRequest::Model,
    target: &Target::Model,
) {
    if request.status != TicketRequestStatus::Pending {
        return;
    }
    let config = services.config.clone();
    let request_id = request.id;
    let text = message_text(username, request, target);
    tokio::spawn(async move {
        let result = async {
            let (slack, url) = {
                let config = config.lock().await;
                let Some(slack) = config.store.slack_approvals.clone() else {
                    return Ok(());
                };
                (slack, request_url(&config, request_id)?)
            };
            let client = SlackClient::new(slack)?;
            client.post(&text, &url).await
        }
        .await;
        if let Err(error) = result {
            warn!(%error, %request_id, "Slack ticket notification failed");
        }
    });
}

#[cfg(test)]
mod tests;
