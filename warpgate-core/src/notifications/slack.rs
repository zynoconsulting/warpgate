//! Slack formatting and delivery for ticket request notifications.
use std::time::Duration;

use anyhow::bail;
use serde_json::{Value, json};
use warpgate_common::SlackNotificationsConfig;

use super::TicketRequestNotification;

struct SlackClient {
    config: SlackNotificationsConfig,
    http: reqwest::Client,
    api_url: url::Url,
}

impl SlackClient {
    fn new(config: SlackNotificationsConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            api_url: url::Url::parse("https://slack.com/api/")?,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }

    async fn post(
        &self,
        notification: &TicketRequestNotification,
        request_url: &url::Url,
    ) -> anyhow::Result<()> {
        let text = message_text(notification);
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

fn message_text(notification: &TicketRequestNotification) -> String {
    let duration = notification.requested_duration_seconds.map_or_else(
        || "Unlimited by current policy".into(),
        |d| format!("{d} seconds"),
    );
    let text = format!(
        "Warpgate ticket request {}\nRequester: {}\nTarget: {} ({:?})\nDuration: {duration}\nReason: {}",
        notification.request_id,
        notification.requester,
        notification.target_name,
        notification.target_kind,
        notification.description,
    );
    let text = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    // Slack section text is limited to 3000 characters. Keep the link separate
    // so a long reason/name cannot hide the actual request URL.
    text.chars().take(3000).collect()
}

pub(super) async fn send(
    config: SlackNotificationsConfig,
    notification: &TicketRequestNotification,
    request_url: &url::Url,
) -> anyhow::Result<()> {
    let client = SlackClient::new(config)?;
    client.post(notification, request_url).await
}

#[cfg(test)]
mod tests;
