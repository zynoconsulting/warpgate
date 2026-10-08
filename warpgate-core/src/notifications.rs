//! Best-effort notifications linking to the existing ticket approval UI.
use anyhow::Context;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::WarpgateConfig;
use warpgate_db_entities::TicketRequest::TicketRequestStatus;
use warpgate_db_entities::{Target, TicketRequest};

use crate::Services;

mod slack;

/// Raw request details shared by notification providers. Providers own formatting.
struct TicketRequestNotification {
    request_id: Uuid,
    requester: String,
    target_name: String,
    target_kind: Target::TargetKind,
    requested_duration_seconds: Option<i64>,
    description: String,
}

impl TicketRequestNotification {
    fn from_request(
        username: &str,
        request: &TicketRequest::Model,
        target: &Target::Model,
    ) -> Option<Self> {
        if request.status != TicketRequestStatus::Pending {
            return None;
        }
        Some(Self {
            request_id: request.id,
            requester: username.to_owned(),
            target_name: target.name.clone(),
            target_kind: target.kind,
            requested_duration_seconds: request.requested_duration_seconds,
            description: request.description.clone(),
        })
    }
}

/// Use the configured public origin, never a requester-controlled Host header.
fn request_url(config: &WarpgateConfig, request_id: Uuid) -> anyhow::Result<url::Url> {
    let host = config
        .external_host_name()
        .context("Ticket notifications require the existing external_host configuration")?;
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

/// Request creation never waits for notification providers.
pub fn notify_ticket_request(
    services: &Services,
    username: &str,
    request: &TicketRequest::Model,
    target: &Target::Model,
) {
    let Some(notification) = TicketRequestNotification::from_request(username, request, target)
    else {
        return;
    };
    let config = services.config.clone();
    tokio::spawn(async move {
        let (providers, url) = {
            let config = config.lock().await;
            let Some(providers) = config.store.notifications.clone().filter(|p| !p.is_empty())
            else {
                return;
            };
            let url = match request_url(&config, notification.request_id) {
                Ok(url) => url,
                Err(error) => {
                    warn!(%error, request_id = %notification.request_id, "Ticket request notification failed");
                    return;
                }
            };
            (providers, url)
        };
        if let Some(slack) = providers.slack {
            let result = slack::send(slack, &notification, &url).await;
            if let Err(error) = result {
                warn!(%error, request_id = %notification.request_id, provider = "slack", "Ticket request notification failed");
            }
        }
    });
}

#[cfg(test)]
mod tests;
