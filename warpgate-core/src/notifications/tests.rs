use serde_json::json;
use time::OffsetDateTime;

use super::*;

pub(super) fn request() -> TicketRequest::Model {
    TicketRequest::Model {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        description: "Needed <@U1> & <https://evil.example|misleading>".into(),
        status: TicketRequestStatus::Pending,
        requested_duration_seconds: Some(3600),
        created: OffsetDateTime::now_utc(),
        resolved_by_user_id: None,
        resolved_at: None,
        ticket_id: None,
        deny_reason: None,
    }
}

pub(super) fn target() -> Target::Model {
    Target::Model {
        id: Uuid::new_v4(),
        name: "target".into(),
        description: String::new(),
        kind: Target::TargetKind::Ssh,
        options: json!({}),
        rate_limit_bytes_per_second: None,
        group_id: None,
        ticket_max_duration_seconds: None,
        ticket_requests_disabled: false,
        ticket_require_approval: true,
        ticket_max_uses: None,
        require_approval: false,
    }
}

pub(super) fn config() -> WarpgateConfig {
    let mut config = WarpgateConfig {
        store: warpgate_common::WarpgateConfigStore::default(),
    };
    config.store.external_host = Some("warpgate.example".into());
    config.store.http.external_port = Some(443);
    config
}

#[test]
fn links_use_existing_public_host_and_port_settings() -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    let mut config = config();
    config.store.external_host = None;
    assert!(request_url(&config, id).is_err());
    config.store.external_host = Some("warpgate.example".into());
    config.store.http.external_port = Some(8443);
    let url = request_url(&config, id)?;
    assert_eq!(url.host_str(), Some("warpgate.example"));
    assert_eq!(url.port(), Some(8443));
    assert!(url.query().is_none());
    assert_eq!(
        url.fragment(),
        Some(format!("/status/requests?ticket_request={id}").as_str())
    );
    Ok(())
}

#[test]
fn only_pending_requests_create_provider_neutral_events() -> anyhow::Result<()> {
    let mut request = request();
    let notification = TicketRequestNotification::from_request("requester", &request, &target())
        .context("pending notification")?;
    assert_eq!(notification.request_id, request.id);
    assert_eq!(notification.description, request.description);
    assert!(notification.description.contains("<@U1>"));
    for status in [TicketRequestStatus::Approved, TicketRequestStatus::Denied] {
        request.status = status;
        assert!(
            TicketRequestNotification::from_request("requester", &request, &target()).is_none()
        );
    }
    Ok(())
}

#[test]
fn notification_providers_are_opt_in() -> anyhow::Result<()> {
    let disabled: warpgate_common::WarpgateConfigStore = serde_json::from_value(json!({}))?;
    assert!(disabled.notifications.is_none());
    let empty: warpgate_common::WarpgateConfigStore =
        serde_json::from_value(json!({"notifications": {}}))?;
    assert!(
        empty
            .notifications
            .is_some_and(|providers| providers.is_empty())
    );
    let enabled: warpgate_common::WarpgateConfigStore = serde_json::from_value(json!({
        "notifications": {"slack": {"channel_id": "C1", "bot_token": "secret-value-for-test"}}
    }))?;
    let providers = enabled.notifications.context("notifications")?;
    assert!(!providers.is_empty());
    assert!(!format!("{providers:?}").contains("secret-value-for-test"));
    let slack = providers.slack.context("Slack provider")?;
    assert_eq!(slack.channel_id, "C1");
    assert_eq!(slack.bot_token.expose_secret(), "secret-value-for-test");
    assert!(
        serde_json::from_value::<warpgate_common::WarpgateConfigStore>(json!({
            "notifications": {"slack": {"channel_id": "C1"}}
        }))
        .is_err()
    );
    Ok(())
}
