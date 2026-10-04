use std::sync::Arc;

use poem::IntoResponse;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::*;

fn request() -> TicketRequest::Model {
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

fn target() -> Target::Model {
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

fn config() -> WarpgateConfig {
    let mut config = WarpgateConfig {
        store: warpgate_common::WarpgateConfigStore::default(),
    };
    config.store.external_host = Some("warpgate.example".into());
    config.store.http.external_port = Some(443);
    config
}

#[tokio::test]
async fn posts_safe_request_details_and_the_canonical_link() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let listener = poem::listener::TcpAcceptor::from_tokio(listener)?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let endpoint = poem::endpoint::make(move |mut request: poem::Request| {
        let recorded = recorded.clone();
        async move {
            assert_eq!(request.uri().path(), "/api/chat.postMessage");
            assert_eq!(
                request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok()),
                Some("Bearer token")
            );
            let bytes = request.take_body().into_bytes().await?;
            let body: Value = serde_json::from_slice(&bytes).map_err(poem::error::BadRequest)?;
            let mut calls = recorded.lock().await;
            calls.push(body);
            let response = match calls.len() {
                1 => poem::web::Json(json!({"ok": true})).into_response(),
                2 => {
                    poem::web::Json(json!({"ok": false, "error": "not_in_channel"})).into_response()
                }
                _ => poem::http::StatusCode::TOO_MANY_REQUESTS.into_response(),
            };
            Ok::<_, poem::Error>(response)
        }
    });
    let server = tokio::spawn(poem::Server::new_with_acceptor(listener).run(endpoint));
    let mut client = SlackClient::new(SlackApprovalsConfig {
        channel_id: "C1".into(),
        bot_token: "token".to_owned().into(),
    })?;
    client.api_url = url::Url::parse(&format!("http://{address}/api/"))?;
    let request = request();
    let url = request_url(&config(), request.id)?;
    let text = message_text("requester", &request, &target());
    client.post(&text, &url).await?;
    let recorded = calls.lock().await;
    let body = recorded.first().context("notification")?;
    assert_eq!(body.get("channel"), Some(&json!("C1")));
    assert_eq!(body.get("mrkdwn"), Some(&json!(false)));
    assert_eq!(body.get("unfurl_links"), Some(&json!(false)));
    let fallback = body
        .get("text")
        .and_then(Value::as_str)
        .context("fallback text")?;
    assert!(fallback.contains("requester"));
    assert!(fallback.contains("target (Ssh)"));
    assert!(fallback.contains("3600 seconds"));
    assert!(fallback.contains("&lt;@U1&gt;"));
    assert!(!fallback.contains("<https://evil.example"));
    let expected_url = format!(
        "https://warpgate.example/@warpgate/admin#/status/requests?ticket_request={}",
        request.id
    );
    assert!(fallback.contains(&expected_url));
    let blocks = body
        .get("blocks")
        .and_then(Value::as_array)
        .context("blocks")?;
    let details = blocks
        .first()
        .context("details block")?
        .get("text")
        .context("details text")?;
    assert_eq!(details.get("type"), Some(&json!("plain_text")));
    let link = blocks
        .last()
        .context("link block")?
        .get("text")
        .context("link text")?;
    assert_eq!(
        link.get("text"),
        Some(&json!(format!(
            "<{expected_url}|Review request in Warpgate>"
        )))
    );
    assert!(!fallback.contains("token"));
    drop(recorded);
    let slack_error = client.post(&text, &url).await;
    assert!(slack_error.is_err_and(|error| error.to_string().contains("not_in_channel")));
    let http_error = client.post(&text, &url).await;
    assert!(http_error.is_err());
    server.abort();
    Ok(())
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
fn long_unicode_reasons_fit_slack_without_truncating_the_link() {
    let mut request = request();
    request.description = "🦀".repeat(4000);
    let text = message_text("requester", &request, &target());
    assert_eq!(text.chars().count(), 3000);
}
