use std::sync::Arc;

use anyhow::Context;
use poem::IntoResponse;
use tokio::sync::Mutex;

use super::*;
use crate::notifications::request_url;
use crate::notifications::tests::{config, request, target};

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
    let mut client = SlackClient::new(SlackNotificationsConfig {
        channel_id: "C1".into(),
        bot_token: "token".to_owned().into(),
    })?;
    client.api_url = url::Url::parse(&format!("http://{address}/api/"))?;
    let request = request();
    let url = request_url(&config(), request.id)?;
    let notification = TicketRequestNotification::from_request("requester", &request, &target())
        .context("pending notification")?;
    client.post(&notification, &url).await?;
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
    let slack_error = client.post(&notification, &url).await;
    assert!(slack_error.is_err_and(|error| error.to_string().contains("not_in_channel")));
    let http_error = client.post(&notification, &url).await;
    assert!(http_error.is_err());
    server.abort();
    Ok(())
}

#[test]
fn long_unicode_reasons_fit_slack_without_truncating_the_link() -> anyhow::Result<()> {
    let mut request = request();
    request.description = "🦀".repeat(4000);
    let notification = TicketRequestNotification::from_request("requester", &request, &target())
        .context("pending notification")?;
    let text = message_text(&notification);
    assert_eq!(text.chars().count(), 3000);
    Ok(())
}
