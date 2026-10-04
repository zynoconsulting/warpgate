use std::time::Duration;

use anyhow::{Context, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Method};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
struct WarpgateMcp {
    client: Client,
    base_url: Url,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RequestApproval {
    /// Target name from warpgate_list_approval_targets.
    target_name: String,
    /// Optional access duration, in seconds; the existing Warpgate policy applies.
    duration_seconds: Option<i64>,
    /// Reason for requesting access; required if the existing policy says so.
    description: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApprovalId {
    /// UUID returned as request.id by warpgate_request_approval.
    approval_id: String,
}

impl WarpgateMcp {
    fn new(base_url: &str, token: &str) -> anyhow::Result<Self> {
        let mut base_url = Url::parse(base_url).context("WARPGATE_URL must be an absolute URL")?;
        let loopback = base_url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]"));
        if base_url.scheme() != "https" && !(base_url.scheme() == "http" && loopback) {
            bail!("WARPGATE_URL must use HTTPS (HTTP is allowed for loopback development)");
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || !matches!(base_url.path(), "" | "/")
        {
            bail!(
                "WARPGATE_URL must contain only the Warpgate origin, without credentials, path, query or fragment"
            );
        }
        base_url.set_path("/@warpgate/api/");
        if token.trim().is_empty() {
            bail!("WARPGATE_TOKEN must be a user API token");
        }
        let mut token =
            HeaderValue::from_str(token).context("Invalid WARPGATE_TOKEN header value")?;
        token.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("x-warpgate-token", token);
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base_url,
            tool_router: Self::tool_router(),
        })
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> CallToolResult {
        let Ok(url) = self.base_url.join(path) else {
            return CallToolResult::structured_error(json!({"error": "Invalid Warpgate API path"}));
        };
        let mut request = self.client.request(method, url);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return CallToolResult::structured_error(
                    json!({"error": error.without_url().to_string()}),
                );
            }
        };
        let status = response.status();
        let Ok(value) = response.json::<Value>().await else {
            return CallToolResult::structured_error(
                json!({"http_status": status.as_u16(), "error": "Warpgate returned no JSON result"}),
            );
        };
        if !status.is_success() {
            return CallToolResult::structured_error(
                json!({"http_status": status.as_u16(), "error": value}),
            );
        }
        let value = if value.is_array() {
            json!({"targets": value})
        } else {
            value
        };
        CallToolResult::structured(value)
    }

    fn approval_path(id: &str, activate: bool) -> Result<String, CallToolResult> {
        let id = Uuid::parse_str(id).map_err(|_| {
            CallToolResult::structured_error(json!({"error": "approval_id must be a UUID"}))
        })?;
        Ok(if activate {
            format!("ticket-requests/{id}/activate")
        } else {
            format!("ticket-requests/{id}")
        })
    }
}

#[tool_router]
impl WarpgateMcp {
    #[tool(
        description = "List requestable Warpgate targets and their current ticket duration limits. Normal user visibility applies.",
        annotations(read_only_hint = true)
    )]
    async fn warpgate_list_approval_targets(&self) -> CallToolResult {
        self.call(Method::GET, "ticket-request-targets", None).await
    }

    #[tool(
        description = "Request an access ticket as the configured Warpgate user. Pending requests send a Slack notification linking to the Warpgate approval page when configured. An approver decides in Warpgate. Existing auto-approval may return auto_approved_ticket_secret once: keep it securely; it cannot be retrieved again."
    )]
    async fn warpgate_request_approval(
        &self,
        Parameters(request): Parameters<RequestApproval>,
    ) -> CallToolResult {
        self.call(Method::POST, "ticket-requests", Some(json!({"target_name": request.target_name, "duration_seconds": request.duration_seconds, "description": request.description}))).await
    }

    #[tool(
        description = "Read your ticket request's Pending, Approved or Denied status. Poll to learn the decision. Approved requests with no ticket_id can be activated. Request approval creates no new expiry deadline.",
        annotations(read_only_hint = true)
    )]
    async fn warpgate_get_approval(
        &self,
        Parameters(id): Parameters<ApprovalId>,
    ) -> CallToolResult {
        match Self::approval_path(&id.approval_id, false) {
            Ok(path) => self.call(Method::GET, &path, None).await,
            Err(error) => error,
        }
    }

    #[tool(
        description = "Activate your approved ticket request. Returns the ticket secret once and target connection metadata. Preserve the secret securely: activation is not replayable. Existing ticket duration/use limits and any separate target session approval still apply."
    )]
    async fn warpgate_activate_ticket(
        &self,
        Parameters(id): Parameters<ApprovalId>,
    ) -> CallToolResult {
        match Self::approval_path(&id.approval_id, true) {
            Ok(path) => self.call(Method::POST, &path, None).await,
            Err(error) => error,
        }
    }
}

#[tool_handler(router = self.tool_router, name = "warpgate-mcp", version = "0.29.0", instructions = "Request target access through the existing Warpgate ticket workflow. Slack notifications link approvers to Warpgate, where they approve or deny. Poll your request for the decision, then activate an approved unactivated request. Ticket secrets appear only once. Approval does not bypass independent session approval requirements. Never expose ticket secrets in Slack.")]
impl ServerHandler for WarpgateMcp {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let url =
        std::env::var("WARPGATE_URL").context("Set WARPGATE_URL to the Warpgate HTTPS origin")?;
    let token = std::env::var("WARPGATE_TOKEN")
        .context("Set WARPGATE_TOKEN to an existing user API token")?;
    let server = WarpgateMcp::new(&url, &token)?;
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mcp_protocol_exposes_only_owner_scoped_ticket_tools_and_preserves_one_time_secrets()
    -> anyhow::Result<()> {
        use poem::IntoResponse;
        use rmcp::model::CallToolRequestParams;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let listener = poem::listener::TcpAcceptor::from_tokio(listener)?;
        let id = Uuid::new_v4();
        let endpoint = poem::endpoint::make(move |mut request: poem::Request| async move {
            assert_eq!(
                request
                    .headers()
                    .get("x-warpgate-token")
                    .and_then(|v| v.to_str().ok()),
                Some("requester-token")
            );
            let path = request.uri().path().to_string();
            let value = if path == "/@warpgate/api/ticket-request-targets" {
                json!([{"name": "target"}])
            } else if path == "/@warpgate/api/ticket-requests" {
                let bytes = request.take_body().into_bytes().await?;
                let body: Value =
                    serde_json::from_slice(&bytes).map_err(poem::error::BadRequest)?;
                assert_eq!(body.get("target_name"), Some(&json!("target")));
                json!({"request": {"id": id, "status": "Approved", "ticket_id": "auto-ticket"}, "auto_approved_ticket_secret": "auto-secret"})
            } else if path == format!("/@warpgate/api/ticket-requests/{id}") {
                json!({"request": {"id": id, "status": "Approved", "ticket_id": null}})
            } else if path == format!("/@warpgate/api/ticket-requests/{id}/activate") {
                json!({"request": {"id": id, "status": "Approved"}, "target": {"name": "target", "kind": "Ssh"}, "secret": "activated-secret"})
            } else {
                return Ok(poem::http::StatusCode::NOT_FOUND.into_response());
            };
            Ok::<_, poem::Error>(poem::web::Json(value).into_response())
        });
        let http = tokio::spawn(poem::Server::new_with_acceptor(listener).run(endpoint));
        let server = WarpgateMcp::new(&format!("http://{address}"), "requester-token")?;
        let (server_transport, client_transport) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            let service = server.serve(server_transport).await?;
            service.waiting().await?;
            anyhow::Ok(())
        });
        let client = ().serve(client_transport).await?;
        let tools = client.list_all_tools().await?;
        let mut names: Vec<_> = tools.iter().map(|t| t.name.as_ref()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "warpgate_activate_ticket",
                "warpgate_get_approval",
                "warpgate_list_approval_targets",
                "warpgate_request_approval"
            ]
        );
        let targets = client
            .call_tool(CallToolRequestParams::new("warpgate_list_approval_targets"))
            .await?;
        let data = targets.structured_content.context("structured targets")?;
        assert_eq!(data.get("targets"), Some(&json!([{"name": "target"}])));
        let arguments = serde_json::Map::from_iter([("target_name".into(), json!("target"))]);
        let created = client
            .call_tool(
                CallToolRequestParams::new("warpgate_request_approval").with_arguments(arguments),
            )
            .await?;
        let data = created.structured_content.context("structured creation")?;
        assert_eq!(
            data.get("auto_approved_ticket_secret"),
            Some(&json!("auto-secret"))
        );
        let arguments = serde_json::Map::from_iter([("approval_id".into(), json!(id.to_string()))]);
        let decision = client
            .call_tool(
                CallToolRequestParams::new("warpgate_get_approval")
                    .with_arguments(arguments.clone()),
            )
            .await?;
        assert_eq!(decision.is_error, Some(false));
        let activated = client
            .call_tool(
                CallToolRequestParams::new("warpgate_activate_ticket").with_arguments(arguments),
            )
            .await?;
        let data = activated
            .structured_content
            .context("structured activation")?;
        assert_eq!(data.get("secret"), Some(&json!("activated-secret")));
        client.cancel().await?;
        task.await??;
        http.abort();
        Ok(())
    }

    #[test]
    fn rejects_unsafe_origins_and_path_injection() {
        for origin in [
            "http://remote.example",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com?token=secret",
        ] {
            assert!(WarpgateMcp::new(origin, "token").is_err());
        }
        assert!(WarpgateMcp::approval_path("../../admin/users", false).is_err());
        assert!(
            serde_json::from_value::<RequestApproval>(
                json!({"target_name": "target", "user_id": "another-user"})
            )
            .is_err()
        );
    }
}
