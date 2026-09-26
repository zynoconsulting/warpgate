use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt};
use poem::web::Data;
use poem::web::websocket::{WebSocket, WebSocketStream};
use poem::{Body, IntoResponse, Request, Response, handler};
use serde::Deserialize;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite;
use tracing::{Instrument, debug, error, warn};
use url::Url;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::may_forward_header;
use warpgate_common::{TargetKubernetesOptions, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::{
    get_client_ip, log_request_error, log_request_result, span_for_request,
};
use warpgate_core::Services;
use warpgate_core::logging::KubernetesAuditSubject;
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};

use crate::audit::{StreamOperation, classify_mutating, classify_stream};
use crate::correlator::{AdmittedSession, RequestCorrelator, correlated_authorization};
use crate::recording::{start_recording_api, start_recording_exec};
use crate::server::auth::{
    KubernetesIdentity, authenticate_kubernetes_user, create_authenticated_client,
};

/// A client-supplied impersonation header (`Impersonate-User`,
/// `Impersonate-Group`, `Impersonate-Uid`, `Impersonate-Extra-*`). These let a
/// caller assume another identity on the cluster and must never be forwarded,
/// recorded, or logged.
fn is_impersonation_header(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("impersonate-")
}

/// Headers whose values are secrets or identity-spoofing vectors and so must
/// never be written to a recording or a log line.
fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "authorization" || lower == "cookie" || is_impersonation_header(&lower)
}

/// Copy of `headers` with sensitive entries removed, for recording and logging.
fn redact_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Whether a pump failure only means a peer had already gone: a client killed
/// mid-stream drops its TCP connection without a websocket close (how a
/// `kubectl port-forward` ordinarily ends), and the close handshake itself can
/// leave one direction writing into the socket the other has just closed.
/// Neither is an error an operator needs to see.
///
/// `tungstenite`'s `AlreadyClosed` / `ConnectionClosed` are matched on text:
/// poem stringifies them into `io::Error::other` on the server side, so a
/// `downcast_ref` would never match there.
fn is_peer_gone(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            return matches!(
                io_error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    // rustls reports a peer that vanished without a TLS
                    // close_notify as an unexpected EOF.
                    | std::io::ErrorKind::UnexpectedEof
            );
        }
        let text = cause.to_string();
        text.contains("Trying to work with closed connection")
            || text.contains("Connection closed normally")
    })
}

fn construct_target_url(
    req: &Request,
    api_path: &str,
    k8s_options: &TargetKubernetesOptions,
) -> Result<Url> {
    let query = req.uri().query().unwrap_or("");

    Ok(Url::parse(&if query.is_empty() {
        format!("{}{}", k8s_options.cluster_url, api_path)
    } else {
        format!("{}{}?{}", k8s_options.cluster_url, api_path, query)
    })?)
}

#[handler]
#[allow(clippy::too_many_arguments)]
pub async fn handle_api_request(
    ws: Option<WebSocket>,
    req: &Request,
    body: Body,
    correlator: Data<&Arc<Mutex<RequestCorrelator>>>,
    ctx: Data<&UnauthenticatedRequestContext>,
) -> Result<Response, poem::Error> {
    debug!(
        full_uri = %req.uri(),
        "Handling Kubernetes API request"
    );

    // Authenticate the transport credential on every request (cheap; also enforces
    // account status). Authorization — the credential policy / web approval — is
    // resolved once per correlated session and reused, so a single `kubectl`
    // command's fan-out of requests only prompts for approval once.
    let identity = authenticate_kubernetes_user(req, ctx.services()).await?;
    let (target_name, path) = match &identity {
        // Ticket credentials select the target; the entire URI belongs to the
        // upstream API, including discovery endpoints such as /api and /version.
        KubernetesIdentity::Ticket(ticket) => (
            ticket.target().name.clone(),
            req.uri().path().trim_start_matches('/').to_owned(),
        ),
        KubernetesIdentity::User(_) => named_target_path(req.uri().path())?,
    };

    // The path exactly as the API server will see it. The url crate resolves
    // `.` and `..` segments, so a request cannot name one pod to the audit
    // classifier and another to the cluster; the classifiers and the upstream
    // URL are all built from this one value.
    let api_path = Url::parse(&format!("http://localhost/{path}"))
        .map_err(poem::error::BadRequest)?
        .path()
        .to_owned();

    let (handle, admitted) =
        correlated_authorization(correlator.0, req, identity, &target_name, ctx.services()).await?;

    let (user_session_id, log_span) = {
        // The user info is already on the session: it is set when the session is
        // registered, before its authorization is resolved.
        let handle = handle.lock().await;
        (
            handle.user_session_id(),
            span_for_request(req, ctx.services(), Some(&*handle)).await?,
        )
    };

    // Built once per request and handed to both branches, so every Kubernetes
    // audit event names the same actor, session and target. The *user* session
    // id is the one the log layer keys entries by — recordings key off the
    // target session id instead, and the two must not be confused.
    let audit_subject = {
        let target = admitted.target();
        KubernetesAuditSubject {
            session_id: user_session_id.0,
            user_id: admitted.user_info().id,
            username: admitted.user_info().username.clone(),
            target_id: target.id,
            target_name: target.name.clone(),
        }
    };

    async {
        let response = if let Some(ws) = ws {
            _handle_websocket_request_inner(
                ws,
                req,
                admitted,
                &api_path,
                &audit_subject,
                ctx.services(),
            )
            .await
            .map(IntoResponse::into_response)
            .map_err(poem::Error::from)
        } else {
            // Not `.context(...)`: that converts the `WarpgateError` to an
            // `anyhow::Error`, which poem renders through `Display` instead
            // of `as_response()`.
            _handle_normal_request_inner(
                req,
                body,
                admitted,
                &api_path,
                &audit_subject,
                ctx.services(),
            )
            .await
            .map(IntoResponse::into_response)
            .map_err(poem::Error::from)
        };

        let client_ip = get_client_ip(req, ctx.services()).await;
        let response = response.inspect_err(|e| {
            log_request_error(req.method(), req.original_uri(), client_ip.as_deref(), e);
        })?;

        log_request_result(
            req.method(),
            req.original_uri(),
            client_ip.as_deref(),
            response.status(),
        );

        Ok(response)
    }
    .instrument(log_span)
    .await
}

/// Normal credentials retain the /<target>/<api-path> route. Decode only the
/// target selector; upstream paths must keep their original escaping.
fn named_target_path(path: &str) -> poem::Result<(String, String)> {
    let (target, path) = path
        .strip_prefix('/')
        .and_then(|p| p.split_once('/'))
        .filter(|(target, _)| !target.is_empty())
        .ok_or_else(|| poem::Error::from_status(poem::http::StatusCode::NOT_FOUND))?;
    let target = percent_encoding::percent_decode_str(target)
        .decode_utf8()
        .map_err(|_| poem::Error::from_status(poem::http::StatusCode::BAD_REQUEST))?;
    Ok((target.into_owned(), path.to_owned()))
}

/// Copies every upstream response header onto a poem response builder.
/// Shared by the normal request path and a websocket upgrade the API server
/// refused, so both forward an upstream response the same way.
fn copy_response_headers(
    mut builder: poem::ResponseBuilder,
    headers: &http::HeaderMap,
) -> poem::ResponseBuilder {
    for (name, value) in headers {
        if let Ok(poem_name) = poem::http::HeaderName::from_bytes(name.as_str().as_bytes())
            && let Ok(poem_value) = poem::http::HeaderValue::from_bytes(value.as_bytes())
        {
            builder = builder.header(poem_name, poem_value);
        }
    }
    builder
}

#[allow(clippy::too_many_arguments)]
async fn _handle_normal_request_inner(
    req: &Request,
    body: Body,
    admitted: AdmittedSession,
    api_path: &str,
    audit_subject: &KubernetesAuditSubject,
    services: &Services,
) -> Result<Response, WarpgateError> {
    let user_info = admitted.user_info();
    let k8s_options = admitted.options();
    let client = create_authenticated_client(k8s_options, Some(&user_info.username), services)
        .await?
        .build()
        .context("building reqwest client")?;

    debug!(
        "Target Kubernetes options: cluster_url={}, auth={:?}",
        k8s_options.cluster_url,
        match &k8s_options.auth {
            warpgate_common::KubernetesTargetAuth::Token(_) => "Token",
            warpgate_common::KubernetesTargetAuth::Certificate(_) => "Certificate",
            warpgate_common::KubernetesTargetAuth::IamRole(_) => "IamRole",
        }
    );

    let method = req.method().as_str();
    // Construct the full URL to the Kubernetes API server (without target prefix)
    let full_url =
        construct_target_url(req, api_path, k8s_options).context("constructing target URL")?;

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        // Client-supplied impersonation must never reach the cluster (nor be
        // recorded or logged), so drop it at the point of ingestion.
        if is_impersonation_header(name.as_str()) {
            continue;
        }
        // Still forward Accept-Encoding to allow for chunked encoding
        if !may_forward_header(name) && name != http::header::ACCEPT_ENCODING {
            continue;
        }
        if let Ok(mut value_str) = value.to_str().map(ToString::to_string) {
            if name == http::header::ACCEPT {
                let values = value
                    .to_str()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|s| *s != "application/vnd.kubernetes.protobuf") // cannot parse protobuf yet
                    .collect::<Vec<_>>();
                value_str = values.join(", ");
            }
            headers.insert(name.to_string(), value_str.clone());
        }
    }

    // Bearer tokens and cookies must not be persisted to a recording or emitted
    // to a log line; this redacted view is used for both.
    let redacted_headers = redact_headers(&headers);

    // Get request body
    let body_bytes = body.into_bytes().await.context("reading request body")?;

    // Record the request if recording is enabled
    let mut recorder_opt = {
        let enabled = services.recordings.is_enabled().await.unwrap_or(false);
        if enabled {
            match start_recording_api(&admitted.id(), &services.recordings).await {
                Ok(recorder) => Some(recorder),
                Err(e) => {
                    warn!("Failed to start recording: {}", e);
                    None
                }
            }
        } else {
            None
        }
    };

    // Forward request to Kubernetes API
    let mut request_builder = client.request(
        http::Method::from_bytes(method.as_bytes()).context("request method")?,
        full_url.clone(),
    );

    // Add headers (excluding authorization, host, and content-length as they'll be set by reqwest)
    let mut upstream_headers = HashMap::new();
    for (name, value) in &headers {
        let header_name_lower = name.to_lowercase();
        if [
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "authorization",
        ]
        .contains(&header_name_lower.as_str())
        {
            debug!(header = name, "Filtering out header from upstream request");
        } else if let (Ok(header_name), Ok(header_value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            request_builder = request_builder.header(header_name, header_value);
            upstream_headers.insert(name.clone(), value.clone());
        }
    }

    debug!(
        filtered_headers = ?redact_headers(&upstream_headers),
        "Headers being sent to upstream Kubernetes API"
    );

    if !body_bytes.is_empty() {
        request_builder = request_builder.body(body_bytes.to_vec());
    }

    // Debug logging for upstream request
    debug!(
        method = method,
        url = %full_url,
        headers = ?redacted_headers,
        body_size = body_bytes.len(),
        "Sending request to upstream Kubernetes API"
    );

    let response = request_builder.send().await?;

    let status = response.status();
    let response_headers = response.headers().clone();

    // Emitted after the response so a refused `kubectl debug` is audited as
    // clearly as an accepted one, and before the body is consumed so a failure
    // to read it cannot lose the event.
    if let Some(operation) = classify_mutating(method, api_path, req.uri().query(), &body_bytes) {
        for event in operation.audit_events(audit_subject, status.as_u16()) {
            event.emit();
        }
    }

    debug!(
        method = method,
        url = %full_url,
        status = %status,
        response_headers = ?response_headers,
        "Received response from upstream Kubernetes API"
    );

    let (response_body, body_for_recording) = {
        // k8s uses streaming chunked responses for watch API
        let transfer_encoding = response_headers
            .get(poem::http::header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_lowercase();

        let query_pairs: Vec<_> = req
            .uri()
            .query()
            .map(|q| url::form_urlencoded::parse(q.as_bytes()).collect())
            .unwrap_or_default();

        // watch=true: used by kubectl to await changes
        // follow=true: used by kubectl logs
        let is_streaming_response = query_pairs
            .iter()
            .any(|(k, v)| (k == "watch" || k == "follow") && v == "true");

        if transfer_encoding == "chunked" || is_streaming_response {
            (
                Body::from_bytes_stream(response.bytes_stream().map_err(std::io::Error::other)),
                None,
            )
        } else {
            let bytes = response
                .bytes()
                .await
                .context("reading kubernetes response")?;

            (Body::from_bytes(bytes.clone()), Some(bytes.to_vec()))
        }
    };

    // Record the response
    if let Some(ref mut recorder) = recorder_opt
        && let Err(e) = recorder
            .record_response(
                method,
                full_url.as_ref(),
                redacted_headers,
                &body_bytes,
                status.as_u16(),
                body_for_recording.unwrap_or_default().as_ref(),
            )
            .await
    {
        warn!("Failed to record Kubernetes response: {}", e);
    }

    let poem_response =
        copy_response_headers(Response::builder().status(status), &response_headers);

    Ok(poem_response.body(response_body))
}

async fn run_websocket_recording(recorder: TerminalRecorder, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        if data.is_empty() {
            continue;
        }
        #[allow(clippy::indexing_slicing, reason = "length checked")]
        let msg_type = data[0];
        #[allow(clippy::indexing_slicing, reason = "length checked")]
        let data = data[1..].to_vec();

        let result = match msg_type {
            0..2 => {
                recorder
                    .write(
                        TerminalRecordingStreamId::from_usual_fd_number(msg_type)
                            .unwrap_or_default(),
                        &data,
                    )
                    .await
            }
            4 => {
                #[derive(Deserialize)]
                struct ResizeData {
                    #[serde(rename = "Width")]
                    width: u32,
                    #[serde(rename = "Height")]
                    height: u32,
                }
                if let Ok(resize_data) = serde_json::from_slice::<ResizeData>(&data) {
                    recorder
                        .write_pty_resize(resize_data.width, resize_data.height)
                        .await
                } else {
                    continue;
                }
            }
            _ => continue,
        };
        if let Err(e) = result {
            error!("Failed to write recording item: {}", e);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn _handle_websocket_request_inner(
    ws: WebSocket,
    req: &Request,
    admitted: AdmittedSession,
    api_path: &str,
    audit_subject: &KubernetesAuditSubject,
    services: &Services,
) -> anyhow::Result<impl IntoResponse> {
    let user_info = admitted.user_info();
    let k8s_options = admitted.options();
    let full_url = construct_target_url(req, api_path, k8s_options)?;

    let client = create_authenticated_client(k8s_options, Some(&user_info.username), services)
        .await?
        .http1_only()
        .build()?;

    // Classified independently of recording: an audit trail must not depend on
    // whether session recording happens to be switched on.
    let operation = classify_stream(api_path, req.uri().query());

    let (recorder_tx, recorder_rx) = mpsc::channel::<Vec<u8>>(1000);
    {
        let enabled = services.recordings.is_enabled().await.unwrap_or(false);
        if enabled
            && let Some(metadata) = operation
                .as_ref()
                .and_then(StreamOperation::recording_metadata)
        {
            match start_recording_exec(&admitted.id(), &services.recordings, metadata).await {
                Err(e) => {
                    error!("Failed to start recording: {}", e);
                }
                Ok(recorder) => {
                    tokio::spawn(run_websocket_recording(recorder, recorder_rx));
                }
            }
        }
    };

    let ws_protocols = requested_websocket_protocols(req.headers());

    // Talk to the API server, and learn what (if anything) it selected,
    // before answering the client at all. Poem commits the downstream
    // response's headers — including `Sec-WebSocket-Protocol` — as soon as
    // `.on_upgrade()` below is evaluated, so the only way to acknowledge the
    // client with the same subprotocol the API server actually chose is to
    // already know it by then, rather than guess and hope the two agree.
    //
    // The "started" audit event fires from the `on_switching_protocols`
    // callback, as soon as the API server answers `101` — before its
    // handshake is validated — because the exec/attach/port-forward it names
    // is already running on the cluster at that point; a validation failure
    // after that must still tear the stream down, but must not make it look
    // like it never started.
    let (client_socket, selected_protocol) =
        match connect_upstream_websocket(&client, full_url, &ws_protocols, || {
            if let Some(operation) = &operation {
                operation.audit_event(audit_subject).emit();
            }
        })
        .await
        {
            Ok(UpstreamWebsocket::Established { socket, protocol }) => (socket, protocol),
            // The API server answered without switching protocols (most often
            // RBAC). Audited on its verdict before the body is read, so a
            // failure to read the body can't lose the event, and forwarded to
            // the client exactly as the normal request path forwards any other
            // upstream response — not the generic 500 text a bare error would
            // otherwise produce.
            Ok(UpstreamWebsocket::Rejected(response)) => {
                if let Some(operation) = &operation {
                    operation
                        .rejection_event(audit_subject, response.status().as_u16())
                        .emit();
                }
                return Ok(forward_rejected_upstream_response(response)
                    .await?
                    .into_response());
            }
            // Either the API server was never reached at all (DNS, TCP,
            // TLS, ...), or it answered 101 but then failed handshake
            // validation — in which case the "started" audit event has
            // already fired, from the callback above, before validation
            // ran. Neither case has a response left to forward, and both
            // are a gateway failure rather than a stream the cluster
            // refused, so both answer 502; do not add a "never reached"
            // audit event here, or a validation failure would be reported
            // twice.
            Err(error) => {
                error!("Kubernetes API websocket connection failed: {error:#}");
                return Ok(poem::Error::from_string(
                    "Kubernetes API websocket connection failed",
                    http::StatusCode::BAD_GATEWAY,
                )
                .into_response());
            }
        };

    // `on_upgrade`'s callback must be `Sync`, even though poem only ever
    // calls it once: `client_socket`'s own type isn't (it wraps a boxed
    // trait object from hyper's upgrade machinery), so it cannot be captured
    // directly. `Mutex` supplies `Sync` without requiring the connection
    // itself to be shareable.
    let client_socket = std::sync::Mutex::new(Some(client_socket));

    let ws_handler_inner = move |socket: WebSocketStream| async move {
        let client_socket = client_socket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("on_upgrade calls its callback exactly once");
        let (client_sink, client_source) = client_socket.split();
        let (server_sink, server_source) = socket.split();

        let server_to_client = {
            let recorder_tx = recorder_tx.clone();
            pump_websocket(server_source, client_sink, move |msg| {
                let recorder_tx = recorder_tx.clone();
                async move {
                    tracing::debug!("Server: {:?}", msg);
                    if let tungstenite::Message::Binary(data) = &msg {
                        let _ = recorder_tx.send(data.to_vec()).await;
                    }
                    anyhow::Ok(msg)
                }
            })
        };

        let client_to_server = pump_websocket(client_source, server_sink, move |msg| {
            let recorder_tx = recorder_tx.clone();
            async move {
                tracing::debug!("Client: {:?}", msg);
                if let tungstenite::Message::Binary(data) = &msg {
                    let _ = recorder_tx.send(data.to_vec()).await;
                }
                anyhow::Ok(msg)
            }
        });

        // Whichever direction ends first takes the stream down; the other is
        // dropped rather than left to fail writing into the closed socket.
        let result = tokio::select! {
            result = server_to_client => result,
            result = client_to_server => result,
        };
        match result {
            Err(error) if is_peer_gone(&error) => debug!("Websocket peer gone: {error:#}"),
            result => result?,
        }
        debug!("Closing Websocket stream");
        Ok::<(), anyhow::Error>(())
    };

    // poem drives the upgraded stream after this handler has returned, so the
    // request span is carried over explicitly; the database log layer keeps
    // only events that fall under a session span.
    let span = tracing::Span::current();

    // Acknowledge exactly the subprotocol the API server selected (exec/attach
    // use `[v2..v5.]channel.k8s.io`; port-forward uses `SPDY/3.1+portforward.k8s.io`
    // or the newer websocket port-forward protocol) — never a guess.
    // `selected_protocol`, if any, is by construction one of `ws_protocols`,
    // the very list poem's own negotiation parses from the client's request
    // (see `requested_websocket_protocols`), so poem is certain to find and
    // echo it back rather than silently drop it.
    let ws = match selected_protocol {
        Some(protocol) => ws.protocols(vec![protocol]),
        None => ws,
    };

    Ok(ws
        .on_upgrade(move |socket| {
            async move {
                if let Err(error) = ws_handler_inner(socket).await {
                    error!("Websocket handling error: {error:?}");
                }
            }
            .instrument(span)
        })
        .into_response())
}

/// Validates the API server's `101 Switching Protocols` answer to an upgrade
/// sent with `key` offering `offered`, per RFC 6455 §4.1. Returns the
/// subprotocol it selected, or `None` if it selected none — legal whether or
/// not anything was offered (RFC 6455 §4.2.2 item 5.5), so the caller can
/// tell a client that offered nothing from one whose offer the server
/// declined; either way, no subprotocol framing is in effect.
///
/// An empty `Sec-WebSocket-Protocol` value is read the same as an absent one.
/// RFC 6455 doesn't allow an empty token there; this is a Kubernetes
/// compatibility exception, not a relaxation of the spec for anyone else. The
/// API server (`wsstream` over `x/net/websocket`) answers this way when
/// offered no subprotocol.
fn check_upstream_handshake(
    headers: &http::HeaderMap,
    key: &str,
    offered: &[String],
) -> anyhow::Result<Option<String>> {
    let header = |name: http::HeaderName| {
        headers
            .get(&name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .with_context(|| format!("missing or invalid {name} response header"))
    };
    let connection = header(http::header::CONNECTION)?;
    if !connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    {
        bail!("unexpected Connection response header: {connection}");
    }
    let upgrade = header(http::header::UPGRADE)?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        bail!("unexpected Upgrade response header: {upgrade}");
    }
    // RFC 6455 §4.2.2/§4.3 define the server's Sec-WebSocket-Accept response
    // as a single value, not a list, so at most one may be sent; reject a
    // repeated one rather than silently taking the first, as `header()`
    // above would.
    let mut accept_headers = headers.get_all(http::header::SEC_WEBSOCKET_ACCEPT).iter();
    let accept = accept_headers
        .next()
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .with_context(|| {
            format!(
                "missing or invalid {} response header",
                http::header::SEC_WEBSOCKET_ACCEPT
            )
        })?;
    if accept_headers.next().is_some() {
        bail!("the API server sent multiple Sec-WebSocket-Accept response headers");
    }
    if accept != tungstenite::handshake::derive_accept_key(key.as_bytes()) {
        bail!("unexpected Sec-WebSocket-Accept response header: {accept}");
    }
    // We never send Sec-WebSocket-Extensions, so the API server has nothing
    // of ours to select from (RFC 6455 §4.1).
    if let Some(extensions) = headers.get(http::header::SEC_WEBSOCKET_EXTENSIONS) {
        let extensions = extensions.to_str().unwrap_or("<invalid>");
        bail!("unexpected Sec-WebSocket-Extensions response header: {extensions}");
    }

    // RFC 6455 §4.2.2/§4.3 likewise define the server's Sec-WebSocket-Protocol
    // response as a single token naming one protocol, not a list; reject
    // anything a legitimate server wouldn't send, rather than silently
    // taking the first value.
    let mut protocol_headers = headers.get_all(http::header::SEC_WEBSOCKET_PROTOCOL).iter();
    let first_protocol_header = protocol_headers.next();
    if protocol_headers.next().is_some() {
        bail!("the API server sent multiple Sec-WebSocket-Protocol response headers");
    }
    let selected = match first_protocol_header {
        None => None,
        Some(value) => {
            let value = value
                .to_str()
                .context("invalid Sec-WebSocket-Protocol response header")?
                .trim();
            if value.contains(',') {
                bail!(
                    "the API server's Sec-WebSocket-Protocol response header names more than one protocol: {value}"
                );
            }
            // See the Kubernetes compatibility note above.
            (!value.is_empty()).then(|| value.to_owned())
        }
    };

    match &selected {
        None => Ok(None),
        Some(protocol) if offered.iter().any(|o| o == protocol) => Ok(selected),
        Some(protocol) => {
            bail!("the API server selected a subprotocol that wasn't offered: {protocol}")
        }
    }
}

/// What the API server did with a websocket upgrade request.
enum UpstreamWebsocket {
    /// The API server switched protocols. `protocol` is what it selected, if
    /// anything (see `check_upstream_handshake`). Boxed: the socket is much
    /// larger than `Rejected`, and this is returned by value.
    Established {
        socket: Box<tokio_tungstenite::WebSocketStream<reqwest::Upgraded>>,
        protocol: Option<String>,
    },
    /// The API server answered without switching protocols (most often
    /// RBAC). Carries the raw response so the caller can audit its status
    /// before reading the body, then forward status, headers and body to the
    /// client exactly as the non-websocket request path forwards any other
    /// upstream response.
    Rejected(reqwest::Response),
}

/// Forwards a websocket upgrade the API server refused to the client, the way
/// the non-websocket request path forwards any other upstream response (see
/// `_handle_normal_request_inner`): same status, same headers, same body —
/// so, for example, an RBAC-refused `kubectl exec` reads to the client as the
/// Kubernetes `Status` object it actually is, not a generic 500.
async fn forward_rejected_upstream_response(
    response: reqwest::Response,
) -> anyhow::Result<Response> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .context("reading Kubernetes API response")?;

    Ok(copy_response_headers(Response::builder().status(status), &headers).body(body))
}

/// Performs the client side of a websocket upgrade with the Kubernetes API
/// server at `url`, offering `protocols` (may be empty — the API server then
/// speaks the original `channel.k8s.io` framing). Done by hand rather than
/// through `reqwest_websocket`: offered no subprotocol, the API server still
/// answers with an empty `Sec-WebSocket-Protocol` header, which
/// `reqwest_websocket` rejects as a protocol it never asked for (see
/// `check_upstream_handshake`).
///
/// `on_switching_protocols` runs as soon as the API server answers `101`,
/// before its handshake is validated: by then the exec/attach/port-forward it
/// names is already running on the cluster, so the caller's "started" audit
/// event must not wait on validation succeeding too.
async fn connect_upstream_websocket(
    client: &reqwest::Client,
    url: Url,
    protocols: &[String],
    on_switching_protocols: impl FnOnce(),
) -> anyhow::Result<UpstreamWebsocket> {
    let key = tungstenite::handshake::client::generate_key();
    let mut upgrade_request = client
        .get(url)
        .version(http::Version::HTTP_11)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(http::header::SEC_WEBSOCKET_KEY, &key);
    if !protocols.is_empty() {
        upgrade_request =
            upgrade_request.header(http::header::SEC_WEBSOCKET_PROTOCOL, protocols.join(", "));
    }
    let response = upgrade_request
        .send()
        .await
        .context("sending websocket request to Kubernetes API")?;

    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Ok(UpstreamWebsocket::Rejected(response));
    }
    on_switching_protocols();

    let protocol = check_upstream_handshake(response.headers(), &key, protocols)
        .context("negotiating websocket connection with Kubernetes")?;
    let upgraded = response
        .upgrade()
        .await
        .context("negotiating websocket connection with Kubernetes")?;
    let socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
        upgraded,
        tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    Ok(UpstreamWebsocket::Established {
        socket: Box::new(socket),
        protocol,
    })
}

/// The subprotocols the client offered, in order, to request from the API
/// server in turn. A client may offer none: the API server then speaks the
/// original `channel.k8s.io` framing, which is still accepted (kubectl always
/// offers `v5`/`v4.channel.k8s.io`, but other clients don't).
///
/// Reads only the first `Sec-WebSocket-Protocol` request header, split on
/// commas. RFC 6455 §4.1 permits a client to repeat the header instead of
/// joining it with commas; reading only the first is poem's own behaviour
/// (its extractor calls `headers.get`, not `get_all`), and this has to match
/// it exactly: whatever list is offered upstream here must be the same list
/// poem's `WebSocket::protocols` offers back to the client, or the two sides
/// could settle on different subprotocols. See `_handle_websocket_request_inner`.
fn requested_websocket_protocols(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get(http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|protocol| !protocol.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    /// Reads (and discards) an HTTP request head from `stream`, up to and
    /// including the blank line that ends it, before a mock server answers.
    /// A single `read()` isn't guaranteed to see the whole request if the
    /// client's write is split across TCP segments; on loopback that's
    /// exceedingly unlikely, but answering while bytes are still unread
    /// would reset the connection instead of closing it cleanly once the
    /// mock server's task ends.
    async fn drain_request_head(stream: &mut tokio::net::TcpStream) {
        use tokio::io::AsyncReadExt;

        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "peer closed before sending a full request head");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    }

    #[test]
    fn upstream_handshake_validates_the_switching_protocols_response() {
        use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

        use super::check_upstream_handshake;

        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let base_headers = || {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONNECTION,
                http::HeaderValue::from_static("Upgrade"),
            );
            headers.insert(
                http::header::UPGRADE,
                http::HeaderValue::from_static("websocket"),
            );
            headers.insert(
                http::header::SEC_WEBSOCKET_ACCEPT,
                derive_accept_key(key.as_bytes()).parse().unwrap(),
            );
            headers
        };
        let v4 = ["v4.channel.k8s.io".to_owned()];

        // No Sec-WebSocket-Protocol header at all: accepted whether or not a
        // list was offered. RFC 6455 §4.2.2 item 5.5 lets a server switch
        // protocols while selecting none of an offered list.
        assert_eq!(
            check_upstream_handshake(&base_headers(), key, &[]).unwrap(),
            None
        );
        assert_eq!(
            check_upstream_handshake(&base_headers(), key, &v4).unwrap(),
            None,
            "the server may decline every offered subprotocol and still switch protocols",
        );

        // The Kubernetes API server's actual answer to an upgrade offering
        // nothing: an empty Sec-WebSocket-Protocol value. RFC 6455 disallows
        // an empty token here; this is the documented compatibility
        // exception, read the same as an absent header.
        let mut empty_protocol = base_headers();
        empty_protocol.insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static(""),
        );
        assert_eq!(
            check_upstream_handshake(&empty_protocol, key, &[]).unwrap(),
            None
        );

        // A protocol that was actually offered is accepted and returned.
        let mut selected_v4 = base_headers();
        selected_v4.insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("v4.channel.k8s.io"),
        );
        assert_eq!(
            check_upstream_handshake(&selected_v4, key, &v4).unwrap(),
            Some("v4.channel.k8s.io".to_owned())
        );

        // A protocol that was never offered.
        let mut unoffered = base_headers();
        unoffered.insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("channel.k8s.io"),
        );
        assert!(check_upstream_handshake(&unoffered, key, &[]).is_err());
        assert!(check_upstream_handshake(&unoffered, key, &v4).is_err());

        // Duplicate Sec-WebSocket-Protocol response fields: RFC 6455
        // §4.2.2/§4.3 allow at most one.
        let mut duplicated = base_headers();
        duplicated.append(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("v4.channel.k8s.io"),
        );
        duplicated.append(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("v4.channel.k8s.io"),
        );
        assert!(check_upstream_handshake(&duplicated, key, &v4).is_err());

        // A comma-joined list within a single field is just as invalid: the
        // RFC allows the server to name exactly one protocol.
        let mut listed = base_headers();
        listed.insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("v4.channel.k8s.io, v5.channel.k8s.io"),
        );
        assert!(
            check_upstream_handshake(
                &listed,
                key,
                &[
                    "v4.channel.k8s.io".to_owned(),
                    "v5.channel.k8s.io".to_owned()
                ]
            )
            .is_err()
        );

        // An extension we never offered: we send no Sec-WebSocket-Extensions
        // request header, so the server has nothing of ours to select from.
        let mut extension = base_headers();
        extension.insert(
            http::header::SEC_WEBSOCKET_EXTENSIONS,
            http::HeaderValue::from_static("permessage-deflate"),
        );
        assert!(check_upstream_handshake(&extension, key, &[]).is_err());

        // Duplicate Sec-WebSocket-Accept response fields: RFC 6455
        // §4.2.2/§4.3 allow at most one, same as Sec-WebSocket-Protocol
        // above.
        let mut duplicated_accept = base_headers();
        duplicated_accept.append(
            http::header::SEC_WEBSOCKET_ACCEPT,
            derive_accept_key(key.as_bytes()).parse().unwrap(),
        );
        assert!(check_upstream_handshake(&duplicated_accept, key, &[]).is_err());

        // Accept-key mismatch.
        assert!(check_upstream_handshake(&base_headers(), "wrong", &[]).is_err());
    }

    #[test]
    fn websocket_protocols_are_optional_and_read_from_the_first_header_only() {
        use super::requested_websocket_protocols;

        let mut headers = http::HeaderMap::new();
        assert!(requested_websocket_protocols(&headers).is_empty());

        headers.append(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("v5.channel.k8s.io, v4.channel.k8s.io"),
        );
        assert_eq!(
            requested_websocket_protocols(&headers),
            ["v5.channel.k8s.io", "v4.channel.k8s.io"]
        );

        // A second, repeated header is not merged in. This has to match
        // poem's own downstream negotiation (`WebSocket::protocols`), which
        // likewise reads only the first occurrence — see
        // `requested_websocket_protocols`'s doc comment — so upstream and
        // downstream always parse the same offer out of the same request.
        headers.append(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static("channel.k8s.io"),
        );
        assert_eq!(
            requested_websocket_protocols(&headers),
            ["v5.channel.k8s.io", "v4.channel.k8s.io"]
        );
    }

    /// The one Rust-level TLS-upstream pattern in this crate
    /// (`client_certs::tests::stalled_tls_handshake_does_not_block_later_connections`)
    /// mocks the *other* direction — a client connecting into Warpgate's own
    /// listener. This test adapts it to mock a TLS-terminated Kubernetes API
    /// server instead, so the manual upgrade this module performs (rather
    /// than through `reqwest_websocket`) is exercised over TLS too, the same
    /// as it would be against a real cluster: in particular, that
    /// `.http1_only()` keeps ALPN from negotiating HTTP/2, which cannot do a
    /// raw connection upgrade.
    #[tokio::test]
    // tungstenite's `Callback::on_request` fixes `ErrorResponse` as the error
    // type; there's no smaller type to return here instead.
    #[allow(clippy::result_large_err)]
    async fn manual_upgrade_negotiates_the_upstream_protocol_over_tls() {
        use futures::{SinkExt, StreamExt};
        use rustls::ServerConfig;
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::tungstenite::handshake::server::{
            ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
        };
        use url::Url;

        use super::{UpstreamWebsocket, connect_upstream_websocket};

        // Safe to call more than once per process (e.g. alongside other
        // tests in this binary): a failed install just means one is already
        // in place.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key.into())
            .unwrap();
        // Advertise both protocols, as a real API server's TLS stack would:
        // without `.http1_only()` on the client below, ALPN would be free to
        // negotiate HTTP/2, which cannot perform a raw connection upgrade.
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // The mock Kubernetes API server: TLS-terminate, then answer the
        // upgrade exactly as the real API server does when offered no
        // subprotocol — an empty Sec-WebSocket-Protocol response header.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls_stream = tls_acceptor.accept(stream).await.unwrap();
            let callback = |request: &HandshakeRequest, mut response: HandshakeResponse| {
                assert!(
                    request
                        .headers()
                        .get(http::header::SEC_WEBSOCKET_PROTOCOL)
                        .is_none(),
                    "test offers no subprotocol"
                );
                response.headers_mut().insert(
                    http::header::SEC_WEBSOCKET_PROTOCOL,
                    http::HeaderValue::from_static(""),
                );
                Ok::<_, ErrorResponse>(response)
            };
            let mut socket = tokio_tungstenite::accept_hdr_async(tls_stream, callback)
                .await
                .unwrap();
            let message = socket.next().await.unwrap().unwrap();
            socket.send(message).await.unwrap();
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .http1_only()
            .build()
            .unwrap();
        let url = Url::parse(&format!("https://127.0.0.1:{port}/socket")).unwrap();

        let started = std::sync::atomic::AtomicBool::new(false);
        let UpstreamWebsocket::Established {
            mut socket,
            protocol,
        } = connect_upstream_websocket(&client, url, &[], || {
            started.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await
        .unwrap()
        else {
            panic!("expected the manual upgrade to succeed over TLS");
        };
        assert!(
            started.load(std::sync::atomic::Ordering::SeqCst),
            "the started callback must run for a successful upgrade"
        );
        // The Kubernetes compatibility exception applies over TLS exactly as
        // it does over plain HTTP: an empty response header still reads as
        // no protocol selected.
        assert_eq!(protocol, None);

        socket.send(Message::text("hello over tls")).await.unwrap();
        let echoed = socket.next().await.unwrap().unwrap();
        assert_eq!(echoed.into_text().unwrap().as_str(), "hello over tls");

        server.await.unwrap();
    }

    /// A mock API server that answers `101` — so the exec/attach/port-forward
    /// it names is already running on the cluster — but with a
    /// `Sec-WebSocket-Accept` that can never validate, forcing
    /// `check_upstream_handshake` to reject it. The "started" callback must
    /// still have run, since it fires as soon as the status is `101`, before
    /// validation: see `connect_upstream_websocket`.
    #[tokio::test]
    async fn started_callback_runs_on_101_even_when_validation_then_fails() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use url::Url;

        use super::connect_upstream_websocket;

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            drain_request_head(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: websocket\r\n\
                      Sec-WebSocket-Accept: not-the-right-accept-key\r\n\
                      \r\n",
                )
                .await
                .unwrap();
        });

        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/exec")).unwrap();

        let started = AtomicBool::new(false);
        let result = connect_upstream_websocket(&client, url, &[], || {
            started.store(true, Ordering::SeqCst);
        })
        .await;

        assert!(
            result.is_err(),
            "a bogus Sec-WebSocket-Accept must fail handshake validation"
        );
        assert!(
            started.load(Ordering::SeqCst),
            "the started callback must run as soon as the status is 101, \
             before validation - not only once validation also succeeds"
        );

        server.await.unwrap();
    }

    /// A mock API server that refuses the upgrade outright (as it does for an
    /// RBAC-denied `kubectl exec`) rather than switching protocols.
    /// `connect_upstream_websocket` must report this as `Rejected`, carrying
    /// the response, rather than as an `Err`; and `forward_rejected_upstream_response`
    /// must turn that into a client response with the refusal's original
    /// status, headers and body, not a generic 500. (The handler's audit
    /// ordering around these two calls is covered by inspection, not a test
    /// here — exercising it end to end would need a full authenticated
    /// session.)
    #[tokio::test]
    async fn upstream_rejection_is_forwarded_with_its_status_and_body() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use url::Url;

        use super::{
            UpstreamWebsocket, connect_upstream_websocket, forward_rejected_upstream_response,
        };

        // `reqwest::Client::builder().build()` needs a process-wide default
        // rustls crypto provider installed even for a plain `http://`
        // request (it still constructs a TLS connector eagerly). Safe to
        // call more than once per process; see the TLS test above.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let body = br#"{"kind":"Status","status":"Failure","reason":"Forbidden"}"#;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // The request itself doesn't matter for this test; only the
            // response the mock server answers with does.
            drain_request_head(&mut stream).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        });

        let client = reqwest::Client::builder().http1_only().build().unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/exec")).unwrap();

        let UpstreamWebsocket::Rejected(response) =
            connect_upstream_websocket(&client, url, &[], || {
                panic!("a rejected upgrade must not run the started callback")
            })
            .await
            .unwrap()
        else {
            panic!("expected the upgrade to be rejected, not established");
        };
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);

        let forwarded = forward_rejected_upstream_response(response).await.unwrap();
        assert_eq!(forwarded.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(
            forwarded.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            forwarded.into_body().into_bytes().await.unwrap().as_ref(),
            body
        );

        server.await.unwrap();
    }

    use std::collections::HashMap;

    use super::{is_impersonation_header, named_target_path, redact_headers};

    #[test]
    fn named_routes_decode_only_the_target_selector() {
        assert_eq!(
            named_target_path("/my%20cluster/api/v1/namespaces/default/pods/a%2Fb").unwrap(),
            (
                "my cluster".into(),
                "api/v1/namespaces/default/pods/a%2Fb".into()
            ),
        );
        assert!(named_target_path("/api").is_err());
        assert!(named_target_path("/").is_err());
        assert!(named_target_path("//api").is_err());
    }

    #[test]
    fn normal_stream_teardown_is_not_an_error() {
        // One direction closes, the other fails writing into it.
        let closed =
            anyhow::anyhow!("Trying to work with closed connection").context("tungstenite error");
        assert!(super::is_peer_gone(&closed));

        for kind in [
            std::io::ErrorKind::BrokenPipe,
            // A killed client: the TLS session ends without a close_notify.
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error = anyhow::Error::new(std::io::Error::new(kind, "peer gone"));
            assert!(super::is_peer_gone(&error), "{kind:?}");
        }
    }

    #[test]
    fn real_stream_failures_are_still_errors() {
        let refused = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "no route",
        ));
        assert!(!super::is_peer_gone(&refused));
        assert!(!super::is_peer_gone(&anyhow::anyhow!(
            "stream error: protocol violation"
        )));
    }

    #[test]
    fn impersonation_detection_is_case_insensitive() {
        assert!(is_impersonation_header("Impersonate-User"));
        assert!(is_impersonation_header("impersonate-group"));
        assert!(is_impersonation_header("Impersonate-Uid"));
        assert!(is_impersonation_header("IMPERSONATE-Extra-scopes"));
        assert!(!is_impersonation_header("authorization"));
        assert!(!is_impersonation_header("accept"));
    }

    #[test]
    fn redact_drops_secrets_and_impersonation() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer secret".into());
        headers.insert("Cookie".into(), "session=1".into());
        headers.insert("Impersonate-User".into(), "root".into());
        headers.insert("Impersonate-Group".into(), "system:masters".into());
        headers.insert("Accept".into(), "application/json".into());

        let redacted = redact_headers(&headers);

        assert_eq!(redacted.len(), 1);
        assert!(redacted.contains_key("Accept"));
        assert!(!redacted.contains_key("Authorization"));
        assert!(!redacted.contains_key("Cookie"));
        assert!(!redacted.keys().any(|k| is_impersonation_header(k)));
    }
}
