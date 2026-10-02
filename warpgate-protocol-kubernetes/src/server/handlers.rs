use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt};
use poem::web::Data;
use poem::web::websocket::{WebSocket, WebSocketStream};
use poem::{Body, IntoResponse, Request, Response, handler};
use reqwest_websocket::Upgrade;
use serde::Deserialize;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, warn};
use url::Url;
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::may_forward_header;
use warpgate_common::{TargetKubernetesOptions, WarpgateError};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::{
    get_client_ip, log_request_error, log_request_result, span_for_request,
};
use warpgate_core::logging::KubernetesAuditSubject;
use warpgate_core::recordings::{TerminalRecorder, TerminalRecordingStreamId};
use warpgate_core::{Services, WarpgateServerHandle, has_active_self_service_ticket};

use crate::audit::{StreamOperation, classify_mutating, classify_stream};
use crate::correlator::{AdmittedSession, RequestCorrelator, correlated_authorization};
use crate::recording::{start_recording_api, start_recording_exec};
use crate::server::auth::{
    KubernetesIdentity, authenticate_kubernetes_user, create_authenticated_client, unauthorized,
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
    let uses_ticket_credential = matches!(&identity, KubernetesIdentity::Ticket(_));
    let (target_name, path) = match &identity {
        // Ticket credentials select the target; the entire URI belongs to the
        // upstream API, including discovery endpoints such as /api and /version.
        KubernetesIdentity::Ticket(ticket) => (
            ticket.target().name.clone(),
            req.uri().path().trim_start_matches('/').to_owned(),
        ),
        KubernetesIdentity::User(..) => named_target_path(req.uri().path())?,
    };

    // The path exactly as the API server will see it. The url crate resolves
    // `.` and `..` segments, so a request cannot name one pod to the audit
    // classifier and another to the cluster; the classifiers and the upstream
    // URL are all built from this one value.
    let api_path = Url::parse(&format!("http://localhost/{path}"))
        .map_err(poem::error::BadRequest)?
        .path()
        .to_owned();

    let (correlation_key, handle, admitted, closed) =
        correlated_authorization(correlator.0, req, identity, &target_name, ctx.services()).await?;
    // The correlated session could have been closed (admin close, or its
    // ticket revoked) between being looked up and reaching here.
    if closed.is_cancelled() {
        return Err(unauthorized());
    }

    // A normal identity authorized by a server-side ticket grant can share a
    // correlated session, but the grant itself must not be cached. Re-check
    // the specific granting ticket before every request so its expiry or
    // revocation takes effect immediately — a used-up or expired *sibling*
    // self-service ticket for the same user/target must not keep the session
    // alive on the granting ticket's behalf.
    if !uses_ticket_credential
        && let Some(ticket_id) = admitted.ticket_id()
        && !has_active_self_service_ticket(
            &ctx.services().db,
            ticket_id,
            admitted.user_info().id,
            admitted.target().id,
        )
        .await?
    {
        // The grant is gone: evict this specific session (identified by its
        // handle, not just the key — a stale sibling request racing on the
        // same key must not evict a session a third request has since opened
        // and spent a bounded ticket's use for) so the very next request
        // authorizes fresh — a role, or a new ticket — instead of failing
        // every request until this entry ages out of the correlator on its
        // own.
        correlator
            .0
            .lock()
            .await
            .evict_session(&correlation_key, &handle);
        return Err(poem::Error::from_string(
            format!("Access denied to target: {target_name}"),
            poem::http::StatusCode::FORBIDDEN,
        ));
    }

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
                closed.clone(),
                handle.clone(),
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
                closed,
                handle.clone(),
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

/// Forward refusal headers the same way as the ordinary request path.
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
    closed: CancellationToken,
    handle: Arc<Mutex<WarpgateServerHandle>>,
) -> Result<Response, WarpgateError> {
    let user_info = admitted.user_info();
    let k8s_options = admitted.options();
    let client_builder = create_authenticated_client(
        k8s_options,
        user_info,
        admitted.target().id,
        admitted.upstream_certificate_cache(),
        services,
    )
    .await?;
    let client = client_builder.build().context("building reqwest client")?;

    debug!(
        "Target Kubernetes options: cluster_url={}, auth={:?}",
        k8s_options.cluster_url,
        match &k8s_options.auth {
            warpgate_common::KubernetesTargetAuth::Token(_) => "Token",
            warpgate_common::KubernetesTargetAuth::Certificate(_) => "Certificate",
            warpgate_common::KubernetesTargetAuth::IamRole(_) => "IamRole",
            warpgate_common::KubernetesTargetAuth::EphemeralCertificate(_) => {
                "EphemeralCertificate"
            }
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

    // A correlated session can be admitted once and reused for a long time
    // (up to `session_max_age`); racing every request against `closed` is
    // what makes a mid-session revoke or admin close take effect immediately
    // rather than only on the session's next re-admission.
    let response = tokio::select! {
        biased;
        () = closed.cancelled() => return Err(WarpgateError::TargetAccessRevoked),
        result = request_builder.send() => result?,
    };

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
            // A `kubectl logs -f`/`watch=true` stream can run for as long as
            // the ticket that opened it, well past `session_max_age` ageing
            // the correlator's own entry out of its cache. Carrying `handle`
            // in the stream's state (rather than just racing `closed`) keeps
            // the session — and its access watcher — alive for as long as
            // this stream is actually read, so a still-open `logs -f` can't
            // outlive the thing revoking it just because the cache forgot it.
            let upstream = response.bytes_stream().map_err(std::io::Error::other);
            let stream = futures::stream::unfold(
                (upstream, closed.clone(), handle.clone(), false),
                |(mut upstream, closed, handle, done)| async move {
                    if done {
                        return None;
                    }
                    tokio::select! {
                        biased;
                        // A clean EOF would read to `kubectl` as the stream
                        // having ended normally (exit 0); an error instead
                        // surfaces the close as the abrupt cutoff it is.
                        () = closed.cancelled() => Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "session closed",
                            )),
                            (upstream, closed, handle, true),
                        )),
                        item = upstream.next() => {
                            item.map(|item| (item, (upstream, closed, handle, false)))
                        }
                    }
                },
            );
            (Body::from_bytes_stream(stream), None)
        } else {
            let bytes = tokio::select! {
                biased;
                () = closed.cancelled() => return Err(WarpgateError::TargetAccessRevoked),
                result = response.bytes() => result.context("reading kubernetes response")?,
            };

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

    let mut poem_response = Response::builder().status(status);

    // Copy response headers
    for (name, value) in &response_headers {
        if let Ok(poem_name) = poem::http::HeaderName::from_bytes(name.as_str().as_bytes())
            && let Ok(poem_value) = poem::http::HeaderValue::from_bytes(value.as_bytes())
        {
            poem_response = poem_response.header(poem_name, poem_value);
        }
    }

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
    closed: CancellationToken,
    handle: Arc<Mutex<WarpgateServerHandle>>,
) -> anyhow::Result<impl IntoResponse> {
    let user_info = admitted.user_info();
    let k8s_options = admitted.options();
    let full_url = construct_target_url(req, api_path, k8s_options)?;

    let client_builder = create_authenticated_client(
        k8s_options,
        user_info,
        admitted.target().id,
        admitted.upstream_certificate_cache(),
        services,
    )
    .await?;
    let client = client_builder.http1_only().build()?;

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

    // Poem commits downstream protocol headers at on_upgrade, so negotiate
    // upstream first. Audit 101 before validation: the cluster's stream has
    // already started even if its handshake is invalid.
    let connection = tokio::select! {
        biased;
        () = closed.cancelled() => bail!("Session closed while upgrading the Kubernetes websocket"),
        result = connect_upstream_websocket(&client, full_url, &ws_protocols, || {
            if let Some(operation) = &operation {
                operation.audit_event(audit_subject).emit();
            }
        }) => result,
    };
    let (client_socket, selected_protocol) = match connection {
        Ok(UpstreamWebsocket::Established { socket, protocol }) => (socket, protocol),
        // Audit before reading the body, then forward the cluster's refusal.
        Ok(UpstreamWebsocket::Rejected(response)) => {
            if let Some(operation) = &operation {
                operation
                    .rejection_event(audit_subject, response.status().as_u16())
                    .emit();
            }
            let response = tokio::select! {
                biased;
                () = closed.cancelled() => bail!("Session closed while reading the Kubernetes websocket refusal"),
                result = forward_rejected_upstream_response(response) => result?,
            };
            return Ok(response.into_response());
        }
        // Transport or invalid-handshake failures have no response to forward.
        Err(error) => {
            error!("Kubernetes API websocket connection failed: {error:#}");
            return Ok(poem::Error::from_string(
                "Kubernetes API websocket connection failed",
                http::StatusCode::BAD_GATEWAY,
            )
            .into_response());
        }
    };

    // Poem requires a Sync callback; the socket is Send and consumed once.
    let client_socket = std::sync::Mutex::new(Some(client_socket));

    let ws_handler_inner = move |socket: WebSocketStream| async move {
        let client_socket = client_socket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("on_upgrade calls its callback exactly once");
        // Retain the session and its access watcher for the entire stream.
        let _session_handle = handle;
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
            biased;
            () = closed.cancelled() => Ok(()),
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

    // Echo the API server's selection, which the library checked was offered.
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

/// Kubernetes can send an empty protocol header when the client offered none.
/// Adapt only that response; reqwest-websocket still owns handshake validation.
struct KubernetesWebsocketRequest(reqwest::RequestBuilder);

impl reqwest_websocket::RequestBuilder for KubernetesWebsocketRequest {
    type Client = KubernetesWebsocketClient;

    fn build_split(
        self,
    ) -> (
        Self::Client,
        Result<reqwest::Request, reqwest_websocket::Error>,
    ) {
        let (client, request) = self.0.build_split();
        (
            KubernetesWebsocketClient(client),
            request.map_err(Into::into),
        )
    }
}

struct KubernetesWebsocketClient(reqwest::Client);

impl reqwest_websocket::Client for KubernetesWebsocketClient {
    async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, reqwest_websocket::Error> {
        let offered_protocol = request
            .headers()
            .contains_key(http::header::SEC_WEBSOCKET_PROTOCOL);
        let mut response = self.0.execute(request).await?;
        if !offered_protocol && response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            let mut protocols = response
                .headers()
                .get_all(http::header::SEC_WEBSOCKET_PROTOCOL)
                .iter();
            let single_empty = protocols
                .next()
                .is_some_and(|value| value.as_bytes().is_empty())
                && protocols.next().is_none();
            if single_empty {
                response
                    .headers_mut()
                    .remove(http::header::SEC_WEBSOCKET_PROTOCOL);
            }
        }
        Ok(response)
    }
}

enum UpstreamWebsocket {
    // Box the socket to keep the enum small.
    Established {
        socket: Box<reqwest_websocket::WebSocket>,
        protocol: Option<String>,
    },
    Rejected(reqwest::Response),
}

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

/// Connect before replying downstream so both sides use the selected protocol.
/// Audit a 101 before validation: the cluster has already started the stream.
async fn connect_upstream_websocket(
    client: &reqwest::Client,
    url: Url,
    protocols: &[String],
    on_switching_protocols: impl FnOnce(),
) -> anyhow::Result<UpstreamWebsocket> {
    let response = KubernetesWebsocketRequest(client.get(url))
        .upgrade()
        .protocols(protocols.to_vec())
        .send()
        .await
        .context("sending websocket request to Kubernetes API")?;
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return Ok(UpstreamWebsocket::Rejected(response.into_inner()));
    }
    on_switching_protocols();
    let socket = response
        .into_websocket()
        .await
        .context("negotiating websocket connection with Kubernetes")?;
    let protocol = socket.protocol().map(ToOwned::to_owned);
    Ok(UpstreamWebsocket::Established {
        socket: Box::new(socket),
        protocol,
    })
}

/// Match Poem's downstream parsing: only the first header, split on commas.
/// Clients such as kubeterm may offer no subprotocol.
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

    /// Exercise the library upgrade over TLS with Kubernetes's empty header.
    /// Advertising HTTP/2 also verifies the HTTP/1-only client configuration.
    #[tokio::test]
    // tungstenite's `Callback::on_request` fixes `ErrorResponse` as the error
    // type; there's no smaller type to return here instead.
    #[allow(clippy::result_large_err)]
    async fn library_upgrade_accepts_the_empty_kubernetes_protocol_over_tls() {
        use futures::{SinkExt, StreamExt};
        use reqwest_websocket::Message;
        use rustls::ServerConfig;
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;
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
            panic!("expected the library upgrade to succeed over TLS");
        };
        assert!(
            started.load(std::sync::atomic::Ordering::SeqCst),
            "the started callback must run for a successful upgrade"
        );
        // The Kubernetes compatibility exception applies over TLS exactly as
        // it does over plain HTTP: an empty response header still reads as
        // no protocol selected.
        assert_eq!(protocol, None);

        socket
            .send(Message::Text("hello over tls".into()))
            .await
            .unwrap();
        let echoed = socket.next().await.unwrap().unwrap();
        let Message::Text(text) = echoed else {
            panic!("expected a text frame")
        };
        assert_eq!(text, "hello over tls");

        server.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's server callback fixes the error type.
    async fn library_upgrade_keeps_protocol_negotiation_strict() {
        use futures::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::handshake::server::{
            ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
        };

        use super::{UpstreamWebsocket, connect_upstream_websocket};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cases: &[(&[&str], &[&str], bool)] = &[
            (&[], &[""], true),
            (&[], &[], true),
            (&[], &["unrequested"], false),
            (&[], &["", "unrequested"], false),
            (&[], &["", ""], false),
            (
                &["v5.channel.k8s.io", "v4.channel.k8s.io"],
                &["v4.channel.k8s.io"],
                true,
            ),
            (&["v4.channel.k8s.io"], &[""], false),
            (&["v4.channel.k8s.io"], &[], false),
            (&["v4.channel.k8s.io"], &["unrequested"], false),
        ];
        for &(offered, selected, succeeds) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let callback = |request: &HandshakeRequest, mut response: HandshakeResponse| {
                    let expected = (!offered.is_empty()).then(|| offered.join(", "));
                    assert_eq!(
                        request
                            .headers()
                            .get(http::header::SEC_WEBSOCKET_PROTOCOL)
                            .map(|value| value.to_str().unwrap()),
                        expected.as_deref(),
                    );
                    for protocol in selected {
                        response.headers_mut().append(
                            http::header::SEC_WEBSOCKET_PROTOCOL,
                            http::HeaderValue::from_str(protocol).unwrap(),
                        );
                    }
                    Ok::<_, ErrorResponse>(response)
                };
                let mut socket = tokio_tungstenite::accept_hdr_async(stream, callback)
                    .await
                    .unwrap();
                if let Some(Ok(message)) = socket.next().await {
                    socket.send(message).await.unwrap();
                }
            });
            let client = reqwest::Client::builder().http1_only().build().unwrap();
            let url = url::Url::parse(&format!("http://{address}/exec")).unwrap();
            let protocols = offered.iter().map(|p| p.to_string()).collect::<Vec<_>>();
            let result = connect_upstream_websocket(&client, url, &protocols, || {}).await;
            assert_eq!(
                result.is_ok(),
                succeeds,
                "offered={offered:?}, selected={selected:?}"
            );
            if let Ok(UpstreamWebsocket::Established {
                mut socket,
                protocol,
            }) = result
            {
                assert_eq!(
                    protocol.as_deref(),
                    selected.first().copied().filter(|p| !p.is_empty())
                );
                socket
                    .send(reqwest_websocket::Message::Text("echo".into()))
                    .await
                    .unwrap();
                let message = socket.next().await.unwrap().unwrap();
                assert!(
                    matches!(message, reqwest_websocket::Message::Text(text) if text == "echo")
                );
            }
            server.await.unwrap();
        }
    }

    /// A mock API server that answers `101` — so the exec/attach/port-forward
    /// it names is already running on the cluster — but with a
    /// `Sec-WebSocket-Accept` that can never validate, forcing
    /// the library to reject it. The "started" callback must
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
