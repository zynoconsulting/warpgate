//! The authorization flow shared by the database protocols (MySQL, PostgreSQL).
//!
//! Both speak the same sequence: IP block, user lockout, full credential
//! policy acceptance (password, and whatever further factor the policy
//! demands) into an [`AuthorizedIdentity`], role-based target authorization,
//! then — only when no role grants the target — an activated self-service
//! ticket for that same user and target, admin approval, and admission. A
//! ticket only ever supplies the target grant on top of an identity that
//! already cleared every other check; it never bypasses a password, MFA, web
//! approval, an IP restriction or a lockout. `ticket-<secret>` authentication
//! ([`AuthSelector::Ticket`]) is a separate selector entirely and is
//! unaffected by any of this.
//!
//! The two protocols differ only in how they word a handful of messages.
//! That difference is [`DbAuthTransport`]; everything else is
//! [`run_db_authorization`], so the two protocols cannot drift apart on any
//! of the security-relevant steps.

use std::net::IpAddr;

use tracing::{error, info, warn};
use url::Url;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthSelector, CredentialKind, RememberApprovalBy,
};
use warpgate_common::{Protocol, Secret, UserSessionId, WarpgateError};

use crate::approvals::{GateOutcome, GatedConnection};
use crate::auth::submit_credential;
use crate::login_protection::FailedAttemptInfo;
use crate::{
    ApprovedTarget, AuthorizedIdentity, ConfigProvider, Services, TargetAuthorization,
    authorize_and_spend_ticket, authorize_for_target, grant_active_self_service_ticket,
    wait_for_auth_completion,
};

/// Proof that the success message has not been sent yet. Exactly one is minted
/// per login and consumed by [`DbAuthTransport::send_auth_ok`], so a second send
/// doesn't compile — both protocols' clients treat a repeat as a protocol error.
#[non_exhaustive]
pub struct AuthOkPermit;

#[allow(async_fn_in_trait)]
pub trait DbAuthTransport {
    /// The owning protocol's error type. Core failures must convert into it so
    /// the flow can propagate rather than fail open.
    type Error: From<WarpgateError>;

    const PROTOCOL: Protocol;

    /// Whether this protocol can present a web-approval prompt mid-authentication.
    /// When false, a policy requiring web approval denies before the success
    /// message is sent, so the client sees a clean denial rather than an OK packet
    /// immediately followed by an error.
    const SUPPORTS_WEB_APPROVAL: bool;

    /// Ask the client for a password. `Ok(None)` means this protocol has no way
    /// to ask again — MySQL sends its password once, inside the handshake — and
    /// the login is denied.
    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, Self::Error>;

    /// Report a successful authentication. Consumes the login's only
    /// [`AuthOkPermit`], which is what limits it to one call.
    async fn send_auth_ok(&mut self, permit: AuthOkPermit) -> Result<(), Self::Error>;

    /// The gateway's externally reachable URL. Supplied by the protocol because
    /// deriving it lives in a crate above this one.
    async fn external_url(&mut self) -> Result<Url, Self::Error>;

    /// Show the user the web-approval link. `Ok(false)` if this protocol has no
    /// way to display one mid-authentication, which denies the login.
    async fn send_web_approval_prompt(
        &mut self,
        url: &Url,
        identification_string: &str,
    ) -> Result<bool, Self::Error>;

    /// Tell the client the login was denied.
    async fn send_denied(&mut self) -> Result<(), Self::Error>;

    /// Announce to the client that session is waiting for admin approval.
    /// The impl may take and consume the auth_ok permit at this point.
    async fn notify_awaiting_admin_approval(
        &mut self,
        _auth_ok: &mut Option<AuthOkPermit>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

async fn hold_for_admin_approval<T: DbAuthTransport>(
    transport: &mut T,
    services: &Services,
    authorization: TargetAuthorization,
    session_id: UserSessionId,
    connection: GatedConnection,
    auth_ok: &mut Option<AuthOkPermit>,
) -> Result<GateOutcome, T::Error> {
    services
        .require_admin_approval(authorization, session_id, connection, || async move {
            transport.notify_awaiting_admin_approval(auth_ok).await
        })
        .await
}

/// Authorizes a database-protocol login end to end.
///
/// `Ok(None)` means the login was denied and the client has already been told;
/// the caller only has to stop. A returned [`ApprovedTarget`] is proof the user
/// may open the target it names *and* that any administrator gate on it let this
/// connection through.
pub async fn run_db_authorization<T: DbAuthTransport>(
    transport: &mut T,
    services: &Services,
    session_id: UserSessionId,
    selector: AuthSelector,
    remote_ip: IpAddr,
) -> Result<Option<ApprovedTarget>, T::Error> {
    // A lookup error must fail closed: propagate it rather than letting a
    // possibly-blocked IP through.
    if let Some(block_info) = services
        .login_protection
        .check_ip_blocked(&remote_ip)
        .await?
    {
        warn!(
            ip = %remote_ip,
            expires_at = %block_info.expires_at,
            protocol = %T::PROTOCOL,
            "Auth from blocked IP"
        );
        transport.send_denied().await?;
        return Ok(None);
    }

    match selector {
        AuthSelector::User {
            username,
            target_name,
        } => {
            authorize_user(
                transport,
                services,
                session_id,
                &username,
                &target_name,
                remote_ip,
                AuthOkPermit,
            )
            .await
        }
        AuthSelector::Ticket { secret } => {
            let Some(authorization) = authorize_and_spend_ticket(
                &services.db,
                &services.login_protection,
                &secret,
                Some(remote_ip),
                T::PROTOCOL,
            )
            .await?
            else {
                transport.send_denied().await?;
                return Ok(None);
            };

            info!(
                "Authorized for {} with a ticket",
                authorization.target().name
            );
            let mut auth_ok = Some(AuthOkPermit);

            let outcome = hold_for_admin_approval(
                transport,
                services,
                authorization,
                session_id,
                GatedConnection {
                    remote_ip: Some(remote_ip),
                    // tickets aren't stable credential fingerprints
                    credentials: RememberApprovalBy::Nothing,
                },
                &mut auth_ok,
            )
            .await;

            let Some(approved) = outcome?.approved() else {
                warn!("Session was not approved by an administrator");
                transport.send_denied().await?;
                return Ok(None);
            };

            if let Some(permit) = auth_ok.take() {
                transport.send_auth_ok(permit).await?;
            }
            Ok(Some(approved))
        }
    }
}

async fn authorize_user<T: DbAuthTransport>(
    transport: &mut T,
    services: &Services,
    session_id: UserSessionId,
    username: &str,
    target_name: &str,
    remote_ip: IpAddr,
    auth_ok: AuthOkPermit,
) -> Result<Option<ApprovedTarget>, T::Error> {
    // As with the IP check above, a lookup error fails closed.
    if services
        .login_protection
        .check_user_locked(username)
        .await?
        .is_some()
    {
        warn!(%username, protocol = %T::PROTOCOL, "Auth for locked user");
        transport.send_denied().await?;
        return Ok(None);
    }

    let state_arc = services
        .create_auth_state(
            &session_id,
            username,
            T::PROTOCOL,
            target_name,
            &[CredentialKind::Password],
            Some(remote_ip),
            Some("password"),
        )
        .await?;

    // Sent before the approval prompt because some clients discard anything that
    // arrives ahead of it, which spends the permit early.
    let mut auth_ok = Some(auth_ok);

    loop {
        let verification = state_arc.lock().await.verify();

        match verification {
            AuthResult::Accepted { user_info } => {
                let identity = {
                    let state = state_arc.lock().await;
                    AuthorizedIdentity::from_auth_state(&state)
                };
                // Verified `Accepted` a moment ago; a state that no longer is
                // means the login was concurrently rejected — deny.
                let Some(identity) = identity else {
                    transport.send_denied().await?;
                    return Ok(None);
                };

                let Some(authorization) =
                    authorize_for_target_or_ticket(services, &identity, target_name).await?
                else {
                    warn!("Target {target_name} not authorized for user {username}");
                    record_password_failure(services, username, remote_ip, T::PROTOCOL).await;
                    transport.send_denied().await?;
                    return Ok(None);
                };

                let credentials = state_arc.lock().await.remembered_by();
                let Some(approved) = hold_for_admin_approval(
                    transport,
                    services,
                    authorization,
                    session_id,
                    GatedConnection {
                        remote_ip: Some(remote_ip),
                        credentials,
                    },
                    &mut auth_ok,
                )
                .await?
                .approved() else {
                    warn!("Session was not approved by an administrator");
                    transport.send_denied().await?;
                    return Ok(None);
                };

                if let Some(permit) = auth_ok.take() {
                    transport.send_auth_ok(permit).await?;
                }

                let _ = services
                    .login_protection
                    .clear_failed_attempts(&remote_ip, &user_info.username)
                    .await;

                return Ok(Some(approved));
            }

            AuthResult::Need(kinds) if kinds.contains(&CredentialKind::Password) => {
                let Some(password) = transport.prompt_password().await? else {
                    transport.send_denied().await?;
                    return Ok(None);
                };

                let outcome = submit_credential(
                    &mut *state_arc.lock().await,
                    AuthCredential::Password(password),
                    services.config_provider.as_ref(),
                    &services.login_protection,
                )
                .await?;

                // Only an invalid password counts toward brute-force protection;
                // a valid one that needs a further factor does not.
                if !outcome.is_valid() {
                    record_password_failure(services, username, remote_ip, T::PROTOCOL).await;
                    transport.send_denied().await?;
                    return Ok(None);
                }
            }

            AuthResult::Need(kinds) if kinds.contains(&CredentialKind::WebUserApproval) => {
                if services.try_web_approval_bypass(&state_arc).await? {
                    continue;
                }

                // Deny before the success message is sent: a protocol that can't
                // show the prompt would otherwise reach `send_denied` having
                // already spent the permit, sending the client OK then error.
                if !T::SUPPORTS_WEB_APPROVAL {
                    warn!(
                        protocol = %T::PROTOCOL,
                        "Web user approval is required but not supported by this protocol"
                    );
                    transport.send_denied().await?;
                    return Ok(None);
                }

                let identification_string =
                    state_arc.lock().await.identification_string().to_owned();

                let external_url = match transport.external_url().await {
                    Ok(url) => url,
                    Err(error) => {
                        error!("Failed to construct external URL");
                        transport.send_denied().await?;
                        return Err(error);
                    }
                };
                let login_url = state_arc
                    .lock()
                    .await
                    .construct_web_approval_url(external_url);

                if let Some(permit) = auth_ok.take() {
                    transport.send_auth_ok(permit).await?;
                }

                if !transport
                    .send_web_approval_prompt(&login_url, &identification_string)
                    .await?
                {
                    transport.send_denied().await?;
                    return Ok(None);
                }

                if !matches!(
                    wait_for_auth_completion(&state_arc).await,
                    AuthResult::Accepted { .. }
                ) {
                    warn!("Web user approval failed");
                    transport.send_denied().await?;
                    return Ok(None);
                }
            }

            // A factor this protocol can't collect.
            AuthResult::Need(_) => {
                transport.send_denied().await?;
                return Ok(None);
            }

            AuthResult::Rejected => {
                record_password_failure(services, username, remote_ip, T::PROTOCOL).await;
                transport.send_denied().await?;
                return Ok(None);
            }
        }
    }
}

/// Authorizes an already-fully-authenticated `identity` for `target_name`: a
/// role first (regardless of the target's own protocol -- same as the
/// pre-JIT behaviour this replaces, and still narrowed against `identity`'s
/// protocol by the caller's own [`ApprovedTarget::narrow`] afterwards), or
/// -- only when no role grants it -- an activated self-service ticket for
/// that same user and target, gated on the target actually speaking
/// `identity`'s protocol. A missing target, a role-less user with no
/// eligible ticket, and a role-less user whose target is of some other
/// protocol are all the same `None` here, so the caller's denial can't
/// distinguish them from each other.
///
/// The ticket supplies only the target grant on top of `identity`: it is
/// never itself a substitute for the credential policy that produced
/// `identity` in [`authorize_user`].
async fn authorize_for_target_or_ticket(
    services: &Services,
    identity: &AuthorizedIdentity,
    target_name: &str,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    let Some(target) = services
        .config_provider
        .get_target_by_name(target_name)
        .await?
    else {
        return Ok(None);
    };

    if let Some(authorization) =
        authorize_for_target(services.config_provider.as_ref(), identity, target.clone()).await?
    {
        return Ok(Some(authorization));
    }

    if target.options.protocol() != identity.protocol() {
        return Ok(None);
    }

    let Some(ticket_id) =
        grant_active_self_service_ticket(&services.db, identity.user_info().id, target.id).await?
    else {
        return Ok(None);
    };

    info!(
        target = %target_name,
        username = %identity.user_info().username,
        "Authorized target access with an activated self-service ticket"
    );
    Ok(Some(TargetAuthorization::for_ticket_session(
        identity.user_info().clone(),
        target,
        ticket_id,
        identity.protocol(),
    )?))
}

async fn record_password_failure(
    services: &Services,
    username: &str,
    remote_ip: IpAddr,
    protocol: Protocol,
) {
    let _ = services
        .login_protection
        .record_failed_attempt(FailedAttemptInfo {
            username: username.to_owned(),
            remote_ip,
            protocol,
            credential_type: "password".to_owned(),
        })
        .await;
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, EntityTrait};
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common::auth::AuthStateUserInfo;
    use warpgate_common::helpers::hash::hash_secret;
    use warpgate_common::{DatabaseTargetAuth, Target, TargetOptions, TargetPostgresOptions, Tls};
    use warpgate_db_entities as e;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use super::*;
    use crate::approvals::tests::delivery::test_services;

    fn postgres_target() -> Target {
        Target {
            id: Uuid::new_v4(),
            name: "pg".into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Postgres(TargetPostgresOptions {
                host: "localhost".into(),
                port: 5432,
                username: "postgres".into(),
                auth: DatabaseTargetAuth::default(),
                tls: Tls::default(),
                idle_timeout: None,
                default_database_name: None,
                protocol_version: Default::default(),
            }),
            rate_limit_bytes_per_second: None,
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        }
    }

    /// A migrated database with `services` wired to it, one user and one
    /// Postgres target, so every test here differs only in the role/ticket
    /// rows it adds on top.
    async fn db_fixture() -> (DatabaseConnection, Services, Target, Uuid) {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        let services = test_services(&db).await;

        let user_id = Uuid::new_v4();
        e::User::ActiveModel {
            id: Set(user_id),
            username: Set("alice".into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(&db)
        .await
        .unwrap();

        let target = postgres_target();
        e::Target::ActiveModel {
            id: Set(target.id),
            name: Set(target.name.clone()),
            description: Set(String::new()),
            kind: Set(e::Target::TargetKind::Postgres),
            options: Set(serde_json::to_value(&target.options).unwrap()),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();

        (db, services, target, user_id)
    }

    /// Grants `user_id` a role authorizing `target_id`, through a fresh role
    /// created just for this assignment.
    async fn grant_role(db: &DatabaseConnection, user_id: Uuid, target_id: Uuid) {
        let role_id = Uuid::new_v4();
        e::Role::ActiveModel {
            id: Set(role_id),
            name: Set(format!("role-{role_id}")),
            description: Set(String::new()),
            is_default: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
        e::UserRoleAssignment::ActiveModel {
            user_id: Set(user_id),
            role_id: Set(role_id),
            granted_at: Set(None),
            expires_at: Set(None),
            revoked_at: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        e::TargetRoleAssignment::ActiveModel {
            target_id: Set(target_id),
            role_id: Set(role_id),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// Inserts a self-service ticket for `user_id`/`target_id` with one use
    /// left, returning its id.
    async fn insert_self_service_ticket(
        db: &DatabaseConnection,
        user_id: Uuid,
        target_id: Uuid,
    ) -> Uuid {
        let ticket_id = Uuid::new_v4();
        e::Ticket::ActiveModel {
            id: Set(ticket_id),
            secret_hash: Set(hash_secret(&format!("t1cket-{ticket_id}"))),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(target_id),
            uses_left: Set(Some(1)),
            self_service: Set(true),
            expiry: Set(None),
            created: Set(OffsetDateTime::now_utc()),
        }
        .insert(db)
        .await
        .unwrap();
        ticket_id
    }

    fn identity_for(user_id: Uuid, protocol: Protocol) -> AuthorizedIdentity {
        AuthorizedIdentity::for_authenticated_session(
            AuthStateUserInfo {
                id: user_id,
                username: "alice".into(),
            },
            protocol,
        )
    }

    async fn uses_left(db: &DatabaseConnection, ticket_id: Uuid) -> Option<i16> {
        e::Ticket::Entity::find_by_id(ticket_id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .uses_left
    }

    /// A role grants access outright and leaves an otherwise-eligible ticket
    /// completely untouched -- role wins, no ticket spent, no attribution.
    #[tokio::test]
    async fn role_wins_with_no_spend() {
        let (db, services, target, user_id) = db_fixture().await;
        grant_role(&db, user_id, target.id).await;
        let ticket_id = insert_self_service_ticket(&db, user_id, target.id).await;

        let identity = identity_for(user_id, Protocol::Postgres);
        let authorization = authorize_for_target_or_ticket(&services, &identity, &target.name)
            .await
            .unwrap()
            .expect("the role should authorize");
        assert_eq!(authorization.ticket_id(), None);
        assert_eq!(uses_left(&db, ticket_id).await, Some(1));
    }

    /// With no role, an activated self-service ticket for the same user and
    /// target grants access and is attributed on the authorization.
    #[tokio::test]
    async fn ticket_grants_when_no_role() {
        let (db, services, target, user_id) = db_fixture().await;
        let ticket_id = insert_self_service_ticket(&db, user_id, target.id).await;

        let identity = identity_for(user_id, Protocol::Postgres);
        let authorization = authorize_for_target_or_ticket(&services, &identity, &target.name)
            .await
            .unwrap()
            .expect("the ticket should authorize");
        assert_eq!(authorization.ticket_id(), Some(ticket_id));
        assert_eq!(uses_left(&db, ticket_id).await, Some(0));
    }

    /// An identity authenticated under a different protocol than the target
    /// actually is must be denied without ever spending the ticket -- a
    /// ticket never authorizes access to a target of another protocol.
    #[tokio::test]
    async fn protocol_mismatch_denies_without_spending() {
        let (db, services, target, user_id) = db_fixture().await;
        let ticket_id = insert_self_service_ticket(&db, user_id, target.id).await;

        let identity = identity_for(user_id, Protocol::MySql);
        let authorization = authorize_for_target_or_ticket(&services, &identity, &target.name)
            .await
            .unwrap();
        assert!(authorization.is_none());
        assert_eq!(uses_left(&db, ticket_id).await, Some(1));
    }

    /// A target that doesn't exist denies the same way a role-less,
    /// ticket-less user would -- the caller can't tell the two apart.
    #[tokio::test]
    async fn missing_target_denies() {
        let (_db, services, _target, user_id) = db_fixture().await;
        let identity = identity_for(user_id, Protocol::Postgres);
        let authorization = authorize_for_target_or_ticket(&services, &identity, "no-such-target")
            .await
            .unwrap();
        assert!(authorization.is_none());
    }
}
