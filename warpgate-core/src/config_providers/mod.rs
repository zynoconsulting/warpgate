use std::collections::HashSet;
use std::net::IpAddr;
use std::ops::Deref;

mod db;
mod sso_user;

pub use db::DatabaseConfigProvider;
use enum_dispatch::enum_dispatch;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Select};
pub use sso_user::resolve_and_map_sso_user;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthState, AuthStateUserInfo, CredentialKind, CredentialPolicy,
    StoredCredential,
};
use warpgate_common::helpers::hash::hash_secret;
use warpgate_common::{
    Protocol, Secret, SpecificTarget, Target, TargetOptions, TargetOptionsVariant, User,
    WarpgateError,
};
use warpgate_db_entities as e;
use warpgate_sso::SsoProviderConfig;

use crate::login_protection::LoginProtectionService;

#[enum_dispatch]
pub enum ConfigProviderEnum {
    Database(DatabaseConfigProvider),
}

#[enum_dispatch(ConfigProviderEnum)]
#[allow(async_fn_in_trait)]
pub trait ConfigProvider {
    async fn list_users(&self) -> Result<Vec<User>, WarpgateError>;

    async fn list_targets(&self) -> Result<Vec<Target>, WarpgateError>;

    async fn get_target_by_name(&self, name: &str) -> Result<Option<Target>, WarpgateError>;

    async fn get_target_by_id(&self, id: Uuid) -> Result<Option<Target>, WarpgateError>;

    async fn get_target_by_hostname(&self, hostname: &str)
    -> Result<Option<Target>, WarpgateError>;

    async fn validate_credential(
        &self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<Option<StoredCredential>, WarpgateError>;

    async fn username_for_sso_credential(
        &self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError>;

    async fn apply_sso_role_mappings(
        &self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        active_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    /// Similar to `apply_sso_role_mappings` but operates on *admin* roles.
    async fn apply_sso_admin_role_mappings(
        &self,
        username: &str,
        managed_admin_role_names: Option<Vec<String>>,
        active_admin_role_names: Vec<String>,
    ) -> Result<(), WarpgateError>;

    async fn get_credential_policy(
        &self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError>;

    async fn authorize_target(&self, username: &str, target: &str) -> Result<bool, WarpgateError>;

    async fn authorize_target_by_id(
        &self,
        user_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, WarpgateError>;

    /// IDs of all targets the user is authorized for, in a single query.
    async fn authorized_target_ids(&self, user_id: Uuid) -> Result<HashSet<Uuid>, WarpgateError>;

    async fn update_public_key_last_used(
        &self,
        username: &str,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError>;

    async fn validate_api_token(&self, token: &str) -> Result<Option<User>, WarpgateError>;
}

/// Proof that a user authenticated for a given protocol, and so may be handed to
/// [`authorize_for_target`]. Every constructor corresponds to a real
/// authentication path, so a new protocol can't authorize a target by building an
/// [`AuthStateUserInfo`] out of thin air — it has to route through one of these.
#[derive(Clone)]
pub struct AuthorizedIdentity {
    user_info: AuthStateUserInfo,
    protocol: Protocol,
}

impl AuthorizedIdentity {
    /// From an [`AuthState`] that has reached [`AuthResult::Accepted`] — i.e. the
    /// per-protocol credential policy was satisfied. `None` otherwise, so the
    /// gate can't be reached with an unsatisfied state.
    pub fn from_auth_state(state: &AuthState) -> Option<Self> {
        match state.verify() {
            AuthResult::Accepted { user_info } => Some(Self {
                user_info,
                protocol: state.protocol(),
            }),
            AuthResult::Need(_) | AuthResult::Rejected => None,
        }
    }

    /// For a request already authenticated somewhere else:
    /// * [FullUserAuthorization::identity] - hTTP cookie session or API token
    /// * Kubernetes credential check
    ///
    /// Everything else must use [Self::from_auth_state]
    pub const fn for_authenticated_session(
        user_info: AuthStateUserInfo,
        protocol: Protocol,
    ) -> Self {
        Self {
            user_info,
            protocol,
        }
    }

    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl std::ops::Deref for AuthorizedIdentity {
    type Target = AuthStateUserInfo;

    fn deref(&self) -> &Self::Target {
        &self.user_info
    }
}

/// Proof that a user is authorized for a specific target (but not necessarily allowed to connect yet pending approval, see [ApprovedTarget]).
pub struct TargetAuthorization<O = TargetOptions> {
    user_info: AuthStateUserInfo,
    target: SpecificTarget<O>,
    protocol: Protocol,
    ticket_id: Option<Uuid>,
}

impl TargetAuthorization {
    #[cfg(test)]
    pub(crate) fn for_test(
        user_info: AuthStateUserInfo,
        target: Target,
        protocol: Protocol,
    ) -> Self {
        Self {
            user_info,
            target: SpecificTarget::any(target),
            protocol,
            ticket_id: None,
        }
    }

    pub fn for_ticket_session(
        user_info: AuthStateUserInfo,
        target: Target,
        ticket_id: Option<Uuid>,
        protocol: Protocol,
    ) -> Result<Self, WarpgateError> {
        Ok(Self {
            user_info,
            target: SpecificTarget::any(target),
            protocol,
            ticket_id,
        })
    }

    pub fn narrow<O: TargetOptionsVariant>(self) -> Result<TargetAuthorization<O>, WarpgateError> {
        if O::PROTOCOL != self.protocol {
            return Err(WarpgateError::InvalidTarget);
        }
        Ok(TargetAuthorization {
            user_info: self.user_info,
            target: self.target.narrow()?,
            protocol: self.protocol,
            ticket_id: self.ticket_id,
        })
    }
}

impl<O> TargetAuthorization<O> {
    pub const fn user_info(&self) -> &AuthStateUserInfo {
        &self.user_info
    }

    /// The target this authorization was granted for. Carrying it means a dial
    /// site never has to re-resolve — and so can't resolve a *different* one.
    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn specific_target(&self) -> &SpecificTarget<O> {
        &self.target
    }

    pub const fn options(&self) -> &O {
        self.target.options()
    }

    /// The protocol the authorizing authentication ran under.
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The ticket this authorization came from, if any.
    pub const fn ticket_id(&self) -> Option<Uuid> {
        self.ticket_id
    }
}

impl ApprovedTarget {
    /// Narrows the capability to one protocol's options variant. The admission
    /// is unchanged — only the type gets more precise.
    pub fn narrow<O: TargetOptionsVariant>(self) -> Result<ApprovedTarget<O>, WarpgateError> {
        Ok(ApprovedTarget(self.0.narrow()?))
    }
}

/// Proof that user is both authorized for a target and has approval, if needed. This is the final pre-connection green light. Not cloneable because one instance = one connection
pub struct ApprovedTarget<O = TargetOptions>(TargetAuthorization<O>);

impl<O> std::fmt::Debug for ApprovedTarget<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedTarget")
            .field("target", &self.0.target().name)
            .field("user", &self.0.user_info().username)
            .finish()
    }
}

impl<O> ApprovedTarget<O> {
    pub(crate) const fn new(authorization: TargetAuthorization<O>) -> Self {
        Self(authorization)
    }

    pub fn into_parts(self) -> (AuthStateUserInfo, SpecificTarget<O>) {
        (self.0.user_info, self.0.target)
    }
}

impl<O> Deref for ApprovedTarget<O> {
    type Target = TargetAuthorization<O>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Checks whether the user may access the target; `Ok(None)` means not
/// authorized.
///
/// Takes the resolved [`Target`] rather than a name so the authorization and the
/// subsequent connection are provably about the same row.
pub async fn authorize_for_target<C: ConfigProvider + ?Sized>(
    config_provider: &C,
    identity: &AuthorizedIdentity,
    target: Target,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    Ok(config_provider
        .authorize_target_by_id(identity.user_info.id, target.id)
        .await?
        .then(|| TargetAuthorization {
            user_info: identity.user_info.clone(),
            target: SpecificTarget::any(target),
            protocol: identity.protocol,
            ticket_id: None,
        }))
}

/// Resolves the target by name and checks authorization. A target that
/// doesn't exist and one the user may not reach are the same `None` here, so
/// a caller can't be used as a target-existence oracle.
pub async fn authorize_for_target_by_name<C: ConfigProvider + ?Sized>(
    config_provider: &C,
    identity: &AuthorizedIdentity,
    target_name: &str,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    match config_provider.get_target_by_name(target_name).await? {
        Some(target) => authorize_for_target(config_provider, identity, target).await,
        None => Ok(None),
    }
}

/// The eligibility constraints for a self-service ticket to act as a
/// server-side authorization grant: bound to this user and target, and not
/// expired. Deliberately silent on `uses_left` — a granting caller and a
/// re-checking caller apply that differently, so it lives in each of their
/// own queries instead of here (see [`grant_active_self_service_ticket`] and
/// [`has_active_self_service_ticket`]).
fn active_self_service_ticket_base_query(
    query: Select<e::Ticket::Entity>,
    user_id: Uuid,
    target_id: Uuid,
) -> Select<e::Ticket::Entity> {
    let now = OffsetDateTime::now_utc();
    query
        .filter(e::Ticket::Column::UserId.eq(user_id))
        .filter(e::Ticket::Column::TargetId.eq(target_id))
        .filter(e::Ticket::Column::SelfService.eq(true))
        .filter(
            Expr::col(e::Ticket::Column::Expiry)
                .is_null()
                .or(Expr::col(e::Ticket::Column::Expiry).gt(now)),
        )
}

/// Grant target access through an activated self-service ticket for this user
/// and target, spending a bounded ticket's use if that's the only eligible
/// kind. Returns the granting ticket's id, or `None` if none is eligible.
///
/// An unlimited-use (`uses_left` `NULL`) ticket is preferred and left
/// untouched: a Kubernetes client's one logical operation fans out into many
/// requests, but only the correlated session's opening request reaches this
/// path (see [`has_active_self_service_ticket`] for the per-request re-check,
/// which must not spend again), so a bounded ticket is only ever charged once
/// per session — the same cost as ticket-secret authentication.
///
/// Two sessions can race for a bounded ticket's last use; the loser's spend
/// fails with `InvalidTicket` and falls through to the next candidate rather
/// than denying access outright when another eligible ticket exists.
async fn grant_active_self_service_ticket(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<Option<Uuid>, WarpgateError> {
    let candidates =
        active_self_service_ticket_base_query(e::Ticket::Entity::find(), user_id, target_id)
            .all(db)
            .await?;

    if let Some(ticket) = candidates.iter().find(|ticket| ticket.uses_left.is_none()) {
        return Ok(Some(ticket.id));
    }

    for ticket in candidates
        .iter()
        .filter(|ticket| ticket.uses_left.is_some_and(|left| left > 0))
    {
        match e::Ticket::spend_use(db, ticket.id).await {
            Ok(()) => return Ok(Some(ticket.id)),
            Err(WarpgateError::InvalidTicket(_)) => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(None)
}

/// Authorize a previously authenticated identity through an activated
/// self-service ticket for the same user and target.
///
/// This is distinct from ticket-secret authentication: this function does not
/// itself verify that `identity`'s caller was fully authenticated — it takes
/// that on faith from `AuthorizedIdentity` and only ever supplies the
/// temporary target grant on top of it. The ordering guarantee comes from its
/// single caller, `authorize_kubernetes_target` in
/// `warpgate-protocol-kubernetes`, which runs the full identity check
/// (transport credential and, where configured, credential policy / MFA)
/// before constructing the `identity` it passes in here.
pub async fn authorize_active_self_service_ticket(
    db: &DatabaseConnection,
    identity: AuthorizedIdentity,
    target: Target,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    let ticket_id =
        grant_active_self_service_ticket(db, identity.user_info().id, target.id).await?;

    Ok(ticket_id.map(|ticket_id| TargetAuthorization {
        user_info: identity.user_info().clone(),
        target: SpecificTarget::any(target),
        protocol: identity.protocol(),
        ticket_id: Some(ticket_id),
    }))
}

/// Re-check a server-side self-service grant so revocation and expiry apply to
/// every request in a correlated Kubernetes session. Takes the specific
/// `ticket_id` the session was granted through — not just any self-service
/// ticket matching `user_id`/`target_id` — so a used-up (or expired, or
/// revoked) *sibling* ticket for the same user/target can't paper over the
/// granting ticket having been revoked. Deliberately ignores `uses_left` on
/// that specific ticket: the session's one use was already spent (or was
/// never needed, for an unlimited ticket) when the grant was made, and
/// re-checking must not spend again on each of a `kubectl` command's fan-out
/// of requests.
pub async fn has_active_self_service_ticket(
    db: &DatabaseConnection,
    ticket_id: Uuid,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<bool, WarpgateError> {
    let ticket =
        active_self_service_ticket_base_query(e::Ticket::Entity::find(), user_id, target_id)
            .filter(e::Ticket::Column::Id.eq(ticket_id))
            .one(db)
            .await?;
    Ok(ticket.is_some())
}

pub async fn authorize_and_spend_ticket(
    db: &DatabaseConnection,
    login_protection: &LoginProtectionService,
    secret: &Secret<String>,
    remote_ip: Option<IpAddr>,
    protocol: Protocol,
) -> Result<Option<TargetAuthorization>, WarpgateError> {
    match validate_ticket(db, login_protection, secret, remote_ip, protocol).await? {
        Some(ticket) => ticket.spend(db).await,
        None => Ok(None),
    }
}

/// A valid ticket credential, which has not yet consumed a use. This can identify
/// requests joining an existing session even after its final use was consumed.
/// Only `spend` can turn it into authorization for a new session.
pub struct ValidatedTicket {
    authorization: TargetAuthorization,
    id: Uuid,
}

impl ValidatedTicket {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn user_info(&self) -> &AuthStateUserInfo {
        self.authorization.user_info()
    }

    pub fn target(&self) -> &Target {
        self.authorization.target()
    }

    pub async fn spend(
        self,
        db: &DatabaseConnection,
    ) -> Result<Option<TargetAuthorization>, WarpgateError> {
        match e::Ticket::spend_use(db, self.id).await {
            Ok(()) => Ok(Some(self.authorization)),
            Err(WarpgateError::InvalidTicket(_)) => {
                warn!(ticket_id = %self.id, "Ticket is revoked or used up");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

pub async fn validate_ticket(
    db: &DatabaseConnection,
    login_protection: &LoginProtectionService,
    secret: &Secret<String>,
    remote_ip: Option<IpAddr>,
    protocol: Protocol,
) -> Result<Option<ValidatedTicket>, WarpgateError> {
    // Spending a ticket is a login, so a blocked IP can't do it either. Checked ahead of the
    // lookup so a blocked caller can't use this as a ticket-existence oracle.
    if let Some(ip) = remote_ip
        && login_protection.check_ip_blocked(&ip).await?.is_some()
    {
        warn!("Ticket presented from a blocked IP: {ip}");
        return Ok(None);
    }

    let ticket = {
        e::Ticket::Entity::find()
            .filter(e::Ticket::Column::SecretHash.eq(hash_secret(secret.expose_secret())))
            .one(db)
            .await?
    };
    if let Some(ticket) = ticket {
        if let Some(datetime) = ticket.expiry
            && datetime < OffsetDateTime::now_utc()
        {
            warn!("Ticket has expired: {}", &ticket.id);
            return Ok(None);
        }

        let Some(ticket_user) = e::User::Entity::find_by_id(ticket.user_id).one(db).await? else {
            return Err(WarpgateError::UserNotFound(ticket.user_id.to_string()));
        };
        let user = User::try_from(ticket_user)?;

        // A ticket is only as good as its user, and this path mints authorization
        // directly, bypassing the auth state store where interactive logins are
        // vetted. A denied user returns the missing-ticket shape, preserving the
        // no-existence-oracle property.
        if !crate::auth_state_store::vet_credential_bearer(login_protection, &user, remote_ip)
            .await?
        {
            return Ok(None);
        }

        let Some(ticket_target) = e::Target::Entity::find_by_id(ticket.target_id)
            .one(db)
            .await?
        else {
            warn!("Ticket target not found: {}", &ticket.target_id);
            return Ok(None);
        };

        let target = Target::try_from(ticket_target)?;

        if target.options.protocol() != protocol {
            warn!(
                "Ticket {} is for a {:?} target, presented over {:?}",
                &ticket.id,
                target.options.protocol(),
                protocol
            );
            return Ok(None);
        }

        // A ticket binds user↔target directly, so it mints the proof without a
        // role check — that's what makes it a ticket.
        Ok(Some(ValidatedTicket {
            id: ticket.id,
            authorization: TargetAuthorization {
                user_info: (&user).into(),
                target: SpecificTarget::any(target),
                protocol,
                ticket_id: Some(ticket.id),
            },
        }))
    } else {
        warn!("Ticket not found");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast;
    use warpgate_common::auth::CredentialPolicyResponse;
    use warpgate_common::{TargetHTTPOptions, TargetSSHOptions, Tls, UserSessionId};

    use super::*;

    fn http_target() -> Target {
        Target {
            id: Uuid::new_v4(),
            name: "web".into(),
            description: String::new(),
            allow_roles: vec![],
            options: TargetOptions::Http(TargetHTTPOptions {
                url: "http://target".into(),
                tls: Tls::default(),
                headers: Default::default(),
                external_host: None,
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

    #[test]
    fn specific_narrows_only_matching_kind_and_protocol() {
        let user = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };

        let narrowed = TargetAuthorization::for_test(user.clone(), http_target(), Protocol::Http)
            .narrow::<TargetHTTPOptions>();
        assert!(narrowed.is_ok_and(|a| a.options().url == "http://target"));

        let wrong_kind = TargetAuthorization::for_test(user.clone(), http_target(), Protocol::Http)
            .narrow::<TargetSSHOptions>();
        assert!(wrong_kind.is_err());

        let wrong_protocol = TargetAuthorization::for_test(user, http_target(), Protocol::Ssh)
            .narrow::<TargetHTTPOptions>();
        assert!(wrong_protocol.is_err());
    }

    /// A migrated database holding one user and one HTTP target, so every
    /// ticket test starts from the same base and differs only in the tickets
    /// it inserts on top.
    #[cfg(feature = "sqlite")]
    async fn db_fixture(
        require_approval: bool,
    ) -> (DatabaseConnection, LoginProtectionService, Target, Uuid) {
        use sea_orm::ActiveValue::Set;
        use sea_orm::{ActiveModelTrait, Database};
        use warpgate_db_entities::Parameters::{
            ConfigMigrationValues, set_config_migration_values,
        };

        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();
        let login_protection = LoginProtectionService::new(db.clone()).await.unwrap();

        let target = http_target();
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
        e::Target::ActiveModel {
            id: Set(target.id),
            name: Set(target.name.clone()),
            description: Set(String::new()),
            kind: Set(e::Target::TargetKind::Http),
            options: Set(serde_json::to_value(&target.options).unwrap()),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(require_approval),
        }
        .insert(&db)
        .await
        .unwrap();

        (db, login_protection, target, user_id)
    }

    /// Inserts a ticket row for `user_id`/`target_id` with a fresh secret and
    /// id, returning both. Shared by the ticket-secret and self-service-grant
    /// tests so each only has to spell out what makes its ticket distinctive.
    #[cfg(feature = "sqlite")]
    async fn insert_ticket(
        db: &DatabaseConnection,
        user_id: Uuid,
        target_id: Uuid,
        self_service: bool,
        uses_left: Option<i16>,
        expiry: Option<OffsetDateTime>,
    ) -> (Uuid, Secret<String>) {
        use sea_orm::ActiveModelTrait;
        use sea_orm::ActiveValue::Set;

        let ticket_id = Uuid::new_v4();
        let secret = format!("t1cket-{ticket_id}");
        e::Ticket::ActiveModel {
            id: Set(ticket_id),
            secret_hash: Set(hash_secret(&secret)),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(target_id),
            uses_left: Set(uses_left),
            self_service: Set(self_service),
            expiry: Set(expiry),
            created: Set(OffsetDateTime::now_utc()),
        }
        .insert(db)
        .await
        .unwrap();
        (ticket_id, Secret::new(secret))
    }

    /// A migrated database holding one user, one HTTP target and one
    /// ticket-secret (non-self-service) ticket for it, so the ticket-secret
    /// tests differ only in what they set up differently.
    #[cfg(feature = "sqlite")]
    async fn ticket_fixture(
        require_approval: bool,
        uses_left: Option<i16>,
    ) -> (
        DatabaseConnection,
        LoginProtectionService,
        Target,
        Uuid,
        Secret<String>,
    ) {
        let (db, login_protection, target, user_id) = db_fixture(require_approval).await;
        let (ticket_id, secret) =
            insert_ticket(&db, user_id, target.id, false, uses_left, None).await;
        (db, login_protection, target, ticket_id, secret)
    }

    /// Convenience wrapper around [`authorize_active_self_service_ticket`]
    /// building the [`AuthorizedIdentity`] it requires from a bare user id, as
    /// every self-service-grant test does.
    #[cfg(feature = "sqlite")]
    async fn grant_for_user(
        db: &DatabaseConnection,
        user_id: Uuid,
        target: Target,
    ) -> Result<Option<TargetAuthorization>, WarpgateError> {
        let identity = AuthorizedIdentity::for_authenticated_session(
            AuthStateUserInfo {
                id: user_id,
                username: "alice".into(),
            },
            Protocol::Kubernetes,
        );
        authorize_active_self_service_ticket(db, identity, target).await
    }

    /// A ticket's spend is atomic with its authorization, gated target or not:
    /// an exhausted ticket establishes nothing, and a live one is down a use
    /// the moment the session exists — the administrator gate refunds through
    /// the question's row if it turns the session away.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_gated_targets_ticket_spends_at_authorization() {
        let (db, login_protection, _target, _ticket_id, secret) =
            ticket_fixture(true, Some(0)).await;

        let authorization =
            authorize_and_spend_ticket(&db, &login_protection, &secret, None, Protocol::Http)
                .await
                .unwrap();
        assert!(authorization.is_none());

        let (db, login_protection, _target, ticket_id, secret) =
            ticket_fixture(true, Some(1)).await;
        assert!(
            authorize_and_spend_ticket(&db, &login_protection, &secret, None, Protocol::Http)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            e::Ticket::Entity::find_by_id(ticket_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .uses_left,
            Some(0),
        );
    }

    /// Two presentations of a 1-use ticket race on the spend; only one may be
    /// authorized, however they interleave.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_ticket_spend_is_atomic_with_its_authorization() {
        let (db, login_protection, target, ticket_id, secret) =
            ticket_fixture(false, Some(1)).await;

        let first = validate_ticket(&db, &login_protection, &secret, None, Protocol::Http)
            .await
            .unwrap()
            .unwrap();
        let second = validate_ticket(&db, &login_protection, &secret, None, Protocol::Http)
            .await
            .unwrap()
            .unwrap();
        let (first, second) = tokio::join!(first.spend(&db), second.spend(&db));
        let authorizations: Vec<_> = [first.unwrap(), second.unwrap()]
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(authorizations.len(), 1);
        // The ticket travels with the authorization so the target session it
        // opens can record which ticket opened it.
        assert!(
            authorizations
                .iter()
                .all(|authorization| authorization.target().id == target.id
                    && authorization.ticket_id() == Some(ticket_id))
        );

        let second =
            authorize_and_spend_ticket(&db, &login_protection, &secret, None, Protocol::Http)
                .await
                .unwrap();
        assert!(second.is_none());

        assert_eq!(
            e::Ticket::Entity::find_by_id(ticket_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .uses_left,
            Some(0)
        );
    }

    /// An unlimited-use self-service ticket grants JIT access repeatedly
    /// without ever touching `uses_left` — it stays usable for the rest of
    /// its window, unlike a ticket-secret spend.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn unlimited_grant_leaves_uses_left_untouched() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (ticket_id, _secret) = insert_ticket(&db, user_id, target.id, true, None, None).await;

        for _ in 0..3 {
            let authorization = grant_for_user(&db, user_id, target.clone())
                .await
                .unwrap()
                .expect("unlimited ticket should grant");
            assert_eq!(authorization.ticket_id(), Some(ticket_id));
        }

        assert_eq!(
            e::Ticket::Entity::find_by_id(ticket_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .uses_left,
            None,
        );
    }

    /// A bounded self-service ticket grants exactly as many times as it has
    /// uses, spending one per grant, then stops authorizing once exhausted.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bounded_grant_spends_one_then_denies_at_zero() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (ticket_id, _secret) =
            insert_ticket(&db, user_id, target.id, true, Some(1), None).await;

        let authorization = grant_for_user(&db, user_id, target.clone())
            .await
            .unwrap()
            .expect("a fresh bounded ticket should grant once");
        assert_eq!(authorization.ticket_id(), Some(ticket_id));
        assert_eq!(
            e::Ticket::Entity::find_by_id(ticket_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .uses_left,
            Some(0),
        );

        // The use is gone: a second, separately-opened correlated session
        // finds nothing to grant it.
        assert!(
            grant_for_user(&db, user_id, target.clone())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A ticket that isn't self-service — one minted for `ticket-<secret>`
    /// authentication — must never authorize a separately-authenticated
    /// identity, however many uses it has left.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn admin_ticket_never_grants() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        insert_ticket(&db, user_id, target.id, false, None, None).await;

        assert!(
            grant_for_user(&db, user_id, target)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A self-service ticket past its expiry must never grant, even if it
    /// still has uses left.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn expired_self_service_ticket_never_grants() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let past = OffsetDateTime::now_utc() - time::Duration::seconds(60);
        insert_ticket(&db, user_id, target.id, true, None, Some(past)).await;

        assert!(
            grant_for_user(&db, user_id, target)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Two sessions racing for a bounded ticket's last use must not both
    /// spend it, but a second eligible ticket lets the loser through instead
    /// of being denied outright.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn grant_falls_through_to_next_ticket_when_a_race_is_lost() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (first_id, _) = insert_ticket(&db, user_id, target.id, true, Some(1), None).await;
        let (second_id, _) = insert_ticket(&db, user_id, target.id, true, Some(1), None).await;

        let (first, second) = tokio::join!(
            grant_for_user(&db, user_id, target.clone()),
            grant_for_user(&db, user_id, target.clone()),
        );
        let granted: HashSet<Uuid> = [first.unwrap(), second.unwrap()]
            .into_iter()
            .flatten()
            .map(|authorization| {
                authorization
                    .ticket_id()
                    .expect("grant carries a ticket id")
            })
            .collect();
        // Both requests found a ticket to spend rather than one losing the
        // race outright, and each spent a distinct ticket.
        assert_eq!(granted, HashSet::from([first_id, second_id]));

        for ticket_id in [first_id, second_id] {
            assert_eq!(
                e::Ticket::Entity::find_by_id(ticket_id)
                    .one(&db)
                    .await
                    .unwrap()
                    .unwrap()
                    .uses_left,
                Some(0),
            );
        }
    }

    /// When both an unlimited and a bounded ticket are eligible, the
    /// unlimited one is preferred and the bounded one is left completely
    /// untouched — not even inspected for a race, since it's never a
    /// candidate once an unlimited ticket exists.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn grant_prefers_unlimited_ticket_and_leaves_bounded_one_untouched() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (unlimited_id, _) = insert_ticket(&db, user_id, target.id, true, None, None).await;
        let (bounded_id, _) = insert_ticket(&db, user_id, target.id, true, Some(1), None).await;

        let authorization = grant_for_user(&db, user_id, target)
            .await
            .unwrap()
            .expect("an eligible ticket should grant");
        assert_eq!(authorization.ticket_id(), Some(unlimited_id));

        assert_eq!(
            e::Ticket::Entity::find_by_id(bounded_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .uses_left,
            Some(1),
        );
    }

    /// The per-request re-check must not consider `uses_left` on the specific
    /// ticket it was granted through — the session's use was already spent
    /// (or never needed) when it was granted — but must still respect that
    /// ticket's `self_service` and expiry.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn recheck_ignores_uses_left_but_respects_self_service_and_expiry() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (ticket_id, _) = insert_ticket(&db, user_id, target.id, true, Some(1), None).await;

        // Spend the only use, exactly as the opening request of a correlated
        // session would.
        let authorization = grant_for_user(&db, user_id, target.clone())
            .await
            .unwrap()
            .expect("a fresh bounded ticket should grant");
        assert_eq!(authorization.ticket_id(), Some(ticket_id));
        // Every later request in that same session re-checks the grant; it
        // must still see it as active although uses_left is now 0.
        assert!(
            has_active_self_service_ticket(&db, ticket_id, user_id, target.id)
                .await
                .unwrap()
        );

        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (admin_ticket_id, _) = insert_ticket(&db, user_id, target.id, false, None, None).await;
        assert!(
            !has_active_self_service_ticket(&db, admin_ticket_id, user_id, target.id)
                .await
                .unwrap()
        );

        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let past = OffsetDateTime::now_utc() - time::Duration::seconds(60);
        let (expired_ticket_id, _) =
            insert_ticket(&db, user_id, target.id, true, None, Some(past)).await;
        assert!(
            !has_active_self_service_ticket(&db, expired_ticket_id, user_id, target.id)
                .await
                .unwrap()
        );
    }

    /// The re-check must target the *specific* ticket a session was granted
    /// through, not just any self-service ticket matching the user/target: a
    /// used-up sibling ticket must not paper over the granting ticket having
    /// been revoked.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn recheck_targets_the_granting_ticket_not_a_sibling() {
        let (db, _login_protection, target, user_id) = db_fixture(false).await;
        let (granting_id, _) = insert_ticket(&db, user_id, target.id, true, Some(1), None).await;
        let (sibling_id, _) = insert_ticket(&db, user_id, target.id, true, Some(1), None).await;

        // The sibling is used up independently but stays unexpired — exactly
        // the row that would previously have satisfied a (user, target)-only
        // re-check regardless of which ticket actually opened the session.
        e::Ticket::spend_use(&db, sibling_id).await.unwrap();

        // The granting ticket is revoked.
        e::Ticket::Entity::delete_by_id(granting_id)
            .exec(&db)
            .await
            .unwrap();

        assert!(
            !has_active_self_service_ticket(&db, granting_id, user_id, target.id)
                .await
                .unwrap()
        );
    }

    struct FixedPolicy(bool);
    impl CredentialPolicy for FixedPolicy {
        fn is_sufficient(
            &self,
            _p: Protocol,
            _c: &HashSet<CredentialKind>,
        ) -> CredentialPolicyResponse {
            if self.0 {
                CredentialPolicyResponse::Ok
            } else {
                CredentialPolicyResponse::Need([CredentialKind::Password].into_iter().collect())
            }
        }
    }

    fn auth_state(satisfied: bool) -> AuthState {
        let (tx, _rx) = broadcast::channel(1);
        AuthState::new(
            UserSessionId(Uuid::new_v4()),
            None,
            AuthStateUserInfo {
                id: Uuid::nil(),
                username: "alice".into(),
            },
            Protocol::Kubernetes,
            String::new(),
            Box::new(FixedPolicy(satisfied)),
            tx,
        )
    }

    #[test]
    fn identity_minted_only_from_accepted_state() {
        // Accepted → a sealed identity carrying the state's protocol and user.
        let accepted = AuthorizedIdentity::from_auth_state(&auth_state(true))
            .expect("an accepted state yields an identity");
        assert_eq!(accepted.protocol(), Protocol::Kubernetes);
        assert_eq!(accepted.user_info().username, "alice");

        // An unsatisfied policy yields no identity, so `authorize_for_target`
        // can't be reached from a state that never passed the policy.
        assert!(AuthorizedIdentity::from_auth_state(&auth_state(false)).is_none());
    }
}
