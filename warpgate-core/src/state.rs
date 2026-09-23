use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, broadcast, watch};
use tokio_util::sync::DropGuard;
use tracing::error;
use uuid::Uuid;
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{NodeId, Protocol, Target, UserSessionId, WarpgateError};
use warpgate_db_entities::{SessionApprovalRequest, TargetSession, UserSession};

use crate::access_watch::{self, AccessGrant, AccessWatchSettings};
use crate::rate_limiting::{RateLimiterRegistry, RateLimiterStackHandle};
use crate::{SessionHandle, WarpgateServerHandle};

pub struct State {
    pub user_sessions: HashMap<UserSessionId, Arc<Mutex<UserSessionState>>>,
    db: DatabaseConnection,
    node_id: NodeId,
    rate_limiter_registry: Arc<Mutex<RateLimiterRegistry>>,
    change_sender: broadcast::Sender<()>,
    /// Nudges every access watcher (see [`crate::access_watch`]) to re-check
    /// its grant immediately instead of waiting out its interval — sent on a
    /// ticket revoke so a session ends promptly rather than up to
    /// `access_watch_interval` late.
    access_watch_nudges: Arc<watch::Sender<u64>>,
    access_watch_interval: Duration,
    access_watch_unconfirmed_limit: Duration,
}

impl State {
    pub fn new(
        db: &DatabaseConnection,
        rate_limiter_registry: &Arc<Mutex<RateLimiterRegistry>>,
        node_id: NodeId,
    ) -> Arc<Mutex<Self>> {
        let sender = broadcast::channel(2).0;
        let (access_watch_interval, access_watch_unconfirmed_limit) = access_watch::default_timing();
        Arc::new(Mutex::new(Self {
            user_sessions: HashMap::new(),
            db: db.clone(),
            node_id,
            rate_limiter_registry: rate_limiter_registry.clone(),
            change_sender: sender,
            access_watch_nudges: Arc::new(watch::channel(0u64).0),
            access_watch_interval,
            access_watch_unconfirmed_limit,
        }))
    }

    /// Wakes every access watcher on this node so it re-checks its grant now
    /// instead of on its next poll. Called when a ticket is deleted, so a
    /// revoke closes its sessions promptly rather than up to one interval
    /// late.
    pub fn nudge_access_watchers(&self) {
        self.access_watch_nudges.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// The sender behind [`Self::nudge_access_watchers`], for a caller (the
    /// cluster-notification bridge task) that fires it often and would
    /// otherwise have to lock the whole `State` just to reach it. Grab this
    /// once at startup rather than re-locking `State` on every notification.
    pub fn access_watch_sender(&self) -> Arc<watch::Sender<u64>> {
        self.access_watch_nudges.clone()
    }

    /// Speeds up access-watch polling for a test, so it does not have to wait
    /// out the production interval.
    #[cfg(test)]
    pub(crate) fn set_access_watch_timing(&mut self, interval: Duration, unconfirmed_limit: Duration) {
        self.access_watch_interval = interval;
        self.access_watch_unconfirmed_limit = unconfirmed_limit;
    }

    /// Registers a session with no owning node: it is a DB record any node
    /// may serve, kept alive by its own backing rather than this node's
    /// handle (a stored browser cookie session). The row's `node_id` is left
    /// unset — the only kind of session for which the orphan reaper looks
    /// elsewhere for liveness instead of this node's registration.
    pub async fn register_nonlocal_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        Self::register_user_session_in(this, protocol, false, state).await
    }

    /// Registers a session bound to this node: it is kept alive by this
    /// node's handle alone, so the row must record an owner — unowned it
    /// would back nothing and the orphan reaper would end it mid-use.
    pub async fn register_node_local_user_session(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        Self::register_user_session_in(this, protocol, true, state).await
    }

    async fn register_user_session_in(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        node_owned: bool,
        state: UserSessionStateInit,
    ) -> Result<Arc<Mutex<WarpgateServerHandle>>, WarpgateError> {
        let mut self_ = this.lock().await;
        let id = UserSessionId(Uuid::new_v4());

        // Read before the state is shared: locking a `UserSessionState` while
        // holding `State` is the reverse of the order everything else takes,
        // and is only safe here because nothing else can reach this one yet.
        // Not relying on that keeps the order true without an exception.
        let remote_address = state
            .remote_address
            .map_or_else(String::new, |address| address.to_string());
        let state = Arc::new(Mutex::new(UserSessionState::new(
            state,
            self_.change_sender.clone(),
        )));

        {
            use sea_orm::ActiveValue::Set;

            let values = UserSession::ActiveModel {
                id: Set(id),
                started: Set(OffsetDateTime::now_utc()),
                remote_address: Set(remote_address),
                protocol: Set(protocol.to_string()),
                // An unowned session is served by any node; recording an owner
                // would make the reaper end it when this node goes away.
                node_id: Set(node_owned.then_some(self_.node_id)),
                ..Default::default()
            };

            let db = &self_.db;
            values
                .insert(db)
                .await
                .context("Error inserting session")
                .map_err(WarpgateError::from)?;
        }

        Ok(self_.install_user_session(this, id, state, protocol, node_owned))
    }

    /// Registers a user session and wraps its raw connection stream with the
    /// session rate limiters in one step, so a raw-TCP protocol cannot serve
    /// an unlimited stream by forgetting the wrap.
    ///
    /// The session is necessarily connection-bound: it is this socket, and it
    /// ends with it — which is also every raw-TCP protocol's default.
    pub async fn register_user_session_with_stream<S>(
        this: &Arc<Mutex<Self>>,
        protocol: Protocol,
        state: UserSessionStateInit,
        stream: S,
    ) -> Result<
        (
            Arc<Mutex<WarpgateServerHandle>>,
            impl AsyncRead + AsyncWrite + Unpin + Send + use<S>,
        ),
        WarpgateError,
    >
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let handle = Self::register_node_local_user_session(this, protocol, state).await?;
        let wrapped = handle.lock().await.wrap_stream(stream).await?;
        Ok((handle, wrapped))
    }

    /// Registers a node-local view over an existing DB-backed user session — an
    /// HTTP browser session created on another node. No row is inserted; the
    /// caller has validated the row. The local handle's drop detaches rather
    /// than ends the session ([`WarpgateServerHandle`] does this for unowned
    /// sessions).
    ///
    /// Never node-owned: only a stored-cookie session has a row to re-attach
    /// to — a node-local session lives and dies with its one owning node and
    /// is never adopted.
    pub async fn adopt_user_session(
        this: &Arc<Mutex<Self>>,
        id: UserSessionId,
        protocol: Protocol,
        state: UserSessionStateInit,
    ) -> Arc<Mutex<WarpgateServerHandle>> {
        let mut self_ = this.lock().await;
        let state = Arc::new(Mutex::new(UserSessionState::new(
            state,
            self_.change_sender.clone(),
        )));
        self_.install_user_session(this, id, state, protocol, false)
    }

    fn install_user_session(
        &mut self,
        owner: &Arc<Mutex<Self>>,
        id: UserSessionId,
        state: Arc<Mutex<UserSessionState>>,
        protocol: Protocol,
        node_owned: bool,
    ) -> Arc<Mutex<WarpgateServerHandle>> {
        self.user_sessions.insert(id, state.clone());
        let _ = self.change_sender.send(());
        let access_watch = AccessWatchSettings {
            interval: self.access_watch_interval,
            unconfirmed_limit: self.access_watch_unconfirmed_limit,
            nudges: self.access_watch_nudges.subscribe(),
        };
        Arc::new(Mutex::new(WarpgateServerHandle::new(
            id,
            self.db.clone(),
            owner.clone(),
            state,
            self.rate_limiter_registry.clone(),
            protocol,
            node_owned,
            self.node_id,
            access_watch,
        )))
    }

    pub async fn close_local_sessions(
        this: &Arc<Mutex<Self>>,
        matches: impl Fn(&UserSessionState) -> bool,
    ) {
        let user_states = this
            .lock()
            .await
            .user_sessions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for state in user_states {
            let state = state.lock().await;
            if matches(&state) {
                state.handle.close();
            }
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.change_sender.subscribe()
    }

    /// Removes a session that never completed authentication, deleting its row
    /// rather than marking it ended — see
    /// [`WarpgateServerHandle::mark_provisional`]. Target sessions started
    /// while still provisional (Kubernetes confirms only after admission) are
    /// part of the attempt and are discarded with it.
    pub async fn discard_session(&mut self, id: UserSessionId) {
        self.user_sessions.remove(&id);

        if let Err(error) = TargetSession::Entity::delete_many()
            .filter(TargetSession::Column::UserSessionId.eq(id))
            .exec(&self.db)
            .await
        {
            error!(%error, %id, "Could not delete the session's target sessions from the DB");
        }
        if let Err(error) = UserSession::Entity::delete_by_id(id).exec(&self.db).await {
            error!(%error, %id, "Could not delete user session from the DB");
        }

        self.abandon_session_approvals(id).await;

        let _ = self.change_sender.send(());
    }

    pub fn detach_user_session(
        &mut self,
        id: UserSessionId,
        session_state: &Arc<Mutex<UserSessionState>>,
    ) {
        if self
            .user_sessions
            .get(&id)
            .is_some_and(|state| Arc::ptr_eq(state, session_state))
        {
            self.user_sessions.remove(&id);
        }
    }

    async fn abandon_session_approvals(&self, id: UserSessionId) {
        if let Err(error) = SessionApprovalRequest::abandon_requests_for_session(&self.db, id).await
        {
            error!(%error, %id, "Could not close the session's approval requests");
        }
    }

    pub async fn remove_session(&mut self, id: UserSessionId) {
        // The row is ended whether or not this node still holds the state: a
        // handle dropped just before this call detaches the entry without
        // ending anything, and ending the row is the whole point of the call.
        self.user_sessions.remove(&id);

        if let Err(error) = UserSession::mark_ended_including_target_sessions(&self.db, id).await {
            error!(%error, %id, "Could not end user session in the DB");
        }

        self.abandon_session_approvals(id).await;

        let _ = self.change_sender.send(());
    }
}

#[derive(Clone)]
pub struct SharedSessionHandle {
    inner: Arc<std::sync::Mutex<Box<dyn SessionHandle + Send + Sync>>>,
}

impl SharedSessionHandle {
    fn new(handle: Box<dyn SessionHandle + Send + Sync>) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(handle)),
        }
    }

    pub fn close(&self) {
        match self.inner.lock() {
            Ok(mut handle) => handle.close(),
            Err(error) => error!(%error, "Could not lock session close handle"),
        }
    }

    /// A weak view for a task that must not keep the underlying handle (and
    /// whatever it owns — e.g. a protocol's `abort_tx`) alive by itself. An
    /// access watcher holds this instead of a [`SharedSessionHandle`]: once
    /// every real owner is gone the handle drops and tears down promptly,
    /// rather than lingering until the watcher's grant also goes dead.
    pub(crate) fn downgrade(&self) -> WeakSessionHandle {
        WeakSessionHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }
}

#[derive(Clone)]
pub(crate) struct WeakSessionHandle {
    inner: Weak<std::sync::Mutex<Box<dyn SessionHandle + Send + Sync>>>,
}

impl WeakSessionHandle {
    /// Closes the session if it still exists. A handle that is already gone
    /// (torn down through some other path) is not an error to observe here.
    pub(crate) fn close(&self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        match inner.lock() {
            Ok(mut handle) => handle.close(),
            Err(error) => error!(%error, "Could not lock session close handle"),
        }
    }
}

pub struct UserSessionState {
    pub remote_address: Option<SocketAddr>,
    pub user_info: Option<AuthStateUserInfo>,
    pub handle: SharedSessionHandle,
    /// The target this session's connection streams are limited against.
    /// Set when a target session starts and never unset — a stream serves at
    /// most one target for its whole life.
    pub target: Option<Target>,
    change_sender: broadcast::Sender<()>,
    pub rate_limiter_handles: Vec<RateLimiterStackHandle>,
    /// One [`access_watch::watch`] task per distinct grant admitted under in
    /// this node-local session state. Dropping the guard cancels the
    /// watcher; the whole map drops with this state, so no watcher outlives
    /// the session it watches.
    pub(crate) access_watches: HashMap<AccessGrant, DropGuard>,
}

pub struct UserSessionStateInit {
    pub remote_address: Option<SocketAddr>,
    pub handle: Box<dyn SessionHandle + Send + Sync>,
}

impl UserSessionState {
    fn new(init: UserSessionStateInit, change_sender: broadcast::Sender<()>) -> Self {
        Self {
            remote_address: init.remote_address,
            user_info: None,
            handle: SharedSessionHandle::new(init.handle),
            target: None,
            change_sender,
            rate_limiter_handles: vec![],
            access_watches: HashMap::new(),
        }
    }

    pub fn emit_change(&self) {
        let _ = self.change_sender.send(());
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sea_orm::ActiveValue::Set;
    use sea_orm::{ColumnTrait, Database, PaginatorTrait, QueryFilter};
    use warpgate_common::{TargetHTTPOptions, TargetOptions, Tls, UserSessionId};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    struct TestHandle;

    impl SessionHandle for TestHandle {
        fn close(&mut self) {}
    }

    fn target() -> Target {
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

    /// A revoked login must not keep serving: an administrative close ends the
    /// row on whichever node runs it, and a node that still holds a view of
    /// the session has to refuse rather than open something new under it.
    #[tokio::test]
    async fn an_ended_login_cannot_open_a_target_session() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = parent.lock().await.user_session_id();

        // Closed elsewhere in the cluster: only the row changes here.
        UserSession::mark_ended_including_target_sessions(&db, parent_id)
            .await
            .unwrap();

        let refused = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target(),
                Protocol::Http,
            ))
            .await;
        assert!(matches!(refused, Err(WarpgateError::UserSessionEnded)));
    }

    /// Closing by user must reach exactly that user's live connections: a
    /// deleted account keeps no open handle, and nobody else's is touched.
    #[tokio::test]
    async fn target_open_racing_session_end_cannot_leave_an_open_access() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = parent.lock().await.user_session_id();
        let access_target = target();

        let opening = TargetSession::open_or_lookup(
            &db,
            warpgate_common::TargetSessionId(Uuid::new_v4()),
            parent_id,
            &access_target,
            None,
            None,
            &user_info,
        );
        let ending = UserSession::mark_ended_including_target_sessions(&db, parent_id);
        let (opened, ended) = tokio::join!(opening, ending);

        ended.unwrap();
        assert!(opened.is_ok() || matches!(opened, Err(WarpgateError::UserSessionEnded)));
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .filter(TargetSession::Column::Ended.is_null())
                .count(&db)
                .await
                .unwrap(),
            0
        );
    }

    /// Dropping the last handle of a node-owned session ends the session and
    /// every access recorded under it — the audit trail's "ended" comes from
    /// this, not from any per-access teardown.
    #[tokio::test]
    async fn dropping_the_handle_ends_the_session_and_its_accesses() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let parent = State::register_node_local_user_session(
            &state,
            Protocol::Ssh,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();

        let target_session_id = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target(),
                Protocol::Ssh,
            ))
            .await
            .unwrap()
            .started()
            .id();

        // The only reference the connection would have held.
        drop(parent);

        // Teardown runs on a spawned task; poll for it.
        for _ in 0..50 {
            let child = TargetSession::Entity::find_by_id(target_session_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap();
            if child.ended.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("target session row was not ended");
    }

    #[tokio::test]
    async fn user_session_reuses_its_target_session_per_target() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id: UserSessionId = parent.lock().await.user_session_id();
        let other_target = target();
        let target = target();

        let first_id = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .started()
            .id();
        let second_id = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .started()
            .id();
        assert_eq!(first_id, second_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        let other_id = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                other_target,
                Protocol::Http,
            ))
            .await
            .unwrap()
            .started()
            .id();
        assert_ne!(first_id, other_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            2
        );
    }

    /// A node adopting a shared session (created elsewhere, or detached here)
    /// has no memory of the row another node already recorded for this target;
    /// the unique (user session, target) pair makes it reuse that row rather
    /// than record a duplicate.
    #[tokio::test]
    async fn adopted_user_session_reuses_the_live_target_session_row() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        let parent_id: UserSessionId = parent.lock().await.user_session_id();
        let target = target();

        let first_id = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Http,
            ))
            .await
            .unwrap()
            .started()
            .id();

        let adopted = State::adopt_user_session(
            &state,
            parent_id,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await;
        let adopted_id = adopted
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target,
                Protocol::Http,
            ))
            .await
            .unwrap()
            .started()
            .id();

        assert_eq!(first_id, adopted_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        // The adopting view detaching must not end the shared row.
        drop(adopted);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            TargetSession::Entity::find_by_id(first_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .ended
                .is_none()
        );
    }

    #[tokio::test]
    async fn nodes_racing_a_shared_target_session_adopt_one_row() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let first_state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let second_state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        let first_parent = State::register_nonlocal_user_session(
            &first_state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        first_parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = first_parent.lock().await.user_session_id();
        let second_parent = State::adopt_user_session(
            &second_state,
            parent_id,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await;
        let target = target();
        let first_authorization =
            crate::TargetAuthorization::for_test(user_info.clone(), target.clone(), Protocol::Http);
        let second_authorization =
            crate::TargetAuthorization::for_test(user_info, target, Protocol::Http);

        let first = async {
            first_parent
                .lock()
                .await
                .start_target_session(first_authorization)
                .await
                .unwrap()
                .started()
                .id()
        };
        let second = async {
            second_parent
                .lock()
                .await
                .start_target_session(second_authorization)
                .await
                .unwrap()
                .started()
                .id()
        };
        let (first_id, second_id) = tokio::join!(first, second);

        assert_eq!(first_id, second_id);
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            1
        );
    }

    /// Which constructor a session registers through — not its protocol — is
    /// what decides whether the row records an owning node, the only thing the
    /// reaper reads. An HTTP session held open by a node-local handle (a
    /// header-borne ticket's) records its owner and so is not swept as an
    /// unbacked orphan.
    #[tokio::test]
    async fn registration_kind_decides_the_owning_node() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let node_id = NodeId(Uuid::new_v4());
        let state = State::new(&db, &rate_limiters, node_id);

        let init = || UserSessionStateInit {
            remote_address: None,
            handle: Box::new(TestHandle),
        };
        let node_of = async |handle: &Arc<Mutex<WarpgateServerHandle>>| {
            let id = handle.lock().await.user_session_id();
            UserSession::Entity::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .node_id
        };

        let cookie_backed = State::register_nonlocal_user_session(&state, Protocol::Http, init())
            .await
            .unwrap();
        assert_eq!(node_of(&cookie_backed).await, None);

        let node_local = State::register_node_local_user_session(&state, Protocol::Http, init())
            .await
            .unwrap();
        assert_eq!(node_of(&node_local).await, Some(node_id));
    }

    #[tokio::test]
    async fn direct_target_session_has_independent_state() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, warpgate_common::NodeId(Uuid::new_v4()));
        let parent = State::register_node_local_user_session(
            &state,
            Protocol::Ssh,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };
        parent
            .lock()
            .await
            .set_user_info(user_info.clone())
            .await
            .unwrap();
        let parent_id = parent.lock().await.user_session_id();
        let target = target();
        let wrong_user = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "mallory".into(),
        };
        assert!(
            parent
                .lock()
                .await
                .start_target_session(crate::TargetAuthorization::for_test(
                    wrong_user,
                    target.clone(),
                    Protocol::Ssh,
                ))
                .await
                .is_err()
        );
        assert!(
            parent
                .lock()
                .await
                .start_target_session(crate::TargetAuthorization::for_test(
                    user_info.clone(),
                    target.clone(),
                    Protocol::Http,
                ))
                .await
                .is_err()
        );
        let admitted = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info.clone(),
                target.clone(),
                Protocol::Ssh,
            ))
            .await
            .unwrap()
            .started();

        let target_session_id = admitted.id();
        let approved = admitted.into_approved();

        assert_eq!(approved.target(), &target);
        let row = TargetSession::Entity::find_by_id(target_session_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.user_session_id, parent_id);
        // The ids are independent: nothing may rely on a child sharing its
        // parent's UUID.
        assert_ne!(target_session_id.0, parent_id.0);

        let again_id = parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                target,
                Protocol::Ssh,
            ))
            .await
            .unwrap()
            .started()
            .id();
        assert_eq!(again_id, target_session_id);
    }

    /// A [`SessionHandle`] that counts its `close()` calls instead of acting
    /// on them, so a test can observe whether — and how many times — the
    /// access watcher closed the session.
    #[derive(Clone, Default)]
    struct CountingHandle(Arc<AtomicUsize>);

    impl SessionHandle for CountingHandle {
        fn close(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Inserts a user, the given (ungated) HTTP target, and a ticket binding
    /// them — modeled on `approvals::tests::ticket_with_uses`, but returning
    /// what a [`crate::TargetAuthorization::for_ticket_session`] needs, since
    /// these tests check admission rather than the approval gate.
    async fn insert_ticket(
        db: &DatabaseConnection,
        access_target: &Target,
        expiry: Option<OffsetDateTime>,
        uses_left: Option<i16>,
    ) -> (AuthStateUserInfo, Uuid) {
        let user_id = Uuid::new_v4();
        warpgate_db_entities::User::Entity::insert(warpgate_db_entities::User::ActiveModel {
            id: Set(user_id),
            username: Set("alice".into()),
            credential_policy: Set(serde_json::Value::Null),
            description: Set(String::new()),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        })
        .exec(db)
        .await
        .unwrap();

        warpgate_db_entities::Target::Entity::insert(warpgate_db_entities::Target::ActiveModel {
            id: Set(access_target.id),
            name: Set(access_target.name.clone()),
            description: Set(String::new()),
            kind: Set(warpgate_db_entities::Target::TargetKind::Http),
            options: Set(serde_json::to_value(&access_target.options).unwrap()),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        })
        .exec(db)
        .await
        .unwrap();

        let ticket_id = Uuid::new_v4();
        warpgate_db_entities::Ticket::Entity::insert(warpgate_db_entities::Ticket::ActiveModel {
            id: Set(ticket_id),
            secret_hash: Set("hash".into()),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(access_target.id),
            uses_left: Set(uses_left),
            self_service: Set(false),
            expiry: Set(expiry),
            created: Set(OffsetDateTime::now_utc()),
        })
        .exec(db)
        .await
        .unwrap();

        (
            AuthStateUserInfo {
                id: user_id,
                username: "alice".into(),
            },
            ticket_id,
        )
    }

    /// A fresh migrated DB plus a `State` with the access-watch poll timing
    /// sped up, so a test doesn't have to wait out the production interval.
    async fn state_with_watch_timing(
        interval: Duration,
        unconfirmed_limit: Duration,
    ) -> (DatabaseConnection, Arc<Mutex<State>>) {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let rate_limiters = Arc::new(Mutex::new(RateLimiterRegistry::new(db.clone())));
        let state = State::new(&db, &rate_limiters, NodeId(Uuid::new_v4()));
        state
            .lock()
            .await
            .set_access_watch_timing(interval, unconfirmed_limit);
        (db, state)
    }

    /// A ticket revoked (or never valid) before admission must refuse the
    /// session outright — no target session row, no watcher — rather than
    /// admitting it and relying on the watcher to close it moments later.
    #[tokio::test]
    async fn admission_refuses_revoked_ticket_and_opens_no_row() {
        let (db, state) = state_with_watch_timing(Duration::from_secs(3600), Duration::from_secs(3600)).await;
        let access_target = target();
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, None, None).await;
        warpgate_db_entities::Ticket::Entity::delete_by_id(ticket_id)
            .exec(&db)
            .await
            .unwrap();

        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let parent_id = parent.lock().await.user_session_id();

        let refused = parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await;
        assert!(matches!(refused, Err(WarpgateError::TargetAccessRevoked)));

        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            parent
                .lock()
                .await
                .user_session_state()
                .lock()
                .await
                .access_watches
                .len(),
            0
        );
    }

    /// Same refusal for a ticket that exists but whose own expiry has
    /// already passed.
    #[tokio::test]
    async fn admission_refuses_expired_ticket() {
        let (db, state) = state_with_watch_timing(Duration::from_secs(3600), Duration::from_secs(3600)).await;
        let access_target = target();
        let past = OffsetDateTime::now_utc() - time::Duration::seconds(60);
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, Some(past), None).await;

        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        let parent_id = parent.lock().await.user_session_id();

        let refused = parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await;
        assert!(matches!(refused, Err(WarpgateError::TargetAccessRevoked)));
        assert_eq!(
            TargetSession::Entity::find()
                .filter(TargetSession::Column::UserSessionId.eq(parent_id))
                .count(&db)
                .await
                .unwrap(),
            0
        );
    }

    /// Exhausting a ticket's uses must never close a session already
    /// admitted under it — only block a *new* admission. `uses_left` is
    /// deliberately not part of the watcher's liveness check.
    #[tokio::test]
    async fn exhausted_uses_do_not_close() {
        let (db, state) =
            state_with_watch_timing(Duration::from_millis(30), Duration::from_millis(90)).await;
        let access_target = target();
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, None, Some(0)).await;

        let closes = Arc::new(AtomicUsize::new(0));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(CountingHandle(closes.clone())),
            },
        )
        .await
        .unwrap();

        let admitted = parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await;
        assert!(admitted.is_ok(), "an exhausted ticket still admits");

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(closes.load(Ordering::SeqCst), 0);
    }

    /// Deleting a ticket (revoking it) closes the session it authorized, on
    /// the watcher's next poll.
    #[tokio::test]
    async fn deleting_ticket_closes_session() {
        let (db, state) =
            state_with_watch_timing(Duration::from_millis(50), Duration::from_millis(150)).await;
        let access_target = target();
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, None, None).await;

        let closes = Arc::new(AtomicUsize::new(0));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(CountingHandle(closes.clone())),
            },
        )
        .await
        .unwrap();
        parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .started();

        warpgate_db_entities::Ticket::Entity::delete_by_id(ticket_id)
            .exec(&db)
            .await
            .unwrap();

        for _ in 0..50 {
            if closes.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("session was not closed after its ticket was deleted");
    }

    /// With a long poll interval, a ticket's own expiry still closes the
    /// session right on the deadline, not on the next (much later) periodic
    /// poll — the watcher sleeps to the sooner of the two.
    #[tokio::test]
    async fn expiry_closes_at_deadline_not_poll() {
        let (db, state) =
            state_with_watch_timing(Duration::from_secs(3600), Duration::from_secs(3600)).await;
        let access_target = target();
        // Long enough that admitting the session (a handful of DB round
        // trips) can't itself eat into the margin before the deadline on a
        // slow/loaded CI box.
        let expiry = OffsetDateTime::now_utc() + time::Duration::seconds(2);
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, Some(expiry), None).await;

        let closes = Arc::new(AtomicUsize::new(0));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(CountingHandle(closes.clone())),
            },
        )
        .await
        .unwrap();
        parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .started();

        for _ in 0..250 {
            if closes.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("session was not closed at its ticket's expiry deadline");
    }

    /// A revoke nudges every watcher to re-check immediately, so a session
    /// closes right away even with a poll interval far longer than the test
    /// itself.
    #[tokio::test]
    async fn nudge_rechecks_immediately() {
        let (db, state) =
            state_with_watch_timing(Duration::from_secs(3600), Duration::from_secs(3600)).await;
        let access_target = target();
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, None, None).await;

        let closes = Arc::new(AtomicUsize::new(0));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(CountingHandle(closes.clone())),
            },
        )
        .await
        .unwrap();
        parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .started();

        warpgate_db_entities::Ticket::Entity::delete_by_id(ticket_id)
            .exec(&db)
            .await
            .unwrap();
        state.lock().await.nudge_access_watchers();

        for _ in 0..25 {
            if closes.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("nudged session was not closed within 500ms");
    }

    /// Repeated admissions under the same grant (another HTTP request,
    /// another `kubectl` call) must reuse one watcher, not spawn a new one
    /// each time.
    #[tokio::test]
    async fn repeated_admissions_share_one_watcher() {
        let (db, state) =
            state_with_watch_timing(Duration::from_secs(3600), Duration::from_secs(3600)).await;
        let access_target = target();
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, None, None).await;

        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();

        for _ in 0..2 {
            parent
                .lock()
                .await
                .start_target_session(
                    crate::TargetAuthorization::for_ticket_session(
                        user_info.clone(),
                        access_target.clone(),
                        ticket_id,
                        Protocol::Http,
                    )
                    .unwrap(),
                )
                .await
                .unwrap()
                .started();
        }

        let session_state = parent.lock().await.user_session_state().clone();
        assert_eq!(session_state.lock().await.access_watches.len(), 1);
    }

    /// An authorization with no backing grant (role-based access) starts no
    /// watcher: nothing revokes it mid-session today.
    #[tokio::test]
    async fn non_ticket_admission_starts_no_watcher() {
        let (_db, state) =
            state_with_watch_timing(Duration::from_secs(3600), Duration::from_secs(3600)).await;
        let access_target = target();
        let user_info = AuthStateUserInfo {
            id: Uuid::new_v4(),
            username: "alice".into(),
        };

        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(TestHandle),
            },
        )
        .await
        .unwrap();
        parent
            .lock()
            .await
            .start_target_session(crate::TargetAuthorization::for_test(
                user_info,
                access_target,
                Protocol::Http,
            ))
            .await
            .unwrap()
            .started();

        let session_state = parent.lock().await.user_session_state().clone();
        assert_eq!(session_state.lock().await.access_watches.len(), 0);
    }

    /// Dropping the last handle of the session (ending it) must stop its
    /// watcher: after the session and its `UserSessionState` are gone, a
    /// later revoke-and-nudge must not still land a `close()` — there is
    /// nothing left to close, and nothing should still be polling to try.
    #[tokio::test]
    async fn dropping_session_cancels_watcher() {
        let (db, state) =
            state_with_watch_timing(Duration::from_millis(20), Duration::from_millis(60)).await;
        let access_target = target();
        let (user_info, ticket_id) = insert_ticket(&db, &access_target, None, None).await;

        let closes = Arc::new(AtomicUsize::new(0));
        let parent = State::register_nonlocal_user_session(
            &state,
            Protocol::Http,
            UserSessionStateInit {
                remote_address: None,
                handle: Box::new(CountingHandle(closes.clone())),
            },
        )
        .await
        .unwrap();
        let parent_id = parent.lock().await.user_session_id();
        parent
            .lock()
            .await
            .start_target_session(
                crate::TargetAuthorization::for_ticket_session(
                    user_info,
                    access_target,
                    ticket_id,
                    Protocol::Http,
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .started();

        // Kept alive independently of `parent`/`UserSessionState`: without
        // this, `CountingHandle` itself drops the moment they do, and a
        // watcher that leaked (bug not actually fixed) would call `close()`
        // on an already-gone `Weak` and silently no-op — this test would
        // then pass whether or not cancellation actually worked. Holding a
        // `SharedSessionHandle` clone here doesn't hold `UserSessionState`
        // itself alive (a separate Arc), so teardown below is unaffected.
        let _keep_handle_alive = parent
            .lock()
            .await
            .user_session_state()
            .lock()
            .await
            .handle
            .clone();

        drop(parent);

        // Teardown runs on a spawned task; poll until the node-local state
        // has been dropped from the map (its only other owner) — i.e. until
        // nothing should be watching any more. (Not also waiting on the DB
        // row's `ended` timestamp: that's covered elsewhere and only slows
        // this test down.)
        for _ in 0..50 {
            if !state.lock().await.user_sessions.contains_key(&parent_id) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!state.lock().await.user_sessions.contains_key(&parent_id));

        // If the watcher were somehow still running, this would wake it
        // immediately instead of waiting out an interval.
        warpgate_db_entities::Ticket::Entity::delete_by_id(ticket_id)
            .exec(&db)
            .await
            .unwrap();
        state.lock().await.nudge_access_watchers();
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(closes.load(Ordering::SeqCst), 0);
    }
}
