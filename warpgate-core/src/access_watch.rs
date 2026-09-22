//! Watches a target session's backing [`AccessGrant`] for revocation or
//! expiry and closes the session when it goes dead.
//!
//! A grant is checked once at admission (see
//! `protocols::handle::WarpgateServerHandle::open_target_session_row`) and,
//! if it grants access, kept live-checked here for as long as anything in
//! this node-local [`crate::UserSessionState`] was admitted under it.
//! `uses_left` is never part of that liveness: exhausting a ticket's uses
//! must stop *new* admissions, not end a session it already let in.

use std::time::Duration;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_db_entities::Ticket;

use crate::state::WeakSessionHandle;

/// How often a watcher re-checks its grant absent a known deadline or a
/// revoke nudge.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// How long a watcher tolerates a grant it cannot re-check (a DB blip) before
/// treating it as dead. A few missed checks, not the first one — a database
/// hiccup must not take down every ticket session in the cluster.
pub(crate) const DEFAULT_UNCONFIRMED_LIMIT: Duration = Duration::from_secs(15);

/// What a target session's admission was granted under. Only a ticket today;
/// the `zyno/database-ticket-jit` branch adds a `SelfService` variant for
/// role-based access minted just-in-time, which is why this is kept as an
/// enum rather than a bare ticket id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AccessGrant {
    Ticket {
        ticket_id: Uuid,
        user_id: Uuid,
        target_id: Uuid,
    },
}

/// The result of re-checking a grant against the database.
#[derive(Debug, Clone, Copy)]
pub enum Liveness {
    /// Still good. `until` is the next known deadline, if any, so the watcher
    /// can sleep up to it instead of polling blindly.
    Live { until: Option<OffsetDateTime> },
    /// The grant's backing row is gone.
    Revoked,
    /// The grant's row still exists but its own deadline has passed.
    Expired,
}

impl AccessGrant {
    /// Re-checks this grant against the database as of `now`.
    pub async fn check(
        &self,
        db: &DatabaseConnection,
        now: OffsetDateTime,
    ) -> Result<Liveness, WarpgateError> {
        match self {
            Self::Ticket {
                ticket_id,
                user_id,
                target_id,
            } => {
                let expiry = Ticket::Entity::find()
                    .filter(Ticket::Column::Id.eq(*ticket_id))
                    .filter(Ticket::Column::UserId.eq(*user_id))
                    .filter(Ticket::Column::TargetId.eq(*target_id))
                    .select_only()
                    .column(Ticket::Column::Expiry)
                    .into_tuple::<Option<OffsetDateTime>>()
                    .one(db)
                    .await?;
                let Some(expiry) = expiry else {
                    return Ok(Liveness::Revoked);
                };
                Ok(match expiry {
                    // `<=`, not `<`: a strict `<` would let the watcher wake
                    // exactly on the deadline, see nothing to act on yet, and
                    // sleep for another full interval before noticing.
                    Some(expiry) if expiry <= now => Liveness::Expired,
                    until => Liveness::Live { until },
                })
            }
        }
    }
}

/// A grant's per-handle watch configuration: how eagerly to poll, and the
/// receiver a fresh watcher's poll loop should start from. Built once per
/// [`crate::WarpgateServerHandle`] in `State::install_user_session`; admission
/// clones `nudges` off it for each grant it needs to (re)watch.
pub(crate) struct AccessWatchSettings {
    pub interval: Duration,
    pub unconfirmed_limit: Duration,
    pub nudges: watch::Receiver<u64>,
}

/// Whether a watcher that just failed to check its grant should give up and
/// close the session, given when it last confirmed the grant was live.
///
/// Pulled out of [`watch`] so the close policy — not the polling around it —
/// is what gets unit tested.
fn close_on_error(
    last_ok: OffsetDateTime,
    now: OffsetDateTime,
    deadline: Option<OffsetDateTime>,
    unconfirmed_limit: Duration,
) -> bool {
    if deadline.is_some_and(|deadline| deadline <= now) {
        return true;
    }
    (now - last_ok).unsigned_abs() >= unconfirmed_limit
}

/// Re-checks `grant` on `interval` (or sooner, on a nudge or a known
/// deadline) until it goes dead, then closes `handle` and returns.
///
/// Also returns as soon as `stop` cancels — the owning `UserSessionState` was
/// dropped, so there is nothing left to close and nothing left to watch for
/// (invariant: at most one watcher per grant per node-local
/// `UserSessionState`, living exactly as long as it does).
pub(crate) async fn watch(
    db: DatabaseConnection,
    grant: AccessGrant,
    handle: WeakSessionHandle,
    stop: CancellationToken,
    mut nudges: watch::Receiver<u64>,
    interval: Duration,
    unconfirmed_limit: Duration,
    mut deadline: Option<OffsetDateTime>,
) {
    let mut last_ok = OffsetDateTime::now_utc();

    loop {
        let now = OffsetDateTime::now_utc();
        let wake_in = match deadline {
            Some(deadline) if deadline <= now => Duration::ZERO,
            Some(deadline) => (deadline - now).unsigned_abs().min(interval),
            None => interval,
        };

        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            () = tokio::time::sleep(wake_in) => {}
            _ = nudges.changed() => {}
        }

        match grant.check(&db, OffsetDateTime::now_utc()).await {
            Ok(Liveness::Live { until }) => {
                deadline = until;
                last_ok = OffsetDateTime::now_utc();
            }
            Ok(dead) => {
                warn!(?grant, ?dead, "Closing session: access grant is no longer live");
                handle.close();
                return;
            }
            Err(error) => {
                warn!(%error, ?grant, "Failed to re-check access grant");
                if close_on_error(last_ok, OffsetDateTime::now_utc(), deadline, unconfirmed_limit) {
                    warn!(?grant, "Closing session: access grant could not be confirmed in time");
                    handle.close();
                    return;
                }
            }
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities as e;

    use super::*;

    /// A migrated in-memory DB with one user, one target, and one ticket for
    /// it — the liveness table below only varies the ticket's own fields, or
    /// the user/target ids it's checked against.
    async fn fixture(expiry: Option<OffsetDateTime>) -> (DatabaseConnection, Uuid, Uuid, Uuid) {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        warpgate_db_migrations::migrate_database(&db).await.unwrap();

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

        let target_id = Uuid::new_v4();
        e::Target::ActiveModel {
            id: Set(target_id),
            name: Set("web".into()),
            description: Set(String::new()),
            kind: Set(e::Target::TargetKind::Http),
            options: Set(serde_json::Value::Null),
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

        let ticket_id = Uuid::new_v4();
        e::Ticket::ActiveModel {
            id: Set(ticket_id),
            secret_hash: Set("hash".into()),
            user_id: Set(user_id),
            description: Set(String::new()),
            target_id: Set(target_id),
            // A used-up ticket must still read Live: exhausting `uses_left`
            // must not end a session already admitted under it.
            uses_left: Set(Some(0)),
            self_service: Set(false),
            expiry: Set(expiry),
            created: Set(OffsetDateTime::now_utc()),
        }
        .insert(&db)
        .await
        .unwrap();

        (db, ticket_id, user_id, target_id)
    }

    #[tokio::test]
    async fn ticket_grant_liveness_table() {
        let now = OffsetDateTime::now_utc();

        // No expiry: live forever.
        let (db, ticket_id, user_id, target_id) = fixture(None).await;
        let grant = AccessGrant::Ticket {
            ticket_id,
            user_id,
            target_id,
        };
        assert!(matches!(
            grant.check(&db, now).await.unwrap(),
            Liveness::Live { until: None }
        ));

        // Expiry in the future: live, with the deadline reported back.
        let future = now + time::Duration::hours(1);
        let (db, ticket_id, user_id, target_id) = fixture(Some(future)).await;
        let grant = AccessGrant::Ticket {
            ticket_id,
            user_id,
            target_id,
        };
        assert!(matches!(
            grant.check(&db, now).await.unwrap(),
            Liveness::Live { until: Some(u) } if u == future
        ));

        // Expiry in the past (including exactly now): expired.
        let past = now - time::Duration::hours(1);
        let (db, ticket_id, user_id, target_id) = fixture(Some(past)).await;
        let grant = AccessGrant::Ticket {
            ticket_id,
            user_id,
            target_id,
        };
        assert!(matches!(
            grant.check(&db, now).await.unwrap(),
            Liveness::Expired
        ));
        assert!(matches!(
            grant.check(&db, past).await.unwrap(),
            Liveness::Expired
        ));

        // Deleted: revoked, not an error.
        e::Ticket::Entity::delete_by_id(ticket_id)
            .exec(&db)
            .await
            .unwrap();
        assert!(matches!(
            grant.check(&db, now).await.unwrap(),
            Liveness::Revoked
        ));

        // A ticket that exists, but for a different user or target, must not
        // be treated as this grant's backing row.
        let (db, ticket_id, user_id, target_id) = fixture(None).await;
        let wrong_user = AccessGrant::Ticket {
            ticket_id,
            user_id: Uuid::new_v4(),
            target_id,
        };
        assert!(matches!(
            wrong_user.check(&db, now).await.unwrap(),
            Liveness::Revoked
        ));
        let wrong_target = AccessGrant::Ticket {
            ticket_id,
            user_id,
            target_id: Uuid::new_v4(),
        };
        assert!(matches!(
            wrong_target.check(&db, now).await.unwrap(),
            Liveness::Revoked
        ));
    }

    #[test]
    fn close_on_error_policy() {
        let now = OffsetDateTime::now_utc();
        let limit = Duration::from_secs(15);

        // A deadline that has already passed closes immediately, even if the
        // last successful check was a moment ago.
        assert!(close_on_error(now, now, Some(now - time::Duration::seconds(1)), limit));

        // No deadline, and the unconfirmed limit not yet reached: keep going.
        assert!(!close_on_error(now, now, None, limit));
        assert!(!close_on_error(
            now,
            now + time::Duration::seconds(10),
            None,
            limit
        ));

        // No deadline, but too long since the last confirmed-live check.
        assert!(close_on_error(
            now,
            now + time::Duration::seconds(15),
            None,
            limit
        ));

        // A future deadline does not by itself excuse a stale confirmation.
        assert!(close_on_error(
            now,
            now + time::Duration::seconds(20),
            Some(now + time::Duration::hours(1)),
            limit
        ));
    }
}
