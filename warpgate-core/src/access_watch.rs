//! Watches a target session's backing [`AccessGrant`] for revocation or
//! expiry and closes the session when it goes dead.
//!
//! A grant is checked once at admission (see
//! `protocols::handle::WarpgateServerHandle::open_target_session_row`) and,
//! if it grants access, kept live-checked here for as long as anything in
//! this node-local [`crate::UserSessionState`] was admitted under it.
//! `uses_left` is never part of that liveness: exhausting a ticket's uses
//! must stop *new* admissions, not end a session it already let in.

use std::time::{Duration, Instant};

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

/// Overrides [`DEFAULT_INTERVAL`] (and, proportionally,
/// [`DEFAULT_UNCONFIRMED_LIMIT`]) when set to a valid number of seconds — a
/// pytest-only knob, in the same spirit as `WARPGATE_UNDER_TEST`
/// (`warpgate_common::helpers::hash`), and only honoured alongside it (see
/// [`default_timing`]). Used to prove a cross-node cluster notification
/// actually delivered a revoke, rather than a node's own periodic poll
/// coincidentally landing inside a short test deadline: set this long on one
/// node and only the notification can close a session within the deadline.
const INTERVAL_OVERRIDE_ENV_VAR: &str = "WARPGATE_ACCESS_WATCH_INTERVAL_SECS";

/// Valid range for [`INTERVAL_OVERRIDE_ENV_VAR`], in seconds. `0` would spin
/// the watch loop hot; anything above an hour is not a plausible test
/// interval and, without a ceiling, `interval * 3` for the unconfirmed limit
/// could overflow `Duration`'s arithmetic and panic.
const INTERVAL_OVERRIDE_RANGE: std::ops::RangeInclusive<u64> = 1..=3600;

/// The (interval, unconfirmed_limit) pair a fresh [`crate::State`] starts
/// with — the hardcoded defaults, unless running under test
/// (`WARPGATE_UNDER_TEST` is set — the same flag production never sets) and
/// [`INTERVAL_OVERRIDE_ENV_VAR`] names an interval within
/// [`INTERVAL_OVERRIDE_RANGE`]. Gating on `WARPGATE_UNDER_TEST` too means the
/// override variable being set for some unrelated reason can never change a
/// production deployment's polling.
pub(crate) fn default_timing() -> (Duration, Duration) {
    let Ok(raw) = std::env::var(INTERVAL_OVERRIDE_ENV_VAR) else {
        return (DEFAULT_INTERVAL, DEFAULT_UNCONFIRMED_LIMIT);
    };

    if std::env::var("WARPGATE_UNDER_TEST")
        .unwrap_or_default()
        .is_empty()
    {
        warn!(
            value = %raw,
            "{INTERVAL_OVERRIDE_ENV_VAR} is set but WARPGATE_UNDER_TEST is not; ignoring it"
        );
        return (DEFAULT_INTERVAL, DEFAULT_UNCONFIRMED_LIMIT);
    }

    match raw.parse::<u64>() {
        Ok(seconds) if INTERVAL_OVERRIDE_RANGE.contains(&seconds) => {
            warn!(
                seconds,
                "{INTERVAL_OVERRIDE_ENV_VAR} is overriding the access-watch poll interval"
            );
            let interval = Duration::from_secs(seconds);
            (interval, interval * 3)
        }
        _ => {
            warn!(
                value = %raw,
                range = ?INTERVAL_OVERRIDE_RANGE,
                "{INTERVAL_OVERRIDE_ENV_VAR} is not a whole number of seconds in range; ignoring it"
            );
            (DEFAULT_INTERVAL, DEFAULT_UNCONFIRMED_LIMIT)
        }
    }
}

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
/// `last_ok`/`now` are a monotonic [`Instant`] — not wall-clock time — so a
/// clock step (NTP, suspend/resume) can't stretch or erase the unconfirmed
/// window; `deadline`/`wall_now` stay wall-clock since a ticket's own expiry
/// is a wall-clock value.
///
/// Pulled out of [`watch`] so the close policy — not the polling around it —
/// is what gets unit tested.
fn close_on_error(
    last_ok: Instant,
    now: Instant,
    deadline: Option<OffsetDateTime>,
    wall_now: OffsetDateTime,
    unconfirmed_limit: Duration,
) -> bool {
    if deadline.is_some_and(|deadline| deadline <= wall_now) {
        return true;
    }
    now.saturating_duration_since(last_ok) >= unconfirmed_limit
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
    settings: AccessWatchSettings,
    mut deadline: Option<OffsetDateTime>,
) {
    let AccessWatchSettings {
        interval,
        unconfirmed_limit,
        mut nudges,
    } = settings;
    let mut last_ok = Instant::now();
    // Latched once `nudges.changed()` errors (all senders gone): after that
    // it would resolve immediately forever, turning the sleep/nudge select
    // below into a busy loop. `State`'s sender realistically outlives every
    // watcher, so this is a belt-and-braces guard, not an expected path.
    let mut nudges_alive = true;

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
            result = async {
                if nudges_alive {
                    nudges.changed().await
                } else {
                    std::future::pending().await
                }
            } => {
                if result.is_err() {
                    nudges_alive = false;
                }
            }
        }

        // Timed out and raced against `stop` too: an unbounded `.await` here
        // would let one hung query block the loop forever, silently
        // defeating both the unconfirmed-limit and the deadline it exists to
        // enforce. Floored at 1s so a tiny test interval can't turn an
        // ordinarily-fine, merely-slow SQLite check into a close-triggering
        // timeout.
        let check_timeout = interval.max(Duration::from_secs(1));
        let outcome = tokio::select! {
            biased;
            () = stop.cancelled() => return,
            outcome = tokio::time::timeout(check_timeout, grant.check(&db, OffsetDateTime::now_utc())) => outcome,
        };
        match outcome {
            Ok(Ok(Liveness::Live { until })) => {
                deadline = until;
                last_ok = Instant::now();
            }
            Ok(Ok(dead)) => {
                warn!(?grant, ?dead, "Closing session: access grant is no longer live");
                handle.close();
                return;
            }
            Ok(Err(error)) => {
                warn!(%error, ?grant, "Failed to re-check access grant");
                if close_on_error(
                    last_ok,
                    Instant::now(),
                    deadline,
                    OffsetDateTime::now_utc(),
                    unconfirmed_limit,
                ) {
                    warn!(?grant, "Closing session: access grant could not be confirmed in time");
                    handle.close();
                    return;
                }
            }
            Err(_timed_out) => {
                warn!(?grant, ?interval, "Access grant check timed out");
                if close_on_error(
                    last_ok,
                    Instant::now(),
                    deadline,
                    OffsetDateTime::now_utc(),
                    unconfirmed_limit,
                ) {
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
        let start = Instant::now();
        let wall_now = OffsetDateTime::now_utc();
        let limit = Duration::from_secs(15);

        // A deadline that has already passed closes immediately, even if the
        // last successful check was a moment ago.
        assert!(close_on_error(
            start,
            start,
            Some(wall_now - time::Duration::seconds(1)),
            wall_now,
            limit
        ));

        // No deadline, and the unconfirmed limit not yet reached: keep going.
        assert!(!close_on_error(start, start, None, wall_now, limit));
        assert!(!close_on_error(
            start,
            start + Duration::from_secs(10),
            None,
            wall_now,
            limit
        ));

        // No deadline, but too long since the last confirmed-live check.
        assert!(close_on_error(
            start,
            start + Duration::from_secs(15),
            None,
            wall_now,
            limit
        ));

        // A future deadline does not by itself excuse a stale confirmation.
        assert!(close_on_error(
            start,
            start + Duration::from_secs(20),
            Some(wall_now + time::Duration::hours(1)),
            wall_now,
            limit
        ));
    }
}
