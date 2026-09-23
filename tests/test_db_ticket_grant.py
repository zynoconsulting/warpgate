"""JIT access for MySQL/PostgreSQL targets through an activated self-service
ticket.

The DB protocols select a target through the user's normal `alice#target`
username (`AuthSelector::User`); when no role grants that target but the user
has an activated self-service ticket for the same user/target, access is
granted anyway. The ticket only ever supplies the target grant -- it never
substitutes for the password, and a role still wins first. Revoking or
expiring the ticket closes a live connection through the same watcher
`ticket-<secret>` auth already uses (see test_ticket_session_termination.py).

Mirrors the self-service request/approve/activate lifecycle and the
parameters setup/restore pattern used by
`test_activated_request_grants_normal_identity_access` on the
`zyno/kubernetes-ticket-jit` branch's tests/test_kubernetes_user_auth_ticket.py
(that test and branch are not present in this tree).
"""

import os
import subprocess
import time
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .approval_util import create_password_user, default_params
from .conftest import ProcessManager, WarpgateProcess
from .util import mysql_client_opts, mysql_client_ssl_opt, wait_mysql_port, wait_port


def _poll(fn, deadline_s=20):
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.5)
    return None


def _ticket_uses_left(api, ticket_id):
    return next(t for t in api.get_tickets() if t.id == ticket_id).uses_left


def _enable_self_service(url):
    # `ticket_request_show_all_targets` is required here: our role-less users
    # have no access at all, and without it a request for a target they can't
    # already reach is refused as "not found".
    with admin_client(url) as api:
        api.update_parameters(default_params(
            ticket_self_service_enabled=True,
            ticket_auto_approve_existing_access=False,
            ticket_request_show_all_targets=True,
        ))


def _disable_self_service(url):
    with admin_client(url) as api:
        api.update_parameters(default_params(
            ticket_self_service_enabled=False,
            ticket_request_show_all_targets=False,
        ))


def _login(url, username, password="123"):
    session = requests.Session()
    session.verify = False
    resp = session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code // 100 == 2, resp.text
    return session


def _activate_self_service_ticket(url, username, target_name, duration_seconds=3600):
    """Request, admin-approve and activate a self-service ticket for
    `username`/`target_name`. Returns `(session, ticket_id)` -- the session is
    the activating user's own login, reusable for a later self-service
    revoke."""
    session = _login(url, username)
    resp = session.post(
        f"{url}/@warpgate/api/ticket-requests",
        json={
            "target_name": target_name,
            "duration_seconds": duration_seconds,
            "description": "db JIT access",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["request"]["status"] == "Pending"
    request_id = data["request"]["id"]

    with admin_client(url) as api:
        result = api.approve_ticket_request(request_id)
        assert result.status == "Approved"
        assert result.ticket_id is None  # not minted until activation

    resp = session.post(f"{url}/@warpgate/api/ticket-requests/{request_id}/activate")
    assert resp.status_code == 200, resp.text
    ticket_id = resp.json()["request"]["ticket_id"]
    assert ticket_id is not None
    return session, ticket_id


def _revoke_own_ticket(session, url, ticket_id):
    resp = session.delete(f"{url}/@warpgate/api/my-tickets/{ticket_id}")
    assert resp.status_code == 204


class _Postgres:
    def __init__(self, port):
        self.port = port

    def wait_ready(self, wg):
        wait_port(self.port, recv=False)
        wait_port(wg.postgres_port, recv=False)

    def create_target(self, api, ticket_max_uses=None):
        return api.create_target(sdk.TargetDataRequest(
            name=f"postgres-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            ticket_max_uses=ticket_max_uses,
            options=sdk.TargetOptions(sdk.TargetOptionsTargetPostgresOptions(
                kind="Postgres",
                protocol_version=sdk.PostgresProtocolVersion.ENUM_3_DOT_2,
                host="localhost",
                port=self.port,
                username="user",
                auth=sdk.DatabaseTargetAuth(
                    sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                        kind="Password", password="123",
                    )
                ),
                tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
            )),
        ))

    def command(self, wg, username, password, query):
        argv = [
            "psql", "--user", username, "--host", "127.0.0.1",
            "--port", str(wg.postgres_port), "-c", query, "db",
        ]
        return argv, {"PGPASSWORD": password, **os.environ}

    def sleep_query(self):
        return "select pg_sleep(3600)"

    def short_sleep_query(self):
        return "select pg_sleep(7)"

    def probe_query(self):
        return "select 1"


class _Mysql:
    def __init__(self, port):
        self.port = port

    def wait_ready(self, wg):
        wait_mysql_port(self.port)
        wait_port(wg.mysql_port, recv=False)

    def create_target(self, api, ticket_max_uses=None):
        return api.create_target(sdk.TargetDataRequest(
            name=f"mysql-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            ticket_max_uses=ticket_max_uses,
            options=sdk.TargetOptions(sdk.TargetOptionsTargetMySqlOptions(
                kind="MySql",
                host="localhost",
                port=self.port,
                username="root",
                auth=sdk.DatabaseTargetAuth(
                    sdk.DatabaseTargetAuthDatabaseTargetPasswordAuth(
                        kind="Password", password="123",
                    )
                ),
                tls=sdk.Tls(mode=sdk.TlsMode.PREFERRED, verify=False),
            )),
        ))

    def command(self, wg, username, password, query):
        argv = [
            "mysql", "--user", username, f"-p{password}",
            "--host", "127.0.0.1", "--port", str(wg.mysql_port),
            *mysql_client_opts, mysql_client_ssl_opt,
            "-e", query, "db",
        ]
        return argv, None

    def sleep_query(self):
        return "select sleep(3600)"

    def short_sleep_query(self):
        return "select sleep(7)"

    def probe_query(self):
        return "select 1"


def _run(processes: ProcessManager, driver, wg, username, password, query, timeout):
    """Runs `query` to completion and returns the client's exit code."""
    argv, env = driver.command(wg, username, password, query)
    client = processes.start(
        argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    client.communicate(timeout=timeout)
    return client.returncode


def _start(processes: ProcessManager, driver, wg, username, password, query):
    """Starts `query` without waiting for it -- for a connection meant to be
    kept open (e.g. a sleep), so its liveness can be checked afterwards."""
    argv, env = driver.command(wg, username, password, query)
    return processes.start(
        argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


# --- Scenarios shared by both protocols -------------------------------------
#
# Each takes the already-connected `driver` plus the usual process/timeout/
# shared_wg fixtures, so the two protocol-specific test classes below are just
# thin wrappers wiring up their own target and passing it in.


def _lifecycle(processes, timeout, wg, driver):
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        user, _role = create_password_user(api)
        target = driver.create_target(api)
    username = f"{user.username}#{target.name}"

    _enable_self_service(url)
    try:
        # No role, no ticket yet.
        assert _run(processes, driver, wg, username, "123", driver.probe_query(), timeout) != 0

        session = _login(url, user.username)
        resp = session.post(
            f"{url}/@warpgate/api/ticket-requests",
            json={
                "target_name": target.name,
                "duration_seconds": 3600,
                "description": "db JIT access",
            },
        )
        assert resp.status_code == 201, resp.text
        request_id = resp.json()["request"]["id"]

        with admin_client(url) as api:
            api.approve_ticket_request(request_id)

        # Approved but not yet activated: still no ticket to grant access.
        assert _run(processes, driver, wg, username, "123", driver.probe_query(), timeout) != 0

        resp = session.post(f"{url}/@warpgate/api/ticket-requests/{request_id}/activate")
        assert resp.status_code == 200, resp.text
        ticket_id = resp.json()["request"]["ticket_id"]

        # Activated: the ticket now grants access.
        assert _run(processes, driver, wg, username, "123", driver.probe_query(), timeout) == 0

        with admin_client(url) as api:
            sessions = api.get_sessions(username=user.username).items
        recorded = [
            ts for s in sessions for ts in s.target_sessions if ts.ticket_id == ticket_id
        ]
        assert len(recorded) == 1, "the admitted target session should carry the granting ticket's id"

        _revoke_own_ticket(session, url, ticket_id)

        # Revoked: a new connection is denied again.
        assert _run(processes, driver, wg, username, "123", driver.probe_query(), timeout) != 0
    finally:
        _disable_self_service(url)


def _revoke_closes_a_live_connection(processes, timeout, wg, driver):
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        user, _role = create_password_user(api)
        target = driver.create_target(api)
    username = f"{user.username}#{target.name}"

    _enable_self_service(url)
    try:
        _, ticket_id = _activate_self_service_ticket(url, user.username, target.name)

        client = _start(processes, driver, wg, username, "123", driver.sleep_query())
        time.sleep(3)
        assert client.poll() is None, "session ended before it was revoked"

        with admin_client(url) as api:
            api.delete_ticket(ticket_id)

        # `wait` raises on timeout rather than returning, so reaching the
        # next line at all is "closed"; the interesting assertion is that it
        # closed as a failure, not a completed 3600-second sleep.
        client.wait(timeout=30)
        assert client.returncode != 0
    finally:
        _disable_self_service(url)


def _wrong_password_denied_with_active_ticket(processes, timeout, wg, driver):
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        user, _role = create_password_user(api)
        target = driver.create_target(api, ticket_max_uses=1)
    username = f"{user.username}#{target.name}"

    _enable_self_service(url)
    try:
        _, ticket_id = _activate_self_service_ticket(url, user.username, target.name)

        assert _run(processes, driver, wg, username, "wrong", driver.probe_query(), timeout) != 0

        with admin_client(url) as api:
            assert _ticket_uses_left(api, ticket_id) == 1, (
                "an active ticket must not be spent when the password itself is wrong"
            )

        # The right password still works afterwards.
        assert _run(processes, driver, wg, username, "123", driver.probe_query(), timeout) == 0
    finally:
        _disable_self_service(url)


def _role_wins_and_survives_revoke(processes, timeout, wg, driver):
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        user, role = create_password_user(api)
        # Bounded to one use, so a role grant leaving it untouched is a
        # direct, non-vacuous check rather than relying on an unlimited
        # ticket where "not spent" can't be observed.
        target = driver.create_target(api, ticket_max_uses=1)
        api.add_target_role(target.id, role.id)
    username = f"{user.username}#{target.name}"

    _enable_self_service(url)
    try:
        _, ticket_id = _activate_self_service_ticket(url, user.username, target.name)

        client = _start(processes, driver, wg, username, "123", driver.sleep_query())
        time.sleep(3)
        assert client.poll() is None, "the role-granted connection failed to open"

        with admin_client(url) as api:
            assert _ticket_uses_left(api, ticket_id) == 1, (
                "a role grant must not spend the also-active ticket's use"
            )
            sessions = api.get_sessions(username=user.username).items
        recorded = [ts for s in sessions for ts in s.target_sessions]
        assert recorded and all(ts.ticket_id is None for ts in recorded), (
            "a role grant must not attribute the session to the (also active) ticket"
        )

        with admin_client(url) as api:
            api.delete_ticket(ticket_id)

        time.sleep(3)
        assert client.poll() is None, "revoking an unrelated ticket must not close a role-granted session"

        client.kill()
        client.wait(timeout=timeout)
    finally:
        _disable_self_service(url)


def _bounded_ticket_spends_one_use_and_survives_exhaustion(processes, timeout, wg, driver):
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        user, _role = create_password_user(api)
        target = driver.create_target(api, ticket_max_uses=1)
    username = f"{user.username}#{target.name}"

    _enable_self_service(url)
    try:
        _, ticket_id = _activate_self_service_ticket(url, user.username, target.name)

        # Short enough to run to completion within the test, long enough
        # that the second connection's denial below overlaps it.
        first = _start(processes, driver, wg, username, "123", driver.short_sleep_query())
        with admin_client(url) as api:
            assert _poll(lambda: _ticket_uses_left(api, ticket_id) == 0), (
                "the first connection never spent the ticket's only use"
            )
        assert first.poll() is None, "the first connection ended unexpectedly"

        # No uses left and no role: a second connection is denied while the
        # first is still running its query.
        assert _run(processes, driver, wg, username, "123", driver.probe_query(), timeout) != 0

        # The first connection ran its query to completion rather than being
        # cut short by the second connection's denial.
        assert first.wait(timeout=30) == 0, (
            "an exhausted ticket must not close a session it already admitted"
        )
    finally:
        _disable_self_service(url)


def _ticket_secret_login_still_works(processes, timeout, wg, driver):
    # ticket-<secret> is a separate selector entirely (AuthSelector::Ticket)
    # and never touches roles, so no role is set up here.
    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        user, _role = create_password_user(api)
        target = driver.create_target(api)
        ticket = api.create_ticket(sdk.CreateTicketRequest(
            target_name=target.name, username=user.username,
        ))

    assert _run(
        processes, driver, wg, f"ticket-{ticket.secret}", "x", driver.probe_query(), timeout,
    ) == 0


class TestPostgresTicketGrant:
    def _driver(self, shared_postgres_port, shared_wg: WarpgateProcess):
        driver = _Postgres(shared_postgres_port)
        driver.wait_ready(shared_wg)
        return driver

    def test_lifecycle(self, processes, timeout, shared_wg: WarpgateProcess, shared_postgres_port):
        _lifecycle(processes, timeout, shared_wg, self._driver(shared_postgres_port, shared_wg))

    def test_revoke_closes_a_live_connection(
        self, processes, timeout, shared_wg: WarpgateProcess, shared_postgres_port
    ):
        _revoke_closes_a_live_connection(
            processes, timeout, shared_wg, self._driver(shared_postgres_port, shared_wg)
        )

    def test_wrong_password_denied_with_active_ticket(
        self, processes, timeout, shared_wg: WarpgateProcess, shared_postgres_port
    ):
        _wrong_password_denied_with_active_ticket(
            processes, timeout, shared_wg, self._driver(shared_postgres_port, shared_wg)
        )

    def test_role_wins_and_survives_revoke(
        self, processes, timeout, shared_wg: WarpgateProcess, shared_postgres_port
    ):
        _role_wins_and_survives_revoke(
            processes, timeout, shared_wg, self._driver(shared_postgres_port, shared_wg)
        )

    def test_bounded_ticket_spends_one_use_and_survives_exhaustion(
        self, processes, timeout, shared_wg: WarpgateProcess, shared_postgres_port
    ):
        _bounded_ticket_spends_one_use_and_survives_exhaustion(
            processes, timeout, shared_wg, self._driver(shared_postgres_port, shared_wg)
        )

    def test_ticket_secret_login_still_works(
        self, processes, timeout, shared_wg: WarpgateProcess, shared_postgres_port
    ):
        _ticket_secret_login_still_works(
            processes, timeout, shared_wg, self._driver(shared_postgres_port, shared_wg)
        )


class TestMysqlTicketGrant:
    def _driver(self, processes: ProcessManager, shared_wg: WarpgateProcess):
        driver = _Mysql(processes.start_mysql_server())
        driver.wait_ready(shared_wg)
        return driver

    def test_lifecycle(self, processes, timeout, shared_wg: WarpgateProcess):
        _lifecycle(processes, timeout, shared_wg, self._driver(processes, shared_wg))

    def test_revoke_closes_a_live_connection(self, processes, timeout, shared_wg: WarpgateProcess):
        _revoke_closes_a_live_connection(processes, timeout, shared_wg, self._driver(processes, shared_wg))

    def test_wrong_password_denied_with_active_ticket(
        self, processes, timeout, shared_wg: WarpgateProcess
    ):
        _wrong_password_denied_with_active_ticket(
            processes, timeout, shared_wg, self._driver(processes, shared_wg)
        )

    def test_role_wins_and_survives_revoke(self, processes, timeout, shared_wg: WarpgateProcess):
        _role_wins_and_survives_revoke(processes, timeout, shared_wg, self._driver(processes, shared_wg))

    def test_bounded_ticket_spends_one_use_and_survives_exhaustion(
        self, processes, timeout, shared_wg: WarpgateProcess
    ):
        _bounded_ticket_spends_one_use_and_survives_exhaustion(
            processes, timeout, shared_wg, self._driver(processes, shared_wg)
        )

    def test_ticket_secret_login_still_works(self, processes, timeout, shared_wg: WarpgateProcess):
        _ticket_secret_login_still_works(processes, timeout, shared_wg, self._driver(processes, shared_wg))
