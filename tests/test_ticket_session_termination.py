"""A ticket's own liveness ends the sessions it authorized, not just new
admissions:

- deleting (revoking) a ticket closes every live session it opened
- an expired ticket does the same, right at its deadline
- exhausting a ticket's *uses* must NOT close a session already admitted
  under it -- only block a further one

Covers SSH, PostgreSQL and MySQL: each protocol's session close path is
different code, and this is what proves the access watcher actually reaches
all of them, not just the one it was written against.
"""

import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .api_client import admin_client, sdk
from .approval_util import create_mysql_target, create_postgres_target
from .conftest import ProcessManager, WarpgateProcess
from .test_ssh_proto import common_args
from .util import (
    mysql_client_opts,
    mysql_client_ssl_opt,
    read_until,
    wait_mysql_port,
    wait_port,
)


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


def _session_ended(url, username, protocol):
    with admin_client(url) as api:
        for s in api.get_sessions().items:
            if s.username == username and s.protocol == protocol:
                return s.ended is not None
    return False


class TestSsh:
    def test_deleted_ticket_closes_a_live_session(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

            # A single-use ticket: the one use is spent the moment the
            # session authenticates, well before we get around to deleting
            # it -- so this also proves the exhausted `uses_left` alone
            # (asserted below) never closes what it already admitted.
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                    number_of_uses=1,
                )
            )

        marker = f"ticket-close-{uuid4().hex}"
        ssh_client = processes.start_ssh_client(
            f"ticket-{ticket.secret}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 3600",
            password="123",
        )
        output = read_until(
            ssh_client.stdout, marker.encode(), time.monotonic() + timeout
        )
        assert marker.encode() in output, "marker never appeared in session output"

        # The ticket's one use is already spent; the session must stay open
        # regardless.
        with admin_client(url) as api:
            assert _ticket_uses_left(api, ticket.ticket.id) == 0
        assert ssh_client.poll() is None, "session ended before it was revoked"

        with admin_client(url) as api:
            api.delete_ticket(ticket.ticket.id)

        assert ssh_client.wait(timeout=30) is not None, "session was not closed"

        assert _poll(lambda: _session_ended(url, user.username, "SSH")), (
            "session never marked ended after its ticket was deleted"
        )

    def test_expired_ticket_closes_a_live_session_at_its_deadline(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            allow_insecure_algos=False,
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(
                                    kind="PublicKey"
                                )
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(ssh_target.id, role.id)

            expiry = (datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                    expiry=expiry,
                )
            )

        marker = f"ticket-expiry-{uuid4().hex}"
        ssh_client = processes.start_ssh_client(
            f"ticket-{ticket.secret}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-tt",
            *common_args,
            f"echo {marker}; sleep 3600",
            password="123",
        )
        output = read_until(
            ssh_client.stdout, marker.encode(), time.monotonic() + timeout
        )
        assert marker.encode() in output, "marker never appeared in session output"

        # Still well within the ticket's 10s life.
        time.sleep(3)
        assert ssh_client.poll() is None, "session ended before its ticket expired"

        # The watcher closes it at the deadline itself, not on some later
        # coarse poll -- so this should land well before the default 5s poll
        # interval would even matter.
        assert ssh_client.wait(timeout=30) is not None, (
            "session was not closed at its ticket's expiry"
        )


class TestPostgres:
    def test_deleted_ticket_closes_a_live_session(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
        shared_postgres_port,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.add_user_role(user.id, role.id)
            target = create_postgres_target(
                api, role, shared_postgres_port, require_approval=False
            )
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=target.name, username=user.username
                )
            )

        wait_port(shared_wg.postgres_port, recv=False)
        client = processes.start(
            [
                "psql",
                "--user",
                f"ticket-{ticket.secret}",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.postgres_port),
                "-c",
                "select pg_sleep(3600)",
                "db",
            ],
            env={"PGPASSWORD": "x", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # Long enough that a still-running process means the query is
        # genuinely blocked in pg_sleep, not just slow to start.
        time.sleep(3)
        assert client.poll() is None, "session ended before it was revoked"

        with admin_client(url) as api:
            api.delete_ticket(ticket.ticket.id)

        assert client.wait(timeout=30) is not None, "session was not closed"
        assert client.returncode != 0

    def test_exhausted_uses_do_not_close_a_live_session(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
        shared_postgres_port,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.add_user_role(user.id, role.id)
            target = create_postgres_target(
                api, role, shared_postgres_port, require_approval=False
            )
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=target.name,
                    username=user.username,
                    number_of_uses=1,
                )
            )

        wait_port(shared_wg.postgres_port, recv=False)
        client = processes.start(
            [
                "psql",
                "--user",
                f"ticket-{ticket.secret}",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.postgres_port),
                "-c",
                "select pg_sleep(7)",
                "db",
            ],
            env={"PGPASSWORD": "x", **os.environ},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        with admin_client(url) as api:
            assert _poll(lambda: _ticket_uses_left(api, ticket.ticket.id) == 0), (
                "ticket use was never spent"
            )
        assert client.poll() is None, "session ended even though it was already admitted"

        # Ran the query to completion rather than being closed.
        assert client.wait(timeout=30) == 0


class TestMysql:
    def test_deleted_ticket_closes_a_live_session(
        self,
        processes: ProcessManager,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        db_port = processes.start_mysql_server()
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.add_user_role(user.id, role.id)
            target = create_mysql_target(api, role, db_port, require_approval=False)
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=target.name, username=user.username
                )
            )

        wait_mysql_port(db_port)
        wait_port(shared_wg.mysql_port, recv=False)
        client = processes.start(
            [
                "mysql",
                "--user",
                f"ticket-{ticket.secret}",
                "-px",
                "--host",
                "127.0.0.1",
                "--port",
                str(shared_wg.mysql_port),
                *mysql_client_opts,
                mysql_client_ssl_opt,
                "-e",
                "select sleep(3600)",
                "db",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        time.sleep(3)
        assert client.poll() is None, "session ended before it was revoked"

        with admin_client(url) as api:
            api.delete_ticket(ticket.ticket.id)

        assert client.wait(timeout=30) is not None, "session was not closed"
        assert client.returncode != 0
