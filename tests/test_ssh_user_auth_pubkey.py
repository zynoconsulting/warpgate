import time
from pathlib import Path
from uuid import uuid4

import requests

from .api_client import admin_client, sdk
from .approval_util import default_params
from .conftest import ProcessManager, WarpgateProcess
from .util import read_until, wait_port


def _enable_self_service(url):
    # `ticket_request_show_all_targets` is required here: our role-less users
    # have no access at all, and without it a request for a target they
    # can't already reach is refused as "not found" (mirrors the setup in
    # test_db_ticket_grant.py).
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
            "description": "SSH JIT access",
        },
    )
    assert resp.status_code == 201, resp.text
    request_id = resp.json()["request"]["id"]

    with admin_client(url) as api:
        api.approve_ticket_request(request_id)

    resp = session.post(f"{url}/@warpgate/api/ticket-requests/{request_id}/activate")
    assert resp.status_code == 200, resp.text
    ticket_id = resp.json()["request"]["ticket_id"]
    assert ticket_id is not None
    return session, ticket_id


def _revoke_own_ticket(session, url, ticket_id):
    resp = session.delete(f"{url}/@warpgate/api/my-tickets/{ticket_id}")
    assert resp.status_code == 204


def _poll(fn, deadline_s=20):
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.5)
    return None


def _session_ended(url, username, protocol):
    with admin_client(url) as api:
        for s in api.get_sessions().items:
            if s.username == username and s.protocol == protocol:
                return s.ended is not None
    return False


def _create_role_less_user(api):
    """A user with no role at all -- so no role can grant any target -- but
    both a password credential (for the self-service web login) and a
    public-key credential (for the SSH login itself)."""
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.create_public_key_credential(
        user.id,
        sdk.NewPublicKeyCredential(
            label="Public Key",
            openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip(),
        ),
    )
    return user


def _create_ssh_target(api, ssh_port):
    return api.create_target(
        sdk.TargetDataRequest(
            name=f"ssh-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetSSHOptions(
                    kind="Ssh",
                    allow_insecure_algos=False,
                    host="127.0.0.1",
                    port=ssh_port,
                    username="root",
                    auth=sdk.SSHTargetAuth(
                        sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                    ),
                )
            ),
        )
    )


def _ssh_ls_bin_sh(processes, shared_wg, user, target, identity="ssh-keys/id_ed25519"):
    """Starts SSH public-key auth as `user:target`; the caller waits for the
    client to exit."""
    return processes.start_ssh_client(
        f"{user.username}:{target.name}@localhost",
        "-p",
        str(shared_wg.ssh_port),
        "-o",
        f"IdentityFile={identity}",
        "-o",
        "PreferredAuthentications=publickey",
        "ls",
        "/bin/sh",
    )


class Test:
    def test_ed25519(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_ed25519.pub").read().strip()
                ),
            )
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

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            # 'sh', '-c', '"ls /bin/sh;sleep 1"',
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0

    def test_rsa(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )

        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_public_key_credential(
                user.id,
                sdk.NewPublicKeyCredential(
                    label="Public Key",
                    openssh_public_key=open("ssh-keys/id_rsa.pub").read().strip()
                ),
            )
            api.add_user_role(user.id, role.id)
            ssh_target = api.create_target(sdk.TargetDataRequest(
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
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            ))
            api.add_target_role(ssh_target.id, role.id)

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-v",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_rsa",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
        assert ssh_client.returncode == 0

        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-o",
            "IdentityFile=ssh-keys/id_ed25519",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAcceptedKeyTypes=+ssh-rsa",
            "ls",
            "/bin/sh",
        )
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0

    def test_active_self_service_ticket_grants_public_key_user(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """An activated self-service ticket grants an authenticated SSH
        `user:target` login when no role grants the target.

        The user's own public-key credential establishes the identity
        (`AuthorizedIdentity`) exactly as in `test_ed25519`; the ticket then
        supplies only the target grant on top of it. This is distinct from
        `ticket-<secret>@` authentication, whose secret is the credential
        itself (see test_ticket_session_termination.py for that path's own
        revoke-closes-session coverage, and
        `test_revoking_the_ticket_closes_a_live_session` below for this one's).
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _create_role_less_user(api)
            ssh_target = _create_ssh_target(api, ssh_port)

        _enable_self_service(url)
        try:
            _activate_self_service_ticket(url, user.username, ssh_target.name)

            ssh_client = _ssh_ls_bin_sh(processes, shared_wg, user, ssh_target)
            assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
            assert ssh_client.returncode == 0
        finally:
            _disable_self_service(url)

    def test_active_ticket_does_not_bypass_the_users_public_key(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """The ticket supplies only the target grant: a key the user never
        registered is still rejected."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _create_role_less_user(api)
            ssh_target = _create_ssh_target(api, ssh_port)

        _enable_self_service(url)
        try:
            _activate_self_service_ticket(url, user.username, ssh_target.name)

            ssh_client = _ssh_ls_bin_sh(
                processes, shared_wg, user, ssh_target, identity="ssh-keys/id_rsa"
            )
            assert ssh_client.communicate(timeout=timeout)[0] == b""
            assert ssh_client.returncode != 0
        finally:
            _disable_self_service(url)

    def test_no_ticket_denies_public_key_user_without_a_role(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """No role, no ticket -- the public key alone must not be enough."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _create_role_less_user(api)
            ssh_target = _create_ssh_target(api, ssh_port)

        ssh_client = _ssh_ls_bin_sh(processes, shared_wg, user, ssh_target)
        assert ssh_client.communicate(timeout=timeout)[0] == b""
        assert ssh_client.returncode != 0

    def test_revoked_ticket_denies_public_key_user_without_a_role(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """A ticket that is no longer active must not grant access.

        Revoked rather than expired: the self-service ticket-request flow
        enforces a 60-second minimum duration, so a real expiry would make
        this test slow. Expired tickets are covered by the core unit test
        `expired_self_service_ticket_never_grants`.
        """
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _create_role_less_user(api)
            ssh_target = _create_ssh_target(api, ssh_port)

        _enable_self_service(url)
        try:
            session, ticket_id = _activate_self_service_ticket(
                url, user.username, ssh_target.name
            )
            _revoke_own_ticket(session, url, ticket_id)

            ssh_client = _ssh_ls_bin_sh(processes, shared_wg, user, ssh_target)
            assert ssh_client.communicate(timeout=timeout)[0] == b""
            assert ssh_client.returncode != 0
        finally:
            _disable_self_service(url)

    def test_ticket_for_another_target_denies_public_key_user(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """An active ticket only grants the target it was activated for."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _create_role_less_user(api)
            ssh_target = _create_ssh_target(api, ssh_port)
            other_target = _create_ssh_target(api, ssh_port)

        _enable_self_service(url)
        try:
            _activate_self_service_ticket(url, user.username, other_target.name)

            ssh_client = _ssh_ls_bin_sh(processes, shared_wg, user, ssh_target)
            assert ssh_client.communicate(timeout=timeout)[0] == b""
            assert ssh_client.returncode != 0
        finally:
            _disable_self_service(url)

    def test_revoking_the_ticket_closes_a_live_session(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        """Revoking the granting ticket closes a session already opened
        through it -- mirrors the SSH case in
        test_ticket_session_termination.py, which covers the same watcher for
        `ticket-<secret>@` sessions."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()]
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _create_role_less_user(api)
            ssh_target = _create_ssh_target(api, ssh_port)

        _enable_self_service(url)
        try:
            session, ticket_id = _activate_self_service_ticket(
                url, user.username, ssh_target.name
            )

            marker = f"ticket-close-{uuid4().hex}"
            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-tt",
                "-o",
                "IdentityFile=ssh-keys/id_ed25519",
                "-o",
                "PreferredAuthentications=publickey",
                f"echo {marker}; sleep 3600",
            )
            output = read_until(
                ssh_client.stdout, marker.encode(), time.monotonic() + timeout
            )
            assert marker.encode() in output, "marker never appeared in session output"
            assert ssh_client.poll() is None, "session ended before it was revoked"

            _revoke_own_ticket(session, url, ticket_id)

            # Raises TimeoutExpired if the session is not closed.
            ssh_client.wait(timeout=30)
            assert _poll(lambda: _session_ended(url, user.username, "SSH")), (
                "session never marked ended after its ticket was revoked"
            )
        finally:
            _disable_self_service(url)
