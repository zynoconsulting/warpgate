from pathlib import Path
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


class Test:
    def test(
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

            secret = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                )
            ).secret

            ssh_client = processes.start_ssh_client(
                f"ticket-{secret}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                "-i",
                str(Path("ssh-keys/id_ed25519")),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "ls",
                "/bin/sh",
            )
            assert ssh_client.communicate(timeout=timeout)[0] == b"/bin/sh\n"
            assert ssh_client.returncode == 0

    def test_ticket_secret_refused_when_user_has_explicit_ssh_credential_policy(
        self,
        processes: ProcessManager,
        wg_c_ed25519_pubkey: Path,
        timeout,
        shared_wg: WarpgateProcess,
    ):
        # A ticket secret used directly as the credential (the
        # `ticket-<secret>@...` username) can't satisfy any credential-policy
        # factor -- it isn't a public key, an SSO assertion, etc. So a user
        # with an explicit, non-empty SSH credential policy must not be able
        # to use a ticket secret to bypass it, and the ticket must not be
        # spent on the attempt.
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
            api.update_user(
                user.id,
                sdk.UserDataRequest(
                    username=user.username,
                    credential_policy=sdk.UserRequireCredentialsPolicy(
                        ssh=["PublicKey"],
                    ),
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
                            host="127.0.0.1",
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

            created = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=ssh_target.name,
                    username=user.username,
                    number_of_uses=1,
                )
            )
            ticket_id = created.ticket.id
            secret = created.secret

        ssh_client = processes.start_ssh_client(
            f"ticket-{secret}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            "-i",
            "/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "ls",
            "/bin/sh",
            password="123",
        )
        ssh_client.communicate(timeout=timeout)
        assert ssh_client.returncode != 0, (
            "a ticket-secret login must be refused when the user's SSH "
            "credential policy is explicit and non-empty"
        )

        with admin_client(url) as api:
            tickets = {t.id: t for t in api.get_tickets()}
        assert tickets[ticket_id].uses_left == 1, (
            "a ticket-secret login refused for policy reasons must not spend the ticket"
        )
