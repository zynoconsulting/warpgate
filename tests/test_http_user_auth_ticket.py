import ssl
import time
from uuid import uuid4

import requests
from websocket import (
    WebSocketConnectionClosedException,
    WebSocketTimeoutException,
    create_connection,
)

from .api_client import admin_client, sdk
from .approval_util import create_http_target, create_password_user, create_postgres_target
from .conftest import WarpgateProcess
from .test_http_common import *  # noqa


class TestHTTPUserAuthTicket:
    def test_auth_password_success(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id)
            echo_target = api.create_target(sdk.TargetDataRequest(
                name=f"echo-{uuid4()}",
                require_approval=False,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
                    kind="Http",
                    headers={},
                    url=f"http://localhost:{echo_server_port}",
                    tls=sdk.Tls(
                        mode=sdk.TlsMode.DISABLED,
                        verify=False,
                    ),
                )),
            ))
            api.add_target_role(echo_target.id, role.id)

            other_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"other-{uuid4()}",
                    require_approval=False,
                    ticket_requests_disabled=False,
                    ticket_require_approval=False,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetHTTPOptions(
                            kind="Http",
                            headers={},
                            url="http://badhost",
                            tls=sdk.Tls(
                                mode=sdk.TlsMode.DISABLED,
                                verify=False,
                            ),
                        )
                    ),
                )
            )
            api.add_target_role(other_target.id, role.id)
            secret = api.create_ticket(sdk.CreateTicketRequest(
                target_name=echo_target.name,
                username=user.username,
            )).secret

        # ---

        session = requests.Session()
        session.verify = False

        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 != 2

        # Ticket as a header
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
            headers={
                "Authorization": f"Warpgate {secret}",
            },
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

        # Bad ticket
        response = session.get(
            f"{url}/some/path?warpgate-target={echo_target.name}",
            allow_redirects=False,
            headers={
                "Authorization": f"Warpgate bad{secret}",
            },
        )
        assert response.status_code // 100 != 2

        # Ticket as a GET param
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

        # Ensure no access to other targets
        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}&warpgate-target=admin",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2

        assert response.json()["path"] == "/some/path"
        response = session.get(
            f"{url}/some/path?warpgate-ticket={secret}&warpgate-target={other_target.name}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2
        assert response.json()["path"] == "/some/path"

    def test_non_http_ticket_opens_no_session(self, shared_wg: WarpgateProcess):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            target = create_postgres_target(api, role, 1, require_approval=False)
            ticket = api.create_ticket(sdk.CreateTicketRequest(
                target_name=target.name, username=user.username, number_of_uses=1,
            ))

            session = requests.Session()
            session.verify = False
            response = session.get(
                f"{url}/some/path?warpgate-ticket={ticket.secret}",
                allow_redirects=False,
            )
            assert response.status_code // 100 != 2
            info = session.get(f"{url}/@warpgate/api/info").json()
            assert info["username"] is None
            assert not info["authorized_via_ticket"]
            uses_left = next(
                t.uses_left for t in api.get_tickets() if t.id == ticket.ticket.id
            )
            assert uses_left == 1

    def test_deleted_ticket_ends_the_cookie_session(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        # A `?warpgate-ticket=` GET establishes a cookie-backed session that
        # is then reused on every later request, without the ticket param —
        # so revoking the ticket has to be re-checked against that stored
        # session, not just against future logins.
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            echo_target = create_http_target(
                api, role, echo_server_port, require_approval=False
            )
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=echo_target.name, username=user.username
                )
            )

        session = requests.Session()
        session.verify = False

        response = session.get(
            f"{url}/some/path?warpgate-ticket={ticket.secret}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2

        with admin_client(url) as api:
            api.delete_ticket(ticket.ticket.id)

        response = session.get(f"{url}/some/path", allow_redirects=False)
        assert response.status_code // 100 != 2

    def test_deleted_ticket_closes_the_websocket(
        self,
        echo_server_port,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user, role = create_password_user(api)
            echo_target = create_http_target(
                api, role, echo_server_port, require_approval=False
            )
            ticket = api.create_ticket(
                sdk.CreateTicketRequest(
                    target_name=echo_target.name, username=user.username
                )
            )

        session = requests.Session()
        session.verify = False
        response = session.get(
            f"{url}/some/path?warpgate-ticket={ticket.secret}",
            allow_redirects=False,
        )
        assert response.status_code // 100 == 2

        cookies = session.cookies.get_dict()
        cookie = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        ws = create_connection(
            f"wss://localhost:{shared_wg.http_port}/socket?warpgate-target={echo_target.name}",
            cookie=cookie,
            sslopt={"cert_reqs": ssl.CERT_NONE},
        )
        ws.send("test")
        assert ws.recv() == "test"

        with admin_client(url) as api:
            api.delete_ticket(ticket.ticket.id)

        ws.settimeout(0.25)
        deadline = time.monotonic() + 15
        closed = False
        while time.monotonic() < deadline:
            try:
                if ws.recv() == "":
                    closed = True
                    break
            except WebSocketConnectionClosedException:
                closed = True
                break
            except WebSocketTimeoutException:
                continue

        assert closed
        ws.close()
