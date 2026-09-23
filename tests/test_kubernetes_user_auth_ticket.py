"""Kubernetes tickets route without a target selector or additional credentials."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import subprocess
import time
from uuid import uuid4

import pytest
import requests
import yaml

from .api_client import admin_client, sdk
from .util import alloc_port, wait_port


def create_target(api, port):
    return api.create_target(sdk.TargetDataRequest(
        name=f"k8s-ticket-{uuid4()}",
        require_approval=False,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        options=sdk.TargetOptions(sdk.TargetOptionsTargetKubernetesOptions(
            kind="Kubernetes",
            cluster_url=f"http://127.0.0.1:{port}",
            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
            auth=sdk.KubernetesTargetAuth(
                sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                    kind="Token", token="upstream-token",
                ),
            ),
        )),
    ))


@pytest.fixture
def ticket_setup(shared_wg, echo_server_port):
    with admin_client(f"https://localhost:{shared_wg.http_port}") as api:
        # No roles, password, API token or certificate: only the ticket grants access.
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        target = create_target(api, echo_server_port)
        yield api, user, target


def create_ticket(setup, **kwargs):
    api, user, target = setup
    return api.create_ticket(sdk.CreateTicketRequest(
        username=user.username, target_name=target.name, **kwargs,
    ))


def request(wg, secret, path="/api", **kwargs):
    return requests.get(
        f"https://localhost:{wg.kubernetes_port}{path}",
        headers={"Authorization": f"Bearer ticket-{secret}"},
        verify=False, timeout=10, **kwargs,
    )


def uses_left(setup, ticket):
    return next(t.uses_left for t in setup[0].get_tickets() if t.id == ticket.ticket.id)


def test_ticket_selects_target_and_shares_one_use(shared_wg, ticket_setup):
    ticket = create_ticket(ticket_setup, number_of_uses=1)
    paths = ["/", "/api", "/apis", "/version", "/api/v1/pods?limit=1"] * 3
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda path: request(shared_wg, ticket.secret, path), paths))
    for response, path in zip(responses, paths):
        assert response.status_code == 200, response.text
        assert response.json()["path"] == path.split("?")[0]
        headers = {k.lower(): v for k, v in response.json()["headers"]}
        assert headers["authorization"] == "Bearer upstream-token"
    assert responses[4].json()["args"] == {"limit": "1"}
    assert uses_left(ticket_setup, ticket) == 0
    sessions = ticket_setup[0].get_sessions(username=ticket_setup[1].username).items
    recorded = [
        target_session for session in sessions
        for target_session in session.target_sessions
        if target_session.ticket_id == ticket.ticket.id
    ]
    assert len(recorded) == 1
    assert recorded[0].target_id == ticket_setup[2].id

    # URL components and query parameters cannot override the ticket's target.
    response = request(shared_wg, ticket.secret, "/admin/api?warpgate-target=admin")
    assert response.status_code == 200
    assert response.json()["path"] == "/admin/api"

    # Another ticket for the same user/target/IP must open its own session.
    exhausted = create_ticket(ticket_setup, number_of_uses=0)
    assert request(shared_wg, exhausted.secret).status_code == 401
    second = create_ticket(ticket_setup, number_of_uses=1)
    assert request(shared_wg, second.secret).status_code == 200
    assert uses_left(ticket_setup, second) == 0


def test_ticket_revocation_applies_to_cached_session(shared_wg, ticket_setup):
    ticket = create_ticket(ticket_setup)
    assert request(shared_wg, ticket.secret).status_code == 200
    assert uses_left(ticket_setup, ticket) is None
    ticket_setup[0].delete_ticket(ticket.ticket.id)
    assert request(shared_wg, ticket.secret).status_code == 401


def test_kubectl_with_targetless_ticket_kubeconfig(shared_wg, ticket_setup, tmp_path):
    ticket = create_ticket(ticket_setup, number_of_uses=1)
    config = tmp_path / "warpgate-kubeconfig.yaml"
    config.write_text(yaml.safe_dump({
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "warpgate", "cluster": {
            "server": f"https://localhost:{shared_wg.kubernetes_port}",
            "insecure-skip-tls-verify": True,
        }}],
        "users": [{"name": "ticket", "user": {"token": f"ticket-{ticket.secret}"}}],
        "contexts": [{"name": "ticket", "context": {"cluster": "warpgate", "user": "ticket"}}],
        "current-context": "ticket",
    }))
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(config), "get", "--raw=/version"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["path"] == "/version"
    assert uses_left(ticket_setup, ticket) == 0


def test_normal_api_token_cannot_join_ticket_session(shared_wg, ticket_setup):
    api, user, target = ticket_setup
    ticket = create_ticket(ticket_setup)
    assert request(shared_wg, ticket.secret).status_code == 200
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    with requests.Session() as session:
        session.verify = False
        url = f"https://localhost:{shared_wg.http_port}/@warpgate/api"
        login = session.post(f"{url}/auth/login", json={
            "username": user.username, "password": "123",
        }, timeout=10)
        login.raise_for_status()
        token_response = session.post(f"{url}/profile/api-tokens", json={
            "label": "kubernetes-ticket-isolation",
            "expiry": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }, timeout=10)
        token_response.raise_for_status()
        headers = {"Authorization": f"Bearer {token_response.json()['secret']}"}

    def normal_request(path):
        return requests.get(
            f"https://localhost:{shared_wg.kubernetes_port}{path}",
            headers=headers, verify=False, timeout=10,
        )

    # Same identity and IP as the ticket, but no role grants normal access.
    assert normal_request(f"/{target.name}/api").status_code == 403
    role = api.create_role(sdk.RoleDataRequest(name=f"k8s-role-{uuid4()}"))
    api.add_user_role(user.id, role.id)
    api.add_target_role(target.id, role.id)
    response = normal_request(f"/{target.name}/api/v1/pods")
    assert response.status_code == 200, response.text
    assert response.json()["path"] == "/api/v1/pods"
    assert normal_request("/api").status_code == 404


def test_activated_request_grants_normal_identity_access(shared_wg, ticket_setup):
    api, user, target = ticket_setup
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.update_parameters(
        sdk.ParameterUpdate(
            allow_own_credential_management=True,
            rate_limit_bytes_per_second=None,
            ssh_client_auth_keyboard_interactive=True,
            ssh_client_auth_password=True,
            ssh_client_auth_publickey=True,
            ticket_self_service_enabled=True,
            ticket_auto_approve_existing_access=False,
            ticket_max_uses=None,
            ticket_require_description=True,
            ticket_request_show_all_targets=True,
        )
    )

    url = f"https://localhost:{shared_wg.http_port}"
    try:
        with requests.Session() as session:
            session.verify = False
            login = session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                timeout=10,
            )
            login.raise_for_status()
            token_response = session.post(
                f"{url}/@warpgate/api/profile/api-tokens",
                json={
                    "label": "kubernetes-jit",
                    "expiry": (
                        datetime.now(timezone.utc) + timedelta(hours=1)
                    ).isoformat(),
                },
                timeout=10,
            )
            token_response.raise_for_status()
            headers = {"Authorization": f"Bearer {token_response.json()['secret']}"}
            endpoint = (
                f"https://localhost:{shared_wg.kubernetes_port}/{target.name}/version"
            )

            # The upstream credential is permanently powerful, but Warpgate has not
            # granted this user access to the target yet.
            denied = requests.get(
                endpoint, headers=headers, verify=False, timeout=10
            )
            assert denied.status_code == 403

            request_response = session.post(
                f"{url}/@warpgate/api/ticket-requests",
                json={
                    "target_name": target.name,
                    "duration_seconds": 3600,
                    "description": "temporary Kubernetes access",
                },
                timeout=10,
            )
            request_response.raise_for_status()
            request_id = request_response.json()["request"]["id"]
            api.approve_ticket_request(request_id)

            # Approval alone is insufficient: activation starts the access window.
            not_activated = requests.get(
                endpoint, headers=headers, verify=False, timeout=10
            )
            assert not_activated.status_code == 403
            activation = session.post(
                f"{url}/@warpgate/api/ticket-requests/{request_id}/activate",
                timeout=10,
            )
            activation.raise_for_status()
            ticket_id = activation.json()["request"]["ticket_id"]

            allowed = requests.get(
                endpoint, headers=headers, verify=False, timeout=10
            )
            assert allowed.status_code == 200, allowed.text
            assert allowed.json()["path"] == "/version"

            revoked = session.delete(
                f"{url}/@warpgate/api/my-tickets/{ticket_id}", timeout=10
            )
            assert revoked.status_code == 204
            denied_after_revocation = requests.get(
                endpoint, headers=headers, verify=False, timeout=10
            )
            assert denied_after_revocation.status_code == 403
    finally:
        api.update_parameters(
            sdk.ParameterUpdate(
                allow_own_credential_management=True,
                rate_limit_bytes_per_second=None,
                ssh_client_auth_keyboard_interactive=True,
                ssh_client_auth_password=True,
                ssh_client_auth_publickey=True,
                ticket_self_service_enabled=False,
                ticket_auto_approve_existing_access=True,
                ticket_require_description=False,
                ticket_request_show_all_targets=False,
            )
        )


def _enable_self_service(api):
    api.update_parameters(
        sdk.ParameterUpdate(
            allow_own_credential_management=True,
            rate_limit_bytes_per_second=None,
            ssh_client_auth_keyboard_interactive=True,
            ssh_client_auth_password=True,
            ssh_client_auth_publickey=True,
            ticket_self_service_enabled=True,
            ticket_auto_approve_existing_access=False,
            ticket_max_uses=None,
            ticket_require_description=True,
            ticket_request_show_all_targets=True,
        )
    )


def _disable_self_service(api):
    api.update_parameters(
        sdk.ParameterUpdate(
            allow_own_credential_management=True,
            rate_limit_bytes_per_second=None,
            ssh_client_auth_keyboard_interactive=True,
            ssh_client_auth_password=True,
            ssh_client_auth_publickey=True,
            ticket_self_service_enabled=False,
            ticket_auto_approve_existing_access=True,
            ticket_require_description=False,
            ticket_request_show_all_targets=False,
        )
    )


def _user_api_token(session, url, label="kubernetes-jit"):
    token_response = session.post(
        f"{url}/@warpgate/api/profile/api-tokens",
        json={
            "label": label,
            "expiry": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
        timeout=10,
    )
    token_response.raise_for_status()
    return token_response.json()["secret"]


def _activate_self_service_ticket(api, session, url, target, duration_seconds=3600):
    """Request, approve and activate a self-service ticket for `target`,
    returning its id. The request/approve/activate ceremony itself is
    exercised end to end by `test_activated_request_grants_normal_identity_access`;
    the tests below only need the resulting active ticket."""
    request_response = session.post(
        f"{url}/@warpgate/api/ticket-requests",
        json={
            "target_name": target.name,
            "duration_seconds": duration_seconds,
            "description": "JIT test access",
        },
        timeout=10,
    )
    request_response.raise_for_status()
    request_id = request_response.json()["request"]["id"]
    api.approve_ticket_request(request_id)
    activation = session.post(
        f"{url}/@warpgate/api/ticket-requests/{request_id}/activate", timeout=10,
    )
    activation.raise_for_status()
    return activation.json()["request"]["ticket_id"]


def test_ticket_grant_does_not_bypass_credential_policy(shared_wg, ticket_setup):
    """An active self-service ticket supplies only the target grant: it must
    not let a request skip the user's Kubernetes credential policy (web
    approval). Exercises the auth-then-role-then-ticket ordering in
    `authorize_kubernetes_target` — a ticket alone must not bypass the
    identity checks a normal login would have to pass."""
    api, user, target = ticket_setup
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.update_user(
        user.id,
        sdk.UserDataRequest(
            username=user.username,
            credential_policy=sdk.UserRequireCredentialsPolicy(
                kubernetes=[sdk.CredentialKind.WEBUSERAPPROVAL],
            ),
        ),
    )
    _enable_self_service(api)

    url = f"https://localhost:{shared_wg.http_port}"
    try:
        with requests.Session() as session:
            session.verify = False
            login = session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                timeout=10,
            )
            login.raise_for_status()
            headers = {"Authorization": f"Bearer {_user_api_token(session, url)}"}
            endpoint = f"https://localhost:{shared_wg.kubernetes_port}/{target.name}/version"

            _activate_self_service_ticket(api, session, url, target)

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    requests.get, endpoint, headers=headers, verify=False, timeout=15,
                )

                # The active ticket must not let the request through on its
                # own: it still has to raise (and wait for) a web approval.
                auth_id = None
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    pending_response = session.get(
                        f"{url}/@warpgate/api/auth/web-auth-requests", timeout=10,
                    )
                    pending_response.raise_for_status()
                    pending = [
                        s for s in pending_response.json()
                        if s["protocol"] == "Kubernetes"
                    ]
                    if pending:
                        auth_id = pending[0]["id"]
                        break
                    time.sleep(0.2)
                assert auth_id is not None, (
                    "the ticket let the request through without web approval"
                )
                assert not future.done(), "request completed before approval"

                approve = session.post(
                    f"{url}/@warpgate/api/auth/state/{auth_id}/approve",
                    json={"scope": "Once"},
                    timeout=10,
                )
                assert approve.status_code == 200

                response = future.result(timeout=15)
                assert response.status_code == 200, response.text
    finally:
        _disable_self_service(api)


def test_denied_web_approval_does_not_spend_a_ticket_use(shared_wg, ticket_setup):
    """A request that never gets past the credential policy must not spend a
    bounded ticket's use: identity/policy is checked before the ticket grant
    (and its spend), so a rejection has to leave `uses_left` untouched."""
    api, user, target = ticket_setup
    api.update_target(target.id, sdk.TargetDataRequest(
        name=target.name,
        require_approval=False,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        ticket_max_uses=1,
        options=target.options,
    ))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    api.update_user(
        user.id,
        sdk.UserDataRequest(
            username=user.username,
            credential_policy=sdk.UserRequireCredentialsPolicy(
                kubernetes=[sdk.CredentialKind.WEBUSERAPPROVAL],
            ),
        ),
    )
    _enable_self_service(api)

    url = f"https://localhost:{shared_wg.http_port}"
    try:
        with requests.Session() as session:
            session.verify = False
            login = session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                timeout=10,
            )
            login.raise_for_status()
            headers = {"Authorization": f"Bearer {_user_api_token(session, url)}"}
            endpoint = f"https://localhost:{shared_wg.kubernetes_port}/{target.name}/version"

            ticket_id = _activate_self_service_ticket(api, session, url, target)

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    requests.get, endpoint, headers=headers, verify=False, timeout=15,
                )

                auth_id = None
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    pending_response = session.get(
                        f"{url}/@warpgate/api/auth/web-auth-requests", timeout=10,
                    )
                    pending_response.raise_for_status()
                    pending = [
                        s for s in pending_response.json()
                        if s["protocol"] == "Kubernetes"
                    ]
                    if pending:
                        auth_id = pending[0]["id"]
                        break
                    time.sleep(0.2)
                assert auth_id is not None

                reject = session.post(
                    f"{url}/@warpgate/api/auth/state/{auth_id}/reject", timeout=10,
                )
                assert reject.status_code == 200

                response = future.result(timeout=15)
                assert response.status_code in (401, 403), response.text

            remaining = next(
                t.uses_left for t in api.get_tickets() if str(t.id) == ticket_id
            )
            assert remaining == 1
    finally:
        _disable_self_service(api)


def test_revoked_grant_evicts_the_session_for_an_immediate_retry(shared_wg, ticket_setup):
    """Revoking the ticket behind an admitted grant must evict the stale
    correlated session, not just deny the request that noticed: a fresh
    ticket has to grant on its very next request, without waiting for
    `session_max_age` to age the stale entry out on its own."""
    api, user, target = ticket_setup
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    _enable_self_service(api)

    url = f"https://localhost:{shared_wg.http_port}"
    try:
        with requests.Session() as session:
            session.verify = False
            login = session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                timeout=10,
            )
            login.raise_for_status()
            headers = {"Authorization": f"Bearer {_user_api_token(session, url)}"}
            endpoint = f"https://localhost:{shared_wg.kubernetes_port}/{target.name}/version"

            ticket_a = _activate_self_service_ticket(api, session, url, target)
            allowed = requests.get(endpoint, headers=headers, verify=False, timeout=10)
            assert allowed.status_code == 200, allowed.text

            revoked = session.delete(
                f"{url}/@warpgate/api/my-tickets/{ticket_a}", timeout=10,
            )
            assert revoked.status_code == 204

            denied = requests.get(endpoint, headers=headers, verify=False, timeout=10)
            assert denied.status_code == 403

            # A second self-service ticket for the same user/target. If the
            # denied request above only failed without evicting the stale
            # session, this would keep failing until session_max_age passed.
            _activate_self_service_ticket(api, session, url, target)
            allowed_again = requests.get(endpoint, headers=headers, verify=False, timeout=10)
            assert allowed_again.status_code == 200, allowed_again.text
    finally:
        _disable_self_service(api)


def test_bounded_ticket_spends_one_use_per_correlated_session(shared_wg, ticket_setup):
    """A bounded self-service ticket (``ticket_max_uses=1``) still grants JIT
    access: the correlated session behind one kubectl-style command spends
    exactly one use, and later requests within that same session keep
    working because the per-request re-check ignores `uses_left`."""
    api, user, target = ticket_setup
    api.update_target(target.id, sdk.TargetDataRequest(
        name=target.name,
        require_approval=False,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        ticket_max_uses=1,
        options=target.options,
    ))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    _enable_self_service(api)

    url = f"https://localhost:{shared_wg.http_port}"
    try:
        with requests.Session() as session:
            session.verify = False
            login = session.post(
                f"{url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
                timeout=10,
            )
            login.raise_for_status()
            headers = {"Authorization": f"Bearer {_user_api_token(session, url)}"}
            ticket_id = _activate_self_service_ticket(api, session, url, target)

            def get(path):
                return requests.get(
                    f"https://localhost:{shared_wg.kubernetes_port}/{target.name}{path}",
                    headers=headers, verify=False, timeout=10,
                )

            # A kubectl command's fan-out of requests shares one correlated
            # session, so it must spend only a single use of the ticket.
            paths = ["/version", "/api", "/apis"]
            with ThreadPoolExecutor(max_workers=len(paths)) as pool:
                responses = list(pool.map(get, paths))
            for response, path in zip(responses, paths):
                assert response.status_code == 200, response.text
                assert response.json()["path"] == path

            remaining = next(
                t.uses_left for t in api.get_tickets() if str(t.id) == ticket_id
            )
            assert remaining == 0

            # A later request in the same correlated session must keep
            # working: the re-check must not consider uses_left, since the
            # session already paid for it.
            more = get("/version")
            assert more.status_code == 200, more.text
    finally:
        _disable_self_service(api)


def test_ticket_expiry_applies_to_cached_session(shared_wg, ticket_setup):
    expiry = datetime.now(timezone.utc) + timedelta(seconds=3)
    ticket = create_ticket(ticket_setup, expiry=expiry)
    assert request(shared_wg, ticket.secret).status_code == 200
    time.sleep(max(0, (expiry - datetime.now(timezone.utc)).total_seconds()) + 0.1)
    assert request(shared_wg, ticket.secret).status_code == 401


def test_ticket_rechecks_user_ip_restrictions(shared_wg, ticket_setup):
    api, user, _ = ticket_setup
    ticket = create_ticket(ticket_setup)
    assert request(shared_wg, ticket.secret).status_code == 200
    api.update_user(user.id, sdk.UserDataRequest(
        username=user.username, allowed_ip_ranges=["192.0.2.0/24"],
    ))
    assert request(shared_wg, ticket.secret).status_code == 401


def test_non_kubernetes_ticket_is_not_spent(shared_wg, ticket_setup):
    api, user, _ = ticket_setup
    target = api.create_target(sdk.TargetDataRequest(
        name=f"http-ticket-{uuid4()}",
        require_approval=False,
        ticket_requests_disabled=False,
        ticket_require_approval=False,
        options=sdk.TargetOptions(sdk.TargetOptionsTargetHTTPOptions(
            kind="Http", url="http://127.0.0.1:1", headers={},
            tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
        )),
    ))
    ticket = create_ticket((api, user, target), number_of_uses=1)
    assert request(shared_wg, ticket.secret).status_code == 401
    assert uses_left(ticket_setup, ticket) == 1


def test_ticket_session_lifetime_is_enforced(processes, echo_server_port):
    wg = processes.start_wg(config_patch={"kubernetes": {"session_max_age": "1s"}})
    wait_port(wg.kubernetes_port, for_process=wg.process, recv=False)
    wait_port(wg.http_port, for_process=wg.process, recv=False)
    with admin_client(f"https://localhost:{wg.http_port}") as api:
        user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
        setup = api, user, create_target(api, echo_server_port)
        ticket = create_ticket(setup, number_of_uses=2)
        assert request(wg, ticket.secret).status_code == 200
        assert uses_left(setup, ticket) == 1
        time.sleep(1.1)
        assert request(wg, ticket.secret).status_code == 200
        assert uses_left(setup, ticket) == 0
        time.sleep(1.1)
        assert request(wg, ticket.secret).status_code == 401


def test_single_use_is_atomic_across_nodes(processes, shared_wg, ticket_setup):
    peer = processes.start_wg(share_with=shared_wg)
    wait_port(peer.kubernetes_port, for_process=peer.process, recv=False)
    ticket = create_ticket(ticket_setup, number_of_uses=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda wg: request(wg, ticket.secret), [shared_wg, peer]))
    assert sorted(r.status_code for r in responses) == [200, 401]
    assert uses_left(ticket_setup, ticket) == 0


@pytest.mark.asyncio
async def test_ticket_websocket_uses_same_session(shared_wg, ticket_setup):
    import aiohttp
    from aiohttp import web

    async def upstream(req):
        assert req.headers["Authorization"] == "Bearer upstream-token"
        if req.path == "/api":
            return web.json_response({})
        ws = web.WebSocketResponse(protocols=["v4.channel.k8s.io"])
        await ws.prepare(req)
        async for message in ws:
            await ws.send_str(message.data)
        return ws

    app = web.Application()
    app.router.add_get("/{path:.*}", upstream)
    runner = web.AppRunner(app)
    await runner.setup()
    port = alloc_port()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    try:
        api, user, _ = ticket_setup
        setup = api, user, create_target(api, port)
        ticket = create_ticket(setup, number_of_uses=1)
        async with aiohttp.ClientSession(headers={
            "Authorization": f"Bearer ticket-{ticket.secret}",
        }) as session:
            url = f"https://localhost:{shared_wg.kubernetes_port}"
            async with session.get(f"{url}/api", ssl=False) as response:
                assert response.status == 200
            async with session.ws_connect(
                f"{url}/socket", ssl=False, protocols=["v4.channel.k8s.io"],
            ) as ws:
                await ws.send_str("ticket websocket")
                assert (await ws.receive(timeout=5)).data == "ticket websocket"
        assert uses_left(setup, ticket) == 0
    finally:
        await runner.cleanup()


async def _run_echo_and_watch_upstream():
    """An upstream mock that echoes over a websocket and, for `watch=true`,
    streams chunks forever. Returns (runner, port); caller must `.cleanup()`
    the runner.
    """
    import aiohttp
    from aiohttp import web

    async def upstream(req):
        assert req.headers["Authorization"] == "Bearer upstream-token"
        if req.query.get("watch") == "true":
            resp = web.StreamResponse(headers={"Transfer-Encoding": "chunked"})
            await resp.prepare(req)
            try:
                while True:
                    await resp.write(b'{"type":"ADDED"}\n')
                    await asyncio.sleep(0.5)
            except (ConnectionResetError, asyncio.CancelledError):
                pass
            return resp
        if req.path == "/api":
            return web.json_response({})
        ws = web.WebSocketResponse(protocols=["v4.channel.k8s.io"])
        await ws.prepare(req)
        async for message in ws:
            await ws.send_str(message.data)
        return ws

    app = web.Application()
    app.router.add_get("/{path:.*}", upstream)
    runner = web.AppRunner(app)
    await runner.setup()
    port = alloc_port()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    return runner, port


@pytest.mark.asyncio
async def test_ticket_revocation_closes_open_websocket(shared_wg, ticket_setup):
    """A ticket admits a correlated session once and it is then reused for a
    long time (`session_max_age`); revoking the ticket has to reach a
    websocket that is already open under it, not just refuse the next new
    one."""
    import aiohttp

    runner, port = await _run_echo_and_watch_upstream()
    try:
        api, user, _ = ticket_setup
        setup = api, user, create_target(api, port)
        ticket = create_ticket(setup, number_of_uses=1)
        async with aiohttp.ClientSession(headers={
            "Authorization": f"Bearer ticket-{ticket.secret}",
        }) as session:
            url = f"https://localhost:{shared_wg.kubernetes_port}"
            async with session.ws_connect(
                f"{url}/socket", ssl=False, protocols=["v4.channel.k8s.io"],
            ) as ws:
                await ws.send_str("still alive")
                assert (await ws.receive(timeout=5)).data == "still alive"

                api.delete_ticket(ticket.ticket.id)

                closed = await ws.receive(timeout=15)
                assert closed.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.ERROR,
                ), closed
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_ticket_revocation_ends_watch_stream(shared_wg, ticket_setup):
    """A `?watch=true` chunked stream (`kubectl get --watch`) opened once
    under a ticket must EOF when that ticket is revoked, even though it was
    admitted long before the revoke."""
    import aiohttp

    runner, port = await _run_echo_and_watch_upstream()
    try:
        api, user, _ = ticket_setup
        setup = api, user, create_target(api, port)
        ticket = create_ticket(setup, number_of_uses=1)
        async with aiohttp.ClientSession(headers={
            "Authorization": f"Bearer ticket-{ticket.secret}",
        }) as session:
            url = f"https://localhost:{shared_wg.kubernetes_port}"
            async with session.get(
                f"{url}/api/v1/pods?watch=true", ssl=False
            ) as response:
                assert response.status == 200
                # At least one chunk, so the stream is genuinely open before
                # we revoke it.
                chunk = await asyncio.wait_for(
                    response.content.readline(), timeout=5
                )
                assert b"ADDED" in chunk

                api.delete_ticket(ticket.ticket.id)

                # EOFs (readline returns b"") instead of streaming forever.
                async def drain():
                    while True:
                        data = await response.content.readline()
                        if not data:
                            return

                await asyncio.wait_for(drain(), timeout=15)
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_admin_close_session_ends_websocket(shared_wg, ticket_setup):
    """Admin-initiated close reaches an open Kubernetes websocket too --
    `KubernetesSessionHandle::close()` used to be a no-op, so this never
    worked before."""
    import aiohttp

    runner, port = await _run_echo_and_watch_upstream()
    try:
        api, user, _ = ticket_setup
        setup = api, user, create_target(api, port)
        ticket = create_ticket(setup, number_of_uses=1)
        async with aiohttp.ClientSession(headers={
            "Authorization": f"Bearer ticket-{ticket.secret}",
        }) as session:
            url = f"https://localhost:{shared_wg.kubernetes_port}"
            async with session.ws_connect(
                f"{url}/socket", ssl=False, protocols=["v4.channel.k8s.io"],
            ) as ws:
                await ws.send_str("still alive")
                assert (await ws.receive(timeout=5)).data == "still alive"

                session_id = next(
                    s.id for s in api.get_sessions(username=user.username).items
                    if s.protocol == "Kubernetes" and s.ended is None
                )
                api.close_session(session_id)

                closed = await ws.receive(timeout=15)
                assert closed.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.ERROR,
                ), closed
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_ticket_revocation_still_closes_a_websocket_after_session_max_age(
    processes, echo_server_port
):
    """A correlated session's cache entry ageing out (`session_max_age`) must
    not silently kill its access watcher out from under a websocket that is
    still open under it -- otherwise a later ticket revocation (or even an
    admin close) can no longer reach that websocket at all, since nothing is
    watching it any more.
    """
    import aiohttp

    wg = processes.start_wg(config_patch={"kubernetes": {"session_max_age": "1s"}})
    wait_port(wg.kubernetes_port, for_process=wg.process, recv=False)
    wait_port(wg.http_port, for_process=wg.process, recv=False)

    runner, port = await _run_echo_and_watch_upstream()
    try:
        with admin_client(f"https://localhost:{wg.http_port}") as api:
            user = api.create_user(sdk.CreateUserRequest(username=f"ticket-{uuid4()}"))
            target = create_target(api, port)
            # Unlimited uses: the fresh request below re-spends the same
            # ticket to force the correlator to re-admit under the same key.
            ticket = api.create_ticket(sdk.CreateTicketRequest(
                username=user.username, target_name=target.name,
            ))

        headers = {"Authorization": f"Bearer ticket-{ticket.secret}"}
        async with aiohttp.ClientSession(headers=headers) as session:
            url = f"https://localhost:{wg.kubernetes_port}"
            async with session.ws_connect(
                f"{url}/socket", ssl=False, protocols=["v4.channel.k8s.io"],
            ) as ws:
                await ws.send_str("before aging out")
                assert (await ws.receive(timeout=5)).data == "before aging out"

                # Outlive session_max_age while the socket stays open.
                await asyncio.sleep(1.5)

                # A fresh request under the same ticket makes the correlator
                # notice its cached entry is stale and replace it, dropping
                # its own reference to the original session's handle. Without
                # the fix, that would be the *last* reference, tearing the
                # original session (and its access watcher) down right here
                # -- even though the websocket above is still open and in use.
                async with session.get(f"{url}/api", ssl=False) as response:
                    assert response.status == 200

                # The still-open websocket, from the now-replaced session,
                # must still work.
                await ws.send_str("after aging out")
                assert (await ws.receive(timeout=5)).data == "after aging out"

                # Revoking the ticket now must still reach it: that only
                # happens if the original session's access watcher is still
                # alive, which only holds if the websocket kept its handle
                # alive itself once the correlator's own reference was gone.
                api.delete_ticket(ticket.ticket.id)
                closed = await ws.receive(timeout=15)
                assert closed.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSING,
                    aiohttp.WSMsgType.ERROR,
                ), closed
    finally:
        await runner.cleanup()
