from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import requests

from .api_client import sdk


@pytest.fixture
def token_owner(shared_wg, admin_client):
    user = admin_client.create_user(
        sdk.CreateUserRequest(username=f"token-scopes-{uuid4()}")
    )
    admin_client.create_password_credential(
        user.id, sdk.NewPasswordCredential(password="123")
    )
    permissions = {
        name: False
        for name in (
            "targets_create",
            "targets_edit",
            "targets_delete",
            "users_create",
            "users_edit",
            "users_delete",
            "access_roles_create",
            "access_roles_edit",
            "access_roles_delete",
            "access_roles_assign",
            "sessions_view",
            "sessions_terminate",
            "approve_sessions",
            "recordings_view",
            "tickets_create",
            "tickets_delete",
            "config_edit",
            "admin_roles_manage",
            "ticket_requests_manage",
        )
    }
    permissions["sessions_view"] = True
    role = admin_client.create_admin_role(
        sdk.AdminRoleDataRequest(
            name=f"token-scopes-{uuid4()}",
            **permissions,
        )
    )
    admin_client.add_user_admin_role(user.id, role.id)
    url = f"https://localhost:{shared_wg.http_port}"
    session = requests.Session()
    session.verify = False
    response = session.post(
        f"{url}/@warpgate/api/auth/login",
        json={"username": user.username, "password": "123"},
        timeout=10,
    )
    response.raise_for_status()
    yield url, session, user
    session.close()
    admin_client.delete_user(user.id)
    admin_client.delete_admin_role(role.id)


def token_body(**scopes):
    return {
        "label": "scopes-test",
        "expiry": (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat(),
        **scopes,
    }


def create_token(owner, **scopes):
    url, session, _ = owner
    response = session.post(
        f"{url}/@warpgate/api/profile/api-tokens",
        json=token_body(**scopes),
        timeout=10,
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize(
    "user_api,admin_api", [(True, False), (False, True), (True, True)]
)
def test_api_access_is_limited_by_selection(token_owner, user_api, admin_api):
    url, session, _ = token_owner
    created = create_token(token_owner, user_api=user_api, admin_api=admin_api)
    assert created["token"]["user_api"] is user_api
    assert created["token"]["admin_api"] is admin_api
    headers = {"X-Warpgate-Token": created["secret"]}
    for prefix in ("/@warpgate", "/_warpgate"):
        for path, allowed in (
            ("/api/profile/api-tokens", user_api),
            ("/admin/api/sessions", admin_api),
        ):
            response = requests.get(
                f"{url}{prefix}{path}",
                headers=headers,
                verify=False,
                timeout=10,
            )
            assert response.status_code == (
                200 if allowed else 403
            ), response.text

    # Cookie authentication still follows the user's normal permissions.
    assert (
        session.get(
            f"{url}/@warpgate/admin/api/sessions", timeout=10
        ).status_code
        == 200
    )


def test_legacy_creation_defaults_and_listing(token_owner):
    url, session, _ = token_owner
    created = create_token(token_owner)
    assert created["token"]["user_api"] is True
    assert created["token"]["admin_api"] is True
    response = session.get(
        f"{url}/@warpgate/api/profile/api-tokens", timeout=10
    )
    response.raise_for_status()
    assert created["token"] in response.json()


def test_at_least_one_api_is_required(token_owner):
    url, session, _ = token_owner
    response = session.post(
        f"{url}/@warpgate/api/profile/api-tokens",
        json=token_body(user_api=False, admin_api=False),
        timeout=10,
    )
    assert response.status_code == 400
    assert "at least one API" in response.text
    assert (
        session.get(
            f"{url}/@warpgate/api/profile/api-tokens", timeout=10
        ).json()
        == []
    )


def test_user_only_token_cannot_mint_admin_access(token_owner):
    url, _, _ = token_owner
    parent = create_token(token_owner, user_api=True, admin_api=False)
    headers = {"X-Warpgate-Token": parent["secret"]}
    for scopes in (
        {},
        {"user_api": True, "admin_api": True},
        {"user_api": False, "admin_api": True},
    ):
        response = requests.post(
            f"{url}/@warpgate/api/profile/api-tokens",
            json=token_body(**scopes),
            headers=headers,
            verify=False,
            timeout=10,
        )
        assert response.status_code == 403
    response = requests.post(
        f"{url}/@warpgate/api/profile/api-tokens",
        json=token_body(user_api=True, admin_api=False),
        headers=headers,
        verify=False,
        timeout=10,
    )
    assert response.status_code == 201
    child = response.json()
    assert child["token"]["admin_api"] is False
    denied = requests.get(
        f"{url}/@warpgate/admin/api/sessions",
        headers={"X-Warpgate-Token": child["secret"]},
        verify=False,
        timeout=10,
    )
    assert denied.status_code == 403


def test_admin_api_selection_does_not_grant_admin_permissions(token_owner):
    url, _, _ = token_owner
    created = create_token(token_owner, user_api=False, admin_api=True)
    response = requests.get(
        f"{url}/@warpgate/admin/api/ticket-requests",
        headers={"X-Warpgate-Token": created["secret"]},
        verify=False,
        timeout=10,
    )
    # The owner has sessions_view, but not ticket_requests_manage.
    assert response.status_code == 403


@pytest.mark.parametrize(
    "user_api,admin_api", [(True, False), (False, True), (True, True)]
)
def test_target_access_requires_user_api(
    token_owner,
    admin_client,
    echo_server_port,
    shared_wg,
    user_api,
    admin_api,
):
    url, _, user = token_owner
    role = admin_client.create_role(
        sdk.RoleDataRequest(name=f"scope-target-{uuid4()}")
    )
    admin_client.add_user_role(user.id, role.id)
    targets = []
    for kind in ("Http", "Kubernetes"):
        options = (
            sdk.TargetOptionsTargetHTTPOptions(
                kind=kind,
                headers={},
                url=f"http://localhost:{echo_server_port}",
                tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
            )
            if kind == "Http"
            else sdk.TargetOptionsTargetKubernetesOptions(
                kind=kind,
                cluster_url=f"http://localhost:{echo_server_port}",
                tls=sdk.Tls(mode=sdk.TlsMode.DISABLED, verify=False),
                auth=sdk.KubernetesTargetAuth(
                    sdk.KubernetesTargetAuthKubernetesTargetTokenAuth(
                        kind="Token",
                        token="upstream-token",
                    ),
                ),
            )
        )
        target = admin_client.create_target(
            sdk.TargetDataRequest(
                name=f"scope-target-{uuid4()}",
                require_approval=False,
                ticket_requests_disabled=False,
                ticket_require_approval=False,
                options=sdk.TargetOptions(options),
            )
        )
        admin_client.add_target_role(target.id, role.id)
        targets.append(target)
    try:
        created = create_token(
            token_owner, user_api=user_api, admin_api=admin_api
        )
        http_response = requests.get(
            f"{url}/scope-test?warpgate-target={targets[0].name}",
            headers={"X-Warpgate-Token": created["secret"]},
            verify=False,
            timeout=10,
        )
        assert http_response.status_code == (
            200 if user_api else 403
        ), http_response.text
        kube_response = requests.get(
            f"https://localhost:{shared_wg.kubernetes_port}/{targets[1].name}/version",
            headers={"Authorization": f"Bearer {created['secret']}"},
            verify=False,
            timeout=10,
        )
        assert kube_response.status_code == (
            200 if user_api else 403
        ), kube_response.text
    finally:
        for target in targets:
            admin_client.delete_target(target.id)
        admin_client.delete_role(role.id)
