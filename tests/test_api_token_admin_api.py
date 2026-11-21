from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import requests

from .api_client import sdk


@pytest.fixture
def token_owner(shared_wg, admin_client):
    """A user holding the built-in admin role, logged in with a web session."""
    user = admin_client.create_user(
        sdk.CreateUserRequest(username=f"token-admin-api-{uuid4()}")
    )
    admin_client.create_password_credential(
        user.id, sdk.NewPasswordCredential(password="123")
    )
    role = next(r for r in admin_client.get_admin_roles() if r.name == "warpgate:admin")
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
    yield url, session
    session.close()
    admin_client.delete_user(user.id)


def create_token(owner, **extra):
    url, session = owner
    response = session.post(
        f"{url}/@warpgate/api/profile/api-tokens",
        json={
            "label": "admin-api-test",
            "expiry": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            **extra,
        },
        timeout=10,
    )
    assert response.status_code == 201, response.text
    return response.json()


def get(url, path, secret):
    return requests.get(
        f"{url}{path}",
        headers={"X-Warpgate-Token": secret},
        verify=False,
        timeout=10,
    )


def test_default_token_can_use_admin_api(token_owner):
    url, _ = token_owner
    created = create_token(token_owner)
    assert created["token"]["admin_api"] is True
    assert get(url, "/@warpgate/admin/api/sessions", created["secret"]).status_code == 200


def test_restricted_token_cannot_use_admin_api(token_owner):
    url, _ = token_owner
    created = create_token(token_owner, admin_api=False)
    assert created["token"]["admin_api"] is False
    secret = created["secret"]

    assert get(url, "/@warpgate/admin/api/sessions", secret).status_code in (401, 403)
    # User (gateway) endpoints keep working
    assert get(url, "/@warpgate/api/profile/api-tokens", secret).status_code == 200
    info = get(url, "/@warpgate/api/info", secret)
    assert info.status_code == 200
    assert not any(info.json()["admin_permissions"].values())

