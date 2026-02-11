import jwt
from datetime import datetime, timezone
import pytest
from server import create_app

@pytest.fixture
def app():
    return create_app(testing=True)

@pytest.fixture
def client(app):
    return app.test_client()

def test_jwks_only_active_key(app, client):
    resp = client.get("/jwks")
    assert resp.status_code == 200
    data = resp.get_json()
    keys = data["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == app.config["ACTIVE_KEY"]["kid"]

def test_auth_valid_token(app, client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    active_key = app.config["ACTIVE_KEY"]
    decoded = jwt.decode(
        token,
        active_key["public"],
        algorithms=["RS256"],
        audience="jwks-demo-client",
        issuer="jwks-demo"
    )

    assert decoded["sub"] == "fake-user-id"
    assert decoded["exp"] > datetime.now(timezone.utc).timestamp()

def test_auth_expired_token(app, client):
    resp = client.post("/auth?expired=1")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    expired_key = app.config["EXPIRED_KEY"]
    decoded = jwt.decode(
        token,
        expired_key["public"],
        algorithms=["RS256"],
        options={"verify_exp": False},
        audience="jwks-demo-client",
        issuer="jwks-demo"
    )

    assert decoded["exp"] < datetime.now(timezone.utc).timestamp()

def test_method_not_allowed(client):
    assert client.post("/jwks").status_code == 405
    assert client.get("/auth").status_code == 405