import json
import secrets
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from api import create_app
from api.db import get_db, init_db


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True, "JWT_SECRET": secrets.token_hex(32),
                      "DATABASE": str(tmp_path / "test.sqlite3")})
    with app.app_context():
        init_db()
        for name in ("alice", "bob"):
            get_db().execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                             (name, generate_password_hash("test-only-password", method="scrypt")))
        get_db().commit()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def auth(client, username="alice"):
    response = client.post("/auth/login", json={"username": username, "password": "test-only-password"})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json["access_token"]}


def test_login_and_notes(client):
    headers = auth(client)
    response = client.post("/api/data", json={"text": "My note"}, headers=headers)
    assert response.status_code == 201
    assert client.get("/api/data", headers=headers).json == {"data": [response.json["data"]]}
    assert client.get("/api/data", headers=auth(client, "bob")).json == {"data": []}


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("header", [None, "Bearer invalid", "Basic abc", "Bearer"])
def test_protected_routes(client, method, header):
    headers = {} if header is None else {"Authorization": header}
    assert getattr(client, method)("/api/data", headers=headers).status_code == 401


@pytest.mark.parametrize("username,password", [
    ("alice", "wrong"), ("unknown", "test-only-password"),
    ("' OR 1=1 --", "test-only-password"),
])
def test_login_rejected(client, username, password):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json == {"error": "Authentication required"}


@pytest.mark.parametrize("body", [None, [], {}, {"username": 1, "password": []}])
def test_bad_login_body(client, body):
    assert client.post("/auth/login", data=json.dumps(body),
                       content_type="application/json").status_code == 400


@pytest.mark.parametrize("text", [None, [], 12, "", "   ", "x" * 1001])
def test_invalid_notes(client, text):
    assert client.post("/api/data", json={"text": text}, headers=auth(client)).status_code == 400


def test_xss_and_sql_payloads(client):
    headers = auth(client)
    payload = "<script>alert('x')</script>'); DROP TABLE users; --"
    response = client.post("/api/data", json={"text": payload}, headers=headers)
    assert response.status_code == 201
    assert "<script>" not in response.json["data"]["text"]
    assert "&lt;script&gt;" in response.json["data"]["text"]
    assert "&#x27;" in response.json["data"]["text"]
    assert client.get("/api/data", headers=headers).json["data"] == [response.json["data"]]
    auth(client)


@pytest.mark.parametrize("case", ["expired", "signature", "missing_exp", "audience", "issuer", "algorithm", "unknown_user", "future"])
def test_invalid_tokens(app, client, case):
    now = datetime.now(timezone.utc)
    claims = {"sub": "1", "iat": now, "nbf": now, "exp": now + timedelta(minutes=15),
              "iss": "secure-notes", "aud": "secure-notes-api"}
    key, algorithm = app.config["JWT_SECRET"], "HS256"
    if case == "expired":
        claims["exp"] = now - timedelta(seconds=1)
    elif case == "signature":
        key = secrets.token_hex(32)
    elif case == "missing_exp":
        del claims["exp"]
    elif case == "audience":
        claims["aud"] = "another-api"
    elif case == "issuer":
        claims["iss"] = "another-issuer"
    elif case == "algorithm":
        algorithm = "HS384"
    elif case == "unknown_user":
        claims["sub"] = "999"
    elif case == "future":
        claims["nbf"] = now + timedelta(minutes=5)
    token = jwt.encode(claims, key, algorithm=algorithm)
    assert client.get("/api/data", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_password_storage(app):
    with app.app_context():
        stored = get_db().execute("SELECT password_hash FROM users LIMIT 1").fetchone()[0]
        assert stored.startswith("scrypt:")
        assert check_password_hash(stored, "test-only-password")
        assert stored != "test-only-password"


def test_cli_user_creation(app, client):
    runner = app.test_cli_runner()
    assert runner.invoke(args=["init-db"]).exit_code == 0
    result = runner.invoke(args=["create-user", "--username", "carol"],
                           input="a-long-test-password\na-long-test-password\n")
    assert result.exit_code == 0
    assert client.post("/auth/login", json={"username": "carol", "password": "a-long-test-password"}).status_code == 200
    assert runner.invoke(args=["create-user", "--username", "carol"],
                         input="a-long-test-password\na-long-test-password\n").exit_code != 0


def test_headers_and_errors(client):
    response = client.get("/api/data")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert client.get("/missing").json == {"error": "Not Found"}
    assert client.post("/auth/login", data="{", content_type="application/json").status_code == 400
    assert client.post("/auth/login", data="x").status_code == 415
    assert client.post("/auth/login", data="x" * 17000, content_type="application/json").status_code == 413


def test_short_secret_rejected():
    with pytest.raises(ValueError, match="JWT_SECRET"):
        create_app({"JWT_SECRET": "short"})
