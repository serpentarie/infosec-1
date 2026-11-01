import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from html import escape
from pathlib import Path

import click
import jwt
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db, init_db

AUTH_SCHEME = "Bearer"


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        JWT_SECRET=os.environ.get("JWT_SECRET", ""),
        DATABASE=str(Path(app.instance_path) / "notes.sqlite3"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)
    secret = app.config["JWT_SECRET"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise ValueError("JWT_SECRET must contain at least 32 bytes; use secrets.token_hex(32)")
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32), method="scrypt")

    @app.teardown_appcontext
    def close_db(_error):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    def unauthorized():
        response = jsonify(error="Authentication required")
        response.status_code = 401
        response.headers["WWW-Authenticate"] = AUTH_SCHEME
        return response

    def authenticated(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            parts = request.headers.get("Authorization", "").split()
            if len(parts) != 2 or parts[0].lower() != AUTH_SCHEME.lower():
                return unauthorized()
            try:
                claims = jwt.decode(
                    parts[1], app.config["JWT_SECRET"], algorithms=["HS256"],
                    issuer="secure-notes", audience="secure-notes-api",
                    options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud"]},
                )
                subject = claims["sub"]
                if not isinstance(subject, str) or not subject.isascii() or not subject.isdecimal():
                    return unauthorized()
                user = get_db().execute("SELECT id FROM users WHERE id = ?", (subject,)).fetchone()
                if user is None:
                    return unauthorized()
                g.user_id = user["id"]
            except jwt.InvalidTokenError:
                return unauthorized()
            return view(*args, **kwargs)
        return wrapped

    def json_object():
        body = request.get_json()
        return body if isinstance(body, dict) else {}

    @app.post("/auth/login")
    def login():
        body = json_object()
        username, password = body.get("username"), body.get("password")
        if (not isinstance(username, str) or not 1 <= len(username) <= 64
                or not isinstance(password, str) or not 1 <= len(password) <= 128):
            return jsonify(error="username (1–64) and password (1–128) must be strings"), 400
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        valid = check_password_hash(user["password_hash"] if user else dummy_hash, password)
        if user is None or not valid:
            return unauthorized()
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": str(user["id"]), "iat": now, "nbf": now,
             "exp": now + timedelta(minutes=15), "iss": "secure-notes", "aud": "secure-notes-api"},
            app.config["JWT_SECRET"], algorithm="HS256",
        )
        return jsonify({"access_token": token, "token_type": AUTH_SCHEME, "expires_in": 900})

    def serialize(row):
        return {"id": row["id"], "text": escape(row["text"], quote=True)}

    @app.get("/api/data")
    @authenticated
    def list_notes():
        rows = get_db().execute(
            "SELECT id, text FROM notes WHERE user_id = ? ORDER BY id", (g.user_id,)
        ).fetchall()
        return jsonify(data=[serialize(row) for row in rows])

    @app.post("/api/data")
    @authenticated
    def create_note():
        text = json_object().get("text")
        if not isinstance(text, str) or not 1 <= len(text.strip()) <= 1000:
            return jsonify(error="text must contain 1–1000 non-blank characters"), 400
        text = text.strip()
        db = get_db()
        cursor = db.execute("INSERT INTO notes (user_id, text) VALUES (?, ?)", (g.user_id, text))
        db.commit()
        return jsonify(data=serialize({"id": cursor.lastrowid, "text": text})), 201

    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables without deleting existing data."""
        init_db()
        click.echo("Database initialized")

    @app.cli.command("create-user")
    @click.option("--username", required=True)
    @click.password_option(confirmation_prompt=True)
    def create_user(username, password):
        """Create a local account; password is entered interactively."""
        if not 1 <= len(username) <= 64 or not 12 <= len(password) <= 128:
            raise click.ClickException("Username: 1–64 characters; password: 12–128 characters")
        db = get_db()
        if db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            raise click.ClickException("Username already exists")
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   (username, generate_password_hash(password, method="scrypt")))
        db.commit()
        click.echo("User created")

    return app
