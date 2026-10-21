"""TrustVault: a dependency-free WSGI document-sharing service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import uuid
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import unquote
from wsgiref.simple_server import make_server

ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("trustvault")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".docx"}
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}\.[^@\s]{2,}$")


def connect(db_path: str) -> sqlite3.Connection:
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 10000")
    return db


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_hex, digest_hex = encoded.split(":", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310_000)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


DUMMY_PASSWORD_HASH = password_hash("not-a-real-password")


def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    db = connect(db_path)
    try:
        db.executescript((ROOT / "schema.sql").read_text(encoding="utf-8"))
    finally:
        db.close()


def append_audit(db: sqlite3.Connection, key: bytes, actor_id: str | None,
                 action: str, document_id: str | None = None,
                 subject_id: str | None = None, details: dict | None = None) -> None:
    previous = db.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = previous["entry_hash"] if previous else "0" * 64
    at = int(time.time())
    payload = {
        "at": at, "actor_id": actor_id, "action": action, "document_id": document_id,
        "subject_id": subject_id, "details": details or {}, "previous_hash": prev_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    entry_hash = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
    db.execute(
        "INSERT INTO audit(at,actor_id,action,document_id,subject_id,details,previous_hash,entry_hash) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (at, actor_id, action, document_id, subject_id,
         json.dumps(details or {}, sort_keys=True), prev_hash, entry_hash),
    )


def audit_is_valid(db: sqlite3.Connection, key: bytes) -> bool:
    previous = "0" * 64
    for row in db.execute("SELECT * FROM audit ORDER BY id"):
        try:
            payload = {
                "at": row["at"], "actor_id": row["actor_id"], "action": row["action"],
                "document_id": row["document_id"], "subject_id": row["subject_id"],
                "details": json.loads(row["details"]), "previous_hash": row["previous_hash"],
            }
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            expected = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        except (TypeError, ValueError):
            return False
        if row["previous_hash"] != previous or not hmac.compare_digest(expected, row["entry_hash"]):
            return False
        previous = row["entry_hash"]
    return True


def seed_users(db_path: str) -> None:
    init_db(db_path)
    demo_users = (
        ("admin@trustvault.test", "Avery Admin", "admin", "AdminDemo!42"),
        ("owner@trustvault.test", "Olivia Owner", "owner", "OwnerDemo!42"),
        ("viewer@trustvault.test", "Victor Viewer", "viewer", "ViewerDemo!42"),
    )
    db = connect(db_path)
    try:
        for email, name, role, password in demo_users:
            db.execute(
                "INSERT OR IGNORE INTO users(id,email,name,role,password_hash) VALUES(?,?,?,?,?)",
                (str(uuid.uuid4()), email, name, role, password_hash(password)),
            )
        db.commit()
    finally:
        db.close()


class TrustVault:
    def __init__(self, db_path: str | None = None, storage_path: str | None = None,
                 secret: str | bytes | None = None, secure_cookie: bool = False):
        self.db_path = db_path or os.environ.get("TRUSTVAULT_DB", str(ROOT / "data" / "trustvault.sqlite3"))
        self.storage_path = Path(storage_path or os.environ.get("TRUSTVAULT_STORAGE", str(ROOT / "private_files")))
        configured_secret = secret or os.environ.get("TRUSTVAULT_SECRET")
        if not configured_secret:
            raise RuntimeError("Set TRUSTVAULT_SECRET to a long random value before starting TrustVault.")
        self.key = configured_secret.encode() if isinstance(configured_secret, str) else configured_secret
        if len(self.key) < 32:
            raise RuntimeError("TRUSTVAULT_SECRET must be at least 32 bytes.")
        self.secure_cookie = secure_cookie or os.environ.get("TRUSTVAULT_COOKIE_SECURE") == "1"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        init_db(self.db_path)

    def __call__(self, environ, start_response):
        method, path = environ.get("REQUEST_METHOD", "GET"), unquote(environ.get("PATH_INFO", "/"))
        try:
            status, body, headers = self.dispatch(environ, method, path)
        except Exception:
            LOGGER.exception("Unhandled TrustVault request error")
            status, body, headers = self.response(500, {"error": "Internal server error"})
        headers += [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
            ("Cache-Control", "no-store"),
        ]
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [body]

    @staticmethod
    def response(status: int, value, content_type: str = "application/json; charset=utf-8", extra=None):
        body = value if isinstance(value, bytes) else (
            value.encode() if isinstance(value, str) else json.dumps(value).encode()
        )
        return status, body, [("Content-Type", content_type), ("Content-Length", str(len(body)))] + (extra or [])

    def read_json(self, environ) -> dict:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValueError("Invalid content length")
        if length < 0:
            raise ValueError("Invalid content length")
        if length > MAX_UPLOAD_BYTES * 2 + 1_000_000:
            raise OverflowError("Request is too large")
        raw = environ["wsgi.input"].read(length)
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object")
        return value

    @staticmethod
    def response_error(status, message):
        return TrustVault.response(status, {"error": message})

    def session_user(self, environ, db):
        cookie = SimpleCookie()
        cookie.load(environ.get("HTTP_COOKIE", ""))
        morsel = cookie.get("tv_session")
        if morsel is None:
            return None
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        row = db.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>? AND u.active=1",
            (token_hash, int(time.time())),
        ).fetchone()
        return (row, token_hash) if row else None

    def dispatch(self, environ, method, path):
        if path == "/" and method == "GET":
            return self.response(200, (ROOT / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if path in ("/app.js", "/styles.css") and method == "GET":
            file = ROOT / "static" / path.rsplit("/", 1)[-1]
            return self.response(200, file.read_bytes(), mimetypes.guess_type(str(file))[0] + "; charset=utf-8")
        db = connect(self.db_path)
        try:
            db.execute("BEGIN IMMEDIATE")
            if path == "/api/login" and method == "POST":
                return self.login(environ, db)
            session = self.session_user(environ, db)
            if path == "/api/logout" and method == "POST":
                if not session:
                    return self.response(204, b"")
                user, token_hash = session
                if not self.csrf_ok(environ, db, token_hash):
                    append_audit(db, self.key, user["id"], "csrf_denied", details={"path": path})
                    return self.response_error(403, "Invalid CSRF token")
                db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                append_audit(db, self.key, user["id"], "logout")
                return self.response(204, b"", extra=[("Set-Cookie", self.cookie("", 0))])
            if not session:
                return self.response_error(401, "Authentication required")
            user, token_hash = session
            if method in ("POST", "PATCH", "DELETE") and not self.csrf_ok(environ, db, token_hash):
                append_audit(db, self.key, user["id"], "csrf_denied", details={"path": path})
                return self.response_error(403, "Invalid CSRF token")
            if path == "/api/me" and method == "GET":
                session_row = db.execute("SELECT csrf FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
                return self.response(200, {"user": self.public_user(user), "csrf": session_row["csrf"]})
            if path == "/api/documents" and method == "GET":
                return self.list_documents(environ, db, user)
            if path == "/api/documents" and method == "POST":
                return self.upload(environ, db, user)
            if path == "/api/audit" and method == "GET":
                if user["role"] != "admin":
                    append_audit(db, self.key, user["id"], "audit_access_denied")
                    return self.response_error(403, "Administrator role required")
                rows = db.execute(
                    "SELECT a.*,u.email AS actor_email,s.email AS subject_email "
                    "FROM audit a LEFT JOIN users u ON u.id=a.actor_id "
                    "LEFT JOIN users s ON s.id=a.subject_id ORDER BY a.id DESC LIMIT 500"
                ).fetchall()
                return self.response(200, {
                    "entries": [dict(row) for row in rows],
                    "chain_valid": audit_is_valid(db, self.key),
                })
            if path == "/api/audit/verify" and method == "GET":
                if user["role"] != "admin":
                    append_audit(db, self.key, user["id"], "audit_verify_denied")
                    return self.response_error(403, "Administrator role required")
                return self.response(200, {"valid": audit_is_valid(db, self.key)})
            match = re.fullmatch(r"/api/documents/([0-9a-f-]{36})(?:/(download|grants))?", path)
            if match:
                doc_id, action = match.groups()
                if action == "download" and method == "GET":
                    return self.download(db, user, doc_id)
                if action == "grants" and method == "POST":
                    return self.grant(environ, db, user, doc_id)
                if action == "grants" and method == "DELETE":
                    return self.revoke(environ, db, user, doc_id)
                if action is None and method == "GET":
                    return self.get_document(db, user, doc_id)
                if action is None and method == "PATCH":
                    return self.update_document(environ, db, user, doc_id)
                if action is None and method == "DELETE":
                    return self.delete_document(db, user, doc_id)
            return self.response_error(404, "Not found")
        except OverflowError as error:
            return self.response_error(413, str(error))
        except (ValueError, UnicodeError, json.JSONDecodeError) as error:
            return self.response_error(400, str(error))
        except Exception:
            db.rollback()
            raise
        finally:
            try:
                db.commit()
            finally:
                db.close()

    @staticmethod
    def public_user(user):
        return {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]}

    def cookie(self, token, max_age):
        secure = "; Secure" if self.secure_cookie else ""
        return f"tv_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def csrf_ok(self, environ, db, token_hash):
        supplied = environ.get("HTTP_X_CSRF_TOKEN", "")
        row = db.execute("SELECT csrf FROM sessions WHERE token_hash=?", (token_hash,)).fetchone()
        return bool(row and supplied and hmac.compare_digest(supplied, row["csrf"]))

    def login(self, environ, db):
        data = self.read_json(environ)
        email, password = str(data.get("email", "")).strip().lower(), data.get("password", "")
        if len(email) > 254 or not isinstance(password, str) or len(password) > 1024:
            return self.response_error(400, "Invalid login input")
        remote_addr = environ.get("REMOTE_ADDR", "unknown")[:64]
        now = int(time.time())
        db.execute("DELETE FROM login_failures WHERE attempted_at<?", (now - 900,))
        failures = db.execute(
            "SELECT COUNT(*) AS n FROM login_failures WHERE remote_addr=? AND attempted_at>=?",
            (remote_addr, now - 900),
        ).fetchone()["n"]
        if failures >= 10:
            append_audit(db, self.key, None, "login_throttled", details={"remote_addr": remote_addr})
            return self.response_error(429, "Too many failed attempts. Try again in 15 minutes.")
        user = db.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
        valid_password = verify_password(password, user["password_hash"] if user else DUMMY_PASSWORD_HASH)
        if not user or not valid_password:
            db.execute("INSERT INTO login_failures(remote_addr,attempted_at) VALUES(?,?)", (remote_addr, now))
            append_audit(db, self.key, None, "login_denied", details={"email": email[:254], "remote_addr": remote_addr})
            return self.response_error(401, "Email or password is incorrect")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        db.execute("INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)",
                   (token_hash, user["id"], csrf, int(time.time()) + 8 * 60 * 60))
        append_audit(db, self.key, user["id"], "login")
        return self.response(200, {"user": self.public_user(user), "csrf": csrf},
                             extra=[("Set-Cookie", self.cookie(token, 8 * 60 * 60))])

    def has_access(self, db, user, doc_id, permission="read"):
        if user["role"] == "owner":
            row = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=? AND deleted_at IS NULL",
                             (doc_id, user["id"])).fetchone()
            if row:
                return row
        row = db.execute(
            "SELECT d.* FROM documents d JOIN grants g ON g.document_id=d.id "
            "WHERE d.id=? AND d.deleted_at IS NULL AND g.user_id=? "
            "AND (g.permission='edit' OR ?='read')",
            (doc_id, user["id"], permission),
        ).fetchone()
        return row

    def deny(self, db, user, action, doc_id):
        append_audit(db, self.key, user["id"], action, doc_id, details={"result": "denied"})
        return self.response_error(404, "Document not found")

    def document_json(self, db, row, user):
        owner = db.execute("SELECT name,email FROM users WHERE id=?", (row["owner_id"],)).fetchone()
        grant = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                           (row["id"], user["id"])).fetchone()
        return {
            "id": row["id"], "name": row["name"], "category": row["category"],
            "mime": row["mime"], "size": row["size"], "created_at": row["created_at"],
            "updated_at": row["updated_at"], "owner": dict(owner),
            "permission": "owner" if row["owner_id"] == user["id"] else grant["permission"],
            "grants": self.grants_json(db, row["id"]) if row["owner_id"] == user["id"] else [],
        }

    @staticmethod
    def grants_json(db, doc_id):
        return [dict(row) for row in db.execute(
            "SELECT u.email,u.name,g.permission,g.created_at FROM grants g "
            "JOIN users u ON u.id=g.user_id WHERE g.document_id=? ORDER BY u.email", (doc_id,)
        )]

    def list_documents(self, environ, db, user):
        terms = ["d.deleted_at IS NULL"]
        params = []
        if user["role"] == "owner":
            terms.append("(d.owner_id=? OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id=d.id AND g.user_id=?))")
            params.extend([user["id"], user["id"]])
        else:
            terms.append("EXISTS (SELECT 1 FROM grants g WHERE g.document_id=d.id AND g.user_id=?)")
            params.append(user["id"])
        query = environ.get("QUERY_STRING", "")
        from urllib.parse import parse_qs
        filters = parse_qs(query)
        for field in ("name", "category"):
            value = filters.get(field, [""])[0][:120]
            if value:
                terms.append(f"d.{field} LIKE ? ESCAPE '\\'")
                escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                params.append(f"%{escaped}%")
        owner_filter = filters.get("owner", [""])[0][:254]
        if owner_filter:
            terms.append("EXISTS (SELECT 1 FROM users u WHERE u.id=d.owner_id AND u.email LIKE ?)")
            params.append(f"%{owner_filter}%")
        after = filters.get("after", [""])[0]
        before = filters.get("before", [""])[0]
        for value, operator in ((after, ">="), (before, "<=")):
            if value:
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                    return self.response_error(400, "Dates must use YYYY-MM-DD format")
                import datetime
                try:
                    boundary = int(datetime.datetime.strptime(value, "%Y-%m-%d").timestamp())
                except ValueError:
                    return self.response_error(400, "Invalid date")
                terms.append(f"d.created_at {operator} ?")
                params.append(boundary if operator == ">=" else boundary + 86_399)
        rows = db.execute(
            "SELECT d.* FROM documents d WHERE " + " AND ".join(terms) + " ORDER BY d.created_at DESC LIMIT 500",
            params,
        ).fetchall()
        return self.response(200, {"documents": [self.document_json(db, row, user) for row in rows]})

    def upload(self, environ, db, user):
        if user["role"] != "owner":
            append_audit(db, self.key, user["id"], "upload_denied", details={"result": "denied"})
            return self.response_error(403, "Only document owners may upload")
        data = self.read_json(environ)
        name = data.get("name")
        category = data.get("category", "General")
        encoded = data.get("content_base64")
        if not isinstance(name, str) or not name.strip() or len(name) > 180 or name != Path(name).name or any(c in name for c in ("/", "\\", "\0")):
            return self.response_error(400, "Provide a safe filename up to 180 characters")
        if not isinstance(category, str) or not category.strip() or len(category) > 80:
            return self.response_error(400, "Category must be 1-80 characters")
        if not isinstance(encoded, str) or len(encoded) > (MAX_UPLOAD_BYTES * 4 // 3 + 8):
            return self.response_error(413, "File must be 10 MB or smaller")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            return self.response_error(400, "Invalid base64 file content")
        if not content or len(content) > MAX_UPLOAD_BYTES:
            return self.response_error(413 if content else 400, "File must be non-empty and 10 MB or smaller")
        extension = Path(name).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            return self.response_error(415, "File type is not allowed")
        try:
            mime = self.detect_mime(extension, content)
        except ValueError as error:
            return self.response_error(415, str(error))
        doc_id, blob_key, now = str(uuid.uuid4()), str(uuid.uuid4()), int(time.time())
        blob_path = self.storage_path / blob_key
        try:
            with blob_path.open("xb") as file:
                file.write(content)
            db.execute(
                "INSERT INTO documents(id,owner_id,name,category,mime,size,blob_key,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (doc_id, user["id"], name.strip(), category.strip(), mime, len(content), blob_key, now, now),
            )
            append_audit(db, self.key, user["id"], "upload", doc_id,
                         details={"name": name.strip(), "size": len(content), "category": category.strip()})
        except Exception:
            blob_path.unlink(missing_ok=True)
            raise
        row = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        return self.response(201, {"document": self.document_json(db, row, user)})

    @staticmethod
    def detect_mime(extension, content):
        signatures = {
            ".pdf": (b"%PDF-", "application/pdf"),
            ".png": (b"\x89PNG\r\n\x1a\n", "image/png"),
            ".jpg": (b"\xff\xd8\xff", "image/jpeg"),
        }
        if extension in signatures:
            signature, mime = signatures[extension]
            if not content.startswith(signature):
                raise ValueError("File content does not match its extension")
            return mime
        if extension == ".docx":
            import zipfile
            from io import BytesIO
            if not zipfile.is_zipfile(BytesIO(content)):
                raise ValueError("DOCX must be a valid Office ZIP package")
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Text file must contain valid UTF-8") from error
        if "\0" in text:
            raise ValueError("Text file contains binary data")
        return "text/csv" if extension == ".csv" else "text/plain"

    def get_document(self, db, user, doc_id):
        row = self.has_access(db, user, doc_id)
        if not row:
            return self.deny(db, user, "read_denied", doc_id)
        append_audit(db, self.key, user["id"], "view", doc_id)
        return self.response(200, {"document": self.document_json(db, row, user)})

    def download(self, db, user, doc_id):
        row = self.has_access(db, user, doc_id)
        if not row:
            return self.deny(db, user, "download_denied", doc_id)
        blob = self.storage_path / row["blob_key"]
        if not blob.is_file() or blob.parent.resolve() != self.storage_path.resolve():
            return self.response_error(404, "Document not found")
        content = blob.read_bytes()
        append_audit(db, self.key, user["id"], "download", doc_id,
                     details={"size": len(content)})
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", row["name"])[:180] or "document"
        return self.response(200, content, row["mime"],
                             [("Content-Disposition", f'attachment; filename="{safe_name}"')])

    def update_document(self, environ, db, user, doc_id):
        row = self.has_access(db, user, doc_id, "edit")
        if not row:
            return self.deny(db, user, "change_denied", doc_id)
        if row["owner_id"] != user["id"] and user["role"] != "owner":
            grant = db.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                               (doc_id, user["id"])).fetchone()
            if not grant or grant["permission"] != "edit":
                return self.deny(db, user, "change_denied", doc_id)
        data = self.read_json(environ)
        name, category = data.get("name", row["name"]), data.get("category", row["category"])
        if not isinstance(name, str) or not name.strip() or len(name) > 180 or name != Path(name).name or any(c in name for c in ("/", "\\", "\0")):
            return self.response_error(400, "Provide a safe filename up to 180 characters")
        if not isinstance(category, str) or not category.strip() or len(category) > 80:
            return self.response_error(400, "Category must be 1-80 characters")
        db.execute("UPDATE documents SET name=?,category=?,updated_at=? WHERE id=?",
                   (name.strip(), category.strip(), int(time.time()), doc_id))
        append_audit(db, self.key, user["id"], "change", doc_id, details={"name": name.strip(), "category": category.strip()})
        updated = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        return self.response(200, {"document": self.document_json(db, updated, user)})

    def delete_document(self, db, user, doc_id):
        row = self.has_access(db, user, doc_id)
        if not row or row["owner_id"] != user["id"]:
            return self.deny(db, user, "delete_denied", doc_id)
        now = int(time.time())
        db.execute("UPDATE documents SET deleted_at=?,updated_at=? WHERE id=?", (now, now, doc_id))
        db.execute("DELETE FROM grants WHERE document_id=?", (doc_id,))
        append_audit(db, self.key, user["id"], "delete", doc_id, details={"name": row["name"]})
        return self.response(204, b"")

    def grant(self, environ, db, user, doc_id):
        doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=? AND deleted_at IS NULL",
                         (doc_id, user["id"])).fetchone() if user["role"] == "owner" else None
        if not doc:
            return self.deny(db, user, "grant_denied", doc_id)
        data = self.read_json(environ)
        email = data.get("email", "")
        permission = data.get("permission", "read")
        if not isinstance(email, str) or not EMAIL_RE.fullmatch(email.strip()) or permission not in ("read", "edit"):
            return self.response_error(400, "Provide a valid email and read or edit permission")
        target = db.execute("SELECT * FROM users WHERE email=? AND active=1", (email.strip().lower(),)).fetchone()
        if not target or target["id"] == user["id"]:
            return self.response_error(400, "Choose an existing, different active user")
        db.execute(
            "INSERT INTO grants(document_id,user_id,permission,granted_by,created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,"
            "granted_by=excluded.granted_by,created_at=excluded.created_at",
            (doc_id, target["id"], permission, user["id"], int(time.time())),
        )
        append_audit(db, self.key, user["id"], "permission_granted", doc_id, target["id"],
                     {"email": target["email"], "permission": permission})
        return self.response(200, {"grants": self.grants_json(db, doc_id)})

    def revoke(self, environ, db, user, doc_id):
        doc = db.execute("SELECT * FROM documents WHERE id=? AND owner_id=? AND deleted_at IS NULL",
                         (doc_id, user["id"])).fetchone() if user["role"] == "owner" else None
        if not doc:
            return self.deny(db, user, "revoke_denied", doc_id)
        data = self.read_json(environ)
        email = data.get("email", "")
        if not isinstance(email, str):
            return self.response_error(400, "Provide the email to revoke")
        target = db.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
        if not target:
            return self.response_error(404, "Grant not found")
        changed = db.execute("DELETE FROM grants WHERE document_id=? AND user_id=?",
                             (doc_id, target["id"])).rowcount
        append_audit(db, self.key, user["id"], "permission_revoked", doc_id, target["id"],
                     {"email": target["email"], "grant_removed": bool(changed)})
        return self.response(200, {"grants": self.grants_json(db, doc_id)})


def application(environ, start_response):
    global _application
    if _application is None:
        _application = TrustVault()
    return _application(environ, start_response)


_application = None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the TrustVault development server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    secret = os.environ.get("TRUSTVAULT_SECRET")
    if not secret:
        raise SystemExit("Set TRUSTVAULT_SECRET (at least 32 random bytes) before startup.")
    seed_users(os.environ.get("TRUSTVAULT_DB", str(ROOT / "data" / "trustvault.sqlite3")))
    app = TrustVault(secure_cookie=args.host not in ("127.0.0.1", "localhost"))
    print(f"TrustVault listening on http://{args.host}:{args.port}")
    make_server(args.host, args.port, app).serve_forever()
