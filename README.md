# TrustVault

TrustVault is a small, runnable document-sharing service built with Python's standard library, SQLite, and a plain JavaScript interface. Files live outside the web root. The server checks the caller's current document grant on every read, download, edit, and delete request; the UI is not an authorization boundary.

## Start here

Requirements: Python 3.11 or newer. TrustVault's application and tests use only the standard library. Waitress is the optional production WSGI server.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
$env:TRUSTVAULT_SECRET = py -c "import secrets; print(secrets.token_hex(32))"
py scripts\setup_db.py --demo-users
waitress-serve --listen=127.0.0.1:8000 app:application
```

Open `http://127.0.0.1:8000`. This local-only command uses demo accounts and plain HTTP. Do not expose it publicly.

For a **public deployment**, do not use `--demo-users`. Set `TRUSTVAULT_SECRET` to a persistent random secret in the host's secret manager and `TRUSTVAULT_COOKIE_SECURE=1`; run `py scripts\setup_db.py`, then provision each real account with `py scripts\create_user.py --email person@company.com --name "Person Name" --role admin` (choose `owner` or `viewer` as needed). Install/start Waitress bound only to a trusted TLS-terminating reverse proxy, and provide HTTPS to users. Store the database and private-file directory on persistent protected storage, and never use the demo passwords or development server on the public internet.

The built-in server is for local evaluation only:

```powershell
$env:TRUSTVAULT_SECRET = py -c "import secrets; print(secrets.token_hex(32))"
py app.py
```

The schema setup is idempotent. `scripts\create_user.py` prompts for a unique account password rather than storing it in shell history. For the design summary and current unfinished work, see [WRITEUP.md](WRITEUP.md).

Configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRUSTVAULT_SECRET` | required | Random secret of at least 32 bytes; signs audit records. Keep it outside the database and back it up securely. |
| `TRUSTVAULT_DB` | `data/trustvault.sqlite3` | SQLite database path. |
| `TRUSTVAULT_STORAGE` | `private_files/` | Private document directory; never configure this as a web-served directory. |
| `TRUSTVAULT_COOKIE_SECURE` | disabled | Set to `1` behind HTTPS to mark the session cookie Secure. |

### Demo accounts

These known passwords exist **only for a local demonstration**. Replace seeded accounts and passwords before deployment, and never expose a demo-seeded instance publicly.

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@trustvault.test` | `AdminDemo!42` |
| Document owner | `owner@trustvault.test` | `OwnerDemo!42` |
| Viewer | `viewer@trustvault.test` | `ViewerDemo!42` |

The owner can grant a named account read or edit access from a document's share action. “Edit” allows metadata changes and download, not replacing the uploaded binary or administering grants. An ungranted viewer and an administrator cannot see the document or retrieve its file.

## Tests

```powershell
py -m unittest discover -s tests -v
```

The tests make direct WSGI requests and cover unauthorized metadata reads, downloads, edits and deletion; owner isolation; role boundaries; grant and immediate revocation; malformed and mismatched file uploads; CSRF; server-side search; and audit evidence for denied attempts. They passed locally on Python 3.15.0 on 2026-10-21. Python 3.11+ is supported.

## Design and security boundaries

- **Roles:** Admins can inspect the audit stream and verify its chain, but receive no implicit document access. Owners create documents, edit metadata, delete their own documents, and grant/revoke per-document access. Viewers can read/download documents with an explicit grant. A named user with an `edit` grant can also change metadata. No folder inheritance or group membership exists.
- **Authorization:** Every document identifier is resolved server-side against the authenticated user, live document state, and current grant. The server returns 404 for inaccessible IDs to avoid confirming document existence. There are no bearer download links or public file URLs. Revocation removes the database grant; subsequent requests, including downloads, fail immediately. A copy already downloaded cannot be remotely recalled.
- **Authentication:** Passwords are PBKDF2-HMAC-SHA256 hashes with random salts; session IDs are random, stored only as hashes, expire after eight hours, and use HttpOnly/SameSite=Strict cookies. Unsafe requests require a session-bound CSRF token. Failed logins are rate-limited per remote address. Production must use HTTPS and Secure cookies.
- **Storage and upload:** Random opaque blob names, a private directory, 10 MiB limit, allowlisted extensions, content signature/UTF-8 validation, and server-generated paths. PDF, PNG, JPEG, UTF-8 text/CSV, and structurally ZIP-valid DOCX are accepted. A ZIP-valid DOCX is not exhaustively inspected for malicious embedded content.
- **Audit:** Security-relevant events, including refused document access and login failures, are appended to SQLite and HMAC-SHA256-linked. Database triggers reject ordinary updates/deletes; the admin screen verifies the chain. The HMAC key is held separately from the database. This is tamper-evident, not a true external immutable ledger: a database operator can truncate the tail, and a host operator who obtains the key and database can rewrite the chain. Production evidence needs remote append-only/WORM export and periodic externally signed checkpoints.
- **Deletion:** User deletion is a soft delete, removes all grants, and makes all application routes return no document. The encrypted-at-rest and retention lifecycle of the retained blob is intentionally not implemented; operators must apply a retention and secure-erasure policy.
- **Intentionally not built:** External sharing links, SSO/MFA, password recovery, versioning, malware scanning, content preview, encryption-at-rest/key management, legal holds, and automatic account provisioning. Do not treat this compact challenge implementation as a certified production records system.

## Database and API

`schema.sql` is the idempotent SQLite setup script. The application runs it on startup. Endpoint roles, request/response behavior, and error codes are in [API.md](API.md). Known attack paths and accepted risks are in [THREATS.md](THREATS.md). The implementation and review checkpoints are in [PROMPTS.md](PROMPTS.md).

## Deployment status and hand-in gaps

This workspace contains source and local run instructions, but has no configured public Git remote, hosting account, or video capture/upload facility. Therefore there is **no public repository URL, live deployment, or recorded demo video** from this environment. Do not interpret the sample credentials or local URL as deployed credentials/URL. `DEMO.md` contains a five-minute walkthrough script for recording once the app is running. The automated suite passed locally; run it again after any changes and before publishing.
