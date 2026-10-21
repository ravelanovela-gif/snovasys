# TrustVault API

All routes are same-origin. After login, the server sets an HttpOnly session cookie; unsafe requests (`POST`, `PATCH`, `DELETE`) must also send the session's `X-CSRF-Token` returned by login or `/api/me`. Document IDs are opaque UUIDs, not authorization credentials. JSON errors have the shape `{"error":"..."}`. Inaccessible and nonexistent documents both return 404.

## Roles

- **Admin:** may inspect and verify audit events. No implicit access to documents.
- **Owner:** may upload; access their own documents; edit metadata; soft-delete their documents; and grant/revoke a named account's read/edit permission.
- **Viewer:** may read and download only documents with a current explicit grant. An edit grant additionally permits metadata changes, but not deletion or permission management.

## Endpoints

| Method and path | Anonymous | Admin | Owner | Viewer | Purpose |
| --- | --- | --- | --- | --- | --- |
| `GET /` | Yes | Yes | Yes | Yes | Application shell. |
| `GET /app.js`, `GET /styles.css` | Yes | Yes | Yes | Yes | Static assets. |
| `POST /api/login` | Yes | Yes | Yes | Yes | Authenticate; returns user and CSRF token and sets session cookie. |
| `POST /api/logout` | No | Yes | Yes | Yes | Invalidate current session; requires CSRF. |
| `GET /api/me` | No | Yes | Yes | Yes | Current user and CSRF token. |
| `GET /api/documents` | No | Only explicitly granted documents | Owned and explicitly granted documents | Explicitly granted documents | Search/filter with `name`, `owner`, `category`, `after`, `before`; results are always authorization-filtered. |
| `POST /api/documents` | No | No | Yes | No | Upload JSON with `name`, `category`, and base64 `content_base64`; max 10 MiB. |
| `GET /api/documents/{id}` | No | Current grant only | Own document or current grant | Current grant only | Read authorized metadata; creates a view event. |
| `GET /api/documents/{id}/download` | No | Current grant only | Own document or current grant | Current grant only | Download; checks current grant immediately before storage read and records success/refusal. |
| `PATCH /api/documents/{id}` | No | Current edit grant only | Own document or current edit grant | Current edit grant only | Update `name` and/or `category`; changes are audited. |
| `DELETE /api/documents/{id}` | No | No | Own document only | No | Soft-delete; removes grants and records event. |
| `POST /api/documents/{id}/grants` | No | No | Owning user only | No | Grant an active named account `read` or `edit` access; regrant updates permission. |
| `DELETE /api/documents/{id}/grants` | No | No | Owning user only | No | Revoke named user's access immediately. JSON body: `{"email":"..."}`. |
| `GET /api/audit` | No | Yes | No | No | Latest 500 audit records, email identities, and full-chain validation result. |
| `GET /api/audit/verify` | No | Yes | No | No | Verify the complete local audit chain. |

Admin access to a document is possible only if an owner explicitly grants that admin a document permission. Listing and download do not accept a role override. Search result limit is 500; dates use `YYYY-MM-DD`. The service returns 400 for invalid input, 401 for missing authentication, 403 for failed CSRF or role-only features, 404 for inaccessible documents, 413 for oversized requests, and 415 for unsupported/mismatched upload content.

## Example: share and revoke

```http
POST /api/documents/UUID/grants
Cookie: tv_session=...
X-CSRF-Token: ...
Content-Type: application/json

{"email":"viewer@trustvault.test","permission":"read"}
```

```http
DELETE /api/documents/UUID/grants
Cookie: tv_session=...
X-CSRF-Token: ...
Content-Type: application/json

{"email":"viewer@trustvault.test"}
```

Revocation affects the next API request because every operation consults the current grants table. Already delivered copies are outside the server's control.
