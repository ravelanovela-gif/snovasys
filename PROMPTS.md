# AI build and review notes

## Context reused throughout

The working brief was the TrustVault challenge in the project request: implement per-document named read/edit grants, role boundaries, immediate revocation, private file storage, tamper-evident and denial-aware auditing, server-side search, upload validation, direct-route authorization tests, threat disclosure, and operating documentation. This was a single AI-assisted implementation session on 2026-10-21, not a fabricated week of separate prompts. The entries below are dated checkpoints from that session. The workspace was not a Git repository and had no configured remote when work began; commit links cannot truthfully be supplied yet. Replace each “Commit: not yet available” with the actual commit URL after committing these reviewed changes.

## Entries

### 2026-10-21 — Build a small secure end-to-end platform

- **Asked:** “Build the complete TrustVault document-sharing challenge in this empty workspace, choosing a stack that can be run and defended.”
- **Produced:** A dependency-light Python WSGI service, SQLite schema, private blob store, JSON API, browser UI, role model, starter tests, and setup.
- **What was wrong:** The first draft treated service construction and persistence as straightforward; checking request lifecycle exposed that writes needed an explicit commit and that an admin with no document-specific grant must not inherit access through the listing query.
- **What I did instead:** Commit each successful request transaction, roll back on unexpected exceptions, and filter admin listing to explicit grants. The unauthenticated admin IDOR case is now in the HTTP-level test suite.
- **Commit:** Not yet available; no Git repository/remote was configured in the workspace.

### 2026-10-21 — Challenge the authorization model with direct requests

- **Asked:** “Try to bypass the UI: test every direct document route as an ungranted viewer and admin, including listing, download, edit, and delete.”
- **Produced:** An ownership/current-grant check on object operations, 404 concealment for forbidden document IDs, and role-specific listing filters.
- **What was wrong:** A first test fixture accidentally logged in as the same owner twice, so it did not prove cross-owner isolation. Reviewing the fixture caught the false assurance before calling it a passing security test.
- **What I did instead:** Added a second seeded owner in the isolated test database and exercised cross-owner deletion plus ungranted viewer/admin routes directly through WSGI.
- **Commit:** Not yet available; no Git repository/remote was configured in the workspace.

### 2026-10-21 — Review immediate revocation and stale access

- **Asked:** “Make grant removal take effect now; do not issue links or cache permissions that remain valid.”
- **Produced:** Database-backed per-document grants and protected download routes.
- **What was wrong:** A UI-only revoke or previously issued bearer URL would still be usable after removal, so a successful UI response alone would not demonstrate the required guarantee.
- **What I did instead:** No bearer download links are issued; download performs a fresh grant lookup. Added a test that downloads with a grant, revokes, and verifies both metadata and download routes return 404 on the next request. Documentation explicitly says already-delivered copies cannot be recalled.
- **Commit:** Not yet available; no Git repository/remote was configured in the workspace.

### 2026-10-21 — Test the audit trail as evidence

- **Asked:** “Record both successful security-sensitive actions and refused access; make edits to historical entries detectable and expose a verification view.”
- **Produced:** An HMAC-SHA256 previous-entry chain, append-only SQLite triggers, denied access events, and an admin verification screen.
- **What was wrong:** An HMAC chain is not the same thing as an independently immutable log. An operator able to truncate the database can remove a valid suffix without the remaining prefix failing verification; a database/key compromise enables rewriting.
- **What I did instead:** Kept the key outside the DB, block ordinary record updates/deletes with triggers, test that denied download attempts appear in the admin feed, and disclose tail-truncation/key-compromise limitations with a production requirement for remote WORM export and external checkpoints.
- **Commit:** Not yet available; no Git repository/remote was configured in the workspace.

### 2026-10-21 — Inspect uploads, cookies, and deployment claims

- **Asked:** “Review file uploads, session behavior, browser security, and the hand-in for unsafe defaults; document anything not actually delivered.”
- **Produced:** File size/type/signature checks, hashed session IDs, CSRF tokens, cookie flags, generic login errors, throttling, and run/deployment instructions.
- **What was wrong:** The initial layout referenced externally hosted fonts while the restrictive CSP disallowed them; the app also could not honestly claim a public URL, video, or test pass in a workspace without configured hosting or Python.
- **What I did instead:** Removed the external font request, use local system fonts, documented TLS/Secure-cookie requirements and sample-account limitations, included a demo recording script, and stated explicitly that deployment/video/test execution remain outstanding.
- **Commit:** Not yet available; no Git repository/remote was configured in the workspace.

## Verification status

The tests are authored in `tests/test_security.py`, but this implementation environment had no Python interpreter, so neither tests nor syntax compilation could be executed here. Run the README test command before deployment and update these entries with the commit URLs and any concrete failures/fixes. Do not replace an unrun check with a claim that it passed.
