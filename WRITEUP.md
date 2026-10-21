# TrustVault project write-up

## What I built

TrustVault is a small document-sharing application using Python's WSGI interface, SQLite, and a plain JavaScript browser client. Owners upload and organize documents, search by name, owner, category, and date, and grant named accounts read or edit access. The admin view shows recent activity and verifies the local audit chain. Setup instructions and endpoint-level role behavior are in [README.md](README.md) and [API.md](API.md).

## Permission model

Every document is private to its owner until an explicit per-document grant is created. A read grant permits metadata reads and downloads. An edit grant also permits metadata changes; only the owner can delete a document or manage its grants. Administrators can inspect audit events but do not bypass document permissions. The server looks up the current owner or grant for each document operation, including downloads. Revocation removes the grant, so the next request is denied. A copy already downloaded cannot be recalled.

## Audit and security

Security-sensitive actions and denied attempts are recorded in a SQLite audit table. Entries are HMAC-signed and linked to the prior entry; ordinary updates and deletes are blocked by database triggers. The signing key is configured outside the database. This detects many changes but is not an independently immutable ledger: a privileged database operator can truncate the tail, and a host compromise can expose both the database and key. A public deployment needs export to a separate append-only service and externally stored checkpoints. Further accepted risks and controls are documented in [THREATS.md](THREATS.md).

## AI use and review

AI was used to build and review the implementation. The prompts, concrete mistakes found during review, and corrections are recorded in [PROMPTS.md](PROMPTS.md). In particular, authorization was checked through direct HTTP requests and tests rather than inferred from the UI. The repository has no Git executable or commit history in this environment, so those notes cannot link to corrective commits yet.

## Verification

`py -m unittest discover -s tests -v` passed all 9 tests on Python 3.15.0 on 2026-10-21. The suite exercises cross-user isolation, access revocation, upload validation, CSRF, server-side search, and audit-chain tamper detection.

## Deliberately unfinished

This workspace does not include a public Git repository, deployed URL, or recorded demo video. These require Git and access to a hosting account and video capture/upload facility. The app also omits SSO/MFA, malware scanning, encryption-at-rest key management, external immutable audit anchoring, version history, and secure erasure. These are documented design limits, not completed features. See [DEMO.md](DEMO.md) for the recording plan and [THREATS.md](THREATS.md) for the fuller risk list.
