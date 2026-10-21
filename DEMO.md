# Five-minute TrustVault demo recording script

This is a recording plan, not a recorded video. Record only against a local/test deployment with demo accounts; never show real confidential documents or publish a deployment with the sample passwords.

1. **0:00–0:35 — Sign in as owner.** Show the document workspace and explain that the owner has no folder-wide sharing; documents start private.
2. **0:35–1:20 — Upload.** Upload a harmless `sample.txt`, show its category and listing, then mention the private storage directory and upload validation/10 MiB limit.
3. **1:20–2:10 — Share.** Open the share dialog, grant `viewer@trustvault.test` read permission, and point out that the named grant is recorded.
4. **2:10–3:00 — Prove access and revoke.** Sign out, sign in as viewer, download the granted file. Sign back in as owner, revoke access. Return to viewer and demonstrate the next download request fails. Explain that this cannot recall bytes already downloaded.
5. **3:00–4:00 — Show the server boundary.** Use the automated tests or an API client to request an ungranted document ID directly as viewer; show 404 for metadata/download, not just a hidden UI button. Run the focused security suite and show results after it has actually been executed.
6. **4:00–5:00 — Audit and limitations.** Sign in as admin, show the grant/revoke/download/denied-attempt events and verified audit-chain indicator. Explain that HMAC plus local triggers detects ordinary edits but does not stop a privileged operator from truncating the local DB; production needs an external immutable audit sink.

**Before recording:** install dependencies, seed fresh demo data, run tests, remove any unrelated personal data, use a clean browser profile, and capture a five-minute screen recording with readable text. The repository currently contains no video file.
