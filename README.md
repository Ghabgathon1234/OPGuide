# Operator Guide Publisher backend

Railway-ready Flask API for the Operator Guide desktop publisher. Google credentials
stay on Railway. The updated desktop publisher remains in the local OperatorGuide project.

## Railway setup

1. Create a Railway service from `Ghabgathon1234/OPGuide`, branch `main`, repository
   root `/`. The root Dockerfile and railway.json configure build/start/health checks.
2. **Attach a persistent Railway volume at `/data` before the first deployment.**
   It stores the changed password hash and rate-limit state. Use **one replica and
   one Gunicorn worker**; do not enable autoscaling or override the worker count.
3. Add these variables in Railway's Variables tab:

   - `GCS_BUCKET_NAME`: `operator-guide-bucket` (verify this is your actual bucket).
   - `GOOGLE_CREDENTIALS_JSON`: the complete Google service-account JSON, as a secret
     variable. Do not commit it or place it in the desktop app.
   - `INITIAL_PASSWORD_HASH`: an Argon2id hash for the initial password `652512`.
     Generate it with `python backend/hash_password.py` after installing backend
     dependencies. Paste the entire output, including dollar signs.
   - `AUTH_DB_PATH`: `/data/auth.sqlite3`.
   - `RELEASE_ROOT`: `operator-guide` (optional; default).
   - `MAX_UPLOAD_MB`: `250` (optional; total multipart request limit, default 250 MiB).

   Railway supplies `PORT`; do not set it manually. The server binds to `0.0.0.0`.
4. Generate a Railway public HTTPS domain. Open `/health` to verify startup.
5. Run the publisher and enter initial password `652512`. It works immediately for
   listing, publishing and deletion. Changing it is optional.
6. To change the password, enter the current password in the publisher, click
   **Change password**, and enter/confirm a new password of 6–256 characters.
   No setup token is required. There is exactly **one shared password**: changing
   it replaces the old password for all publishers. The initial password is not
   retained as a fallback. Passwords stay only in desktop process memory; the backend
   stores a salted Argon2id hash on the persistent volume.

`INITIAL_PASSWORD_HASH` only seeds a new database. Changing that variable does not
reset an existing password. This update preserves previously changed passwords and
removes the old forced-change flag. You may delete the unused BOOTSTRAP_TOKEN variable
from Railway. Back up the volume: losing it reinitializes the configured initial hash.
For deliberate lost-password recovery, stop the service, back up and remove the auth
database, configure the desired initial hash, then redeploy. Bucket data is unaffected.

## API contract

Every private request carries `password` in its HTTPS-encrypted body. Passwords are
never put in URLs. There are no cookies, public file proxy, signed download URLs or
download endpoints. The desktop refuses HTTP URLs and redirects.

- `GET /health`: public liveness status only.
- `POST /api/auth/check`: JSON `{password}`; returns connection info and whether the
  password must be changed (always false; retained for client compatibility).
- `POST /api/auth/password`: JSON `{password, new_password}`; verifies the current password and replaces its hash.
- `POST /api/files/list`: JSON `{password}`; read-only **get/list operation** returning
  names, sizes, updated dates, filename versions and current-release metadata.
  POST keeps the password in the encrypted payload. No object contents are downloaded,
  including by the backend. Only objects under RELEASE_ROOT are listed.
- `POST /api/releases`: multipart `password`, `pdf`, `manifest` (latest.json), and
  optional `index` (search-index JSON). One release uploads all required files.
  Server verifies version, exact object paths, byte count and SHA-256 hashes, and index
  structure. PDFs without bookmark outlines can be published without an index, matching
  the existing publisher behavior. No client-selected bucket or arbitrary upload path.
- `POST /api/files/delete`: JSON `{password, paths: [...]}`; at most 100 paths.
  Only latest.json and versioned PDFs/indexes under RELEASE_ROOT can be deleted.
  Live files are protected unless latest.json is included explicitly to unpublish.

Versions are immutable: an existing PDF or index returns 409. Use a fresh version.
The manifest is uploaded last using a GCS generation precondition. Failures can leave
unreferenced PDF/index objects, but do not promote an incomplete release. Refresh,
delete those orphans, and retry. Deletes can partially succeed; the error lists
completed deletions. Refresh before retrying. Never bypass the backend with another
publisher while a release is in progress; preconditions detect individual-object
conflicts, but GCS has no multi-object transaction.

The current version is stored as custom metadata on latest.json. **Legacy releases
have no such metadata:** the list marks the live version unknown until the next
successful release. The backend intentionally does not download the old JSON to
infer the version. Old-file cleanup is disabled while the live version is unknown.

The desktop currently generates version and search JSON from the selected PDF and
uploads them together, preserving the Flutter app's existing manifest schema and
paths. It does not expose arbitrary JSON editing.

## Bucket security and migration

This removes the extractable Google key from new desktop builds. HTTPS encrypts the
password and files in transit; Argon2id hashes the password at rest. There is no
embedded symmetric encryption key or reusable client-side password hash masquerading
as extra security. Reusing such a value would make it a password equivalent.

Use a dedicated service account with bucket-scoped **Storage Object User**, or a
custom role limited to object get/list/create/update/delete for this bucket. Do not
use project Owner/Editor or Storage Admin. If the bucket contains unrelated data,
use a separate bucket for publisher releases; the application's prefix restriction
is not a replacement for IAM isolation. This code never grants public permissions.

The existing Flutter reader downloads releases directly from Storage. Keep its
required read policy working; moving publishing to Railway does not make existing
public content confidential. Audit both bucket IAM/ACLs and Firebase Storage rules:
public WRITE/DELETE must be denied. This setup does not change those policies for you.

**Rotate/revoke the old service-account key once migration is verified.** Existing
installers and Windows build kits included that key; changing source code does not
remove credentials from those already-created artifacts. Do not distribute them.
Rebuild installers from the updated local publisher source; its new packaging contains no Google credentials.

Remaining limitations: a shared password provides no per-person audit identity or
MFA. Whoever knows it can publish, unpublish and delete. The persisted global limit
of 20 failed authentication attempts per 15 minutes slows brute force but permits
an attacker to cause temporary lockout. Large multipart bodies are bounded but parsed
before password validation; use edge/WAF rate limits or a private network if exposed
to abuse. Do not log request bodies or enable Flask debug mode. Production hardening
can replace shared-password access with individual SSO/MFA and external rate limiting.
Enable GCS soft delete/versioning if recovery from operator mistakes is required.

## Development and tests

Python 3.12 recommended:

```sh
python -m venv .venv
.venv/bin/pip install -r backend/requirements.txt pytest
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests -q
```

Tests use a fake bucket and forbid download methods. No tests write to a real bucket.
See the local publisher README for the desktop app. Railway deployment and live GCS access
must be verified after you configure the secrets and volume.

References: [Railway variables](https://docs.railway.com/variables),
[Railway volumes](https://docs.railway.com/volumes),
[OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[Google service-account key guidance](https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys).
