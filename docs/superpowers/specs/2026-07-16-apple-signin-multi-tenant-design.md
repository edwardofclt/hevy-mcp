# Sign in with Apple + Per-User Hevy Keys for hevy-mcp

**Status:** Approved design — ready for implementation plan.
**Date:** 2026-07-16
**Supersedes:** `2026-05-15-static-cred-deploy-design.md` (shared `MCP_CLIENT_ID`/`MCP_CLIENT_SECRET` model). That design's Basic-auth path and the shared-secret form in the OAuth shim are removed by this design.

## Goal

Deploy hevy-mcp to Fly.io as a real multi-tenant remote MCP server. Each user authenticates with **Sign in with Apple**, manages their own Hevy API key from a web dashboard, and MCP clients (e.g. Claude) connect on that user's behalf via OAuth. A user can never view their Hevy API key again after saving it — only whether one is configured.

## Non-goals

- Changing local/stdio single-user usage (`HEVY_API_KEY` env var / npm package) — untouched.
- Supporting identity providers other than Apple.
- Team/org accounts or key sharing between users.
- Rate limiting beyond what already exists (out of scope; platform/Hevy upstream).
- Horizontal scaling to multiple app instances (SQLite-on-volume implies single instance; documented as a known limitation, not solved here).

## Architecture overview

```
Browser (dashboard)                 MCP client (Claude, etc.)
   │ GET /login                        │ GET /authorize?...PKCE params
   ▼                                    ▼
Sign in with Apple ─────────────────────┘  (both funnel through Apple)
   │ POST /auth/apple/callback (id_token)
   ▼
users table (apple_sub → user_id)
   │
   ├─ dashboard: web_sessions cookie → /account (set/replace Hevy key, write-only)
   │
   └─ MCP flow: consent screen → mcp_auth_codes → POST /token → mcp_tokens (bearer)
                                                                     │
                                                                     ▼
                                          POST /mcp  Authorization: Bearer <token>
                                                                     │
                                          mcp_tokens → user_id → hevy_keys (decrypt)
                                                                     │
                                                          buildServer(apiKey) per session
                                                                     │
                                                            Hevy API (per-user key)
```

The existing PKCE machinery in `src/utils/oauth.ts` (`/authorize`, `/token`, `/register`, `.well-known/*`) is reused. The only structural change to that flow is *who* `/authorize` authenticates: a person via Apple, not a shared secret.

## Data model

SQLite file on a Fly volume (`DATABASE_PATH`, default `/data/hevy-mcp.sqlite`), accessed via Node's built-in `node:sqlite` (no native build step, keeps the Alpine Docker image simple).

```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,           -- uuid
  apple_sub TEXT UNIQUE NOT NULL,
  email TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE hevy_keys (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  ciphertext BLOB NOT NULL,
  iv BLOB NOT NULL,
  auth_tag BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE web_sessions (
  id TEXT PRIMARY KEY,           -- random token, stored in httpOnly cookie
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE mcp_auth_codes (
  code TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  client_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE mcp_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);
```

`apple_sub` (Apple's stable per-(user, Services ID) identifier from the `id_token`'s `sub` claim) is the identity join key, not email — Apple private-relay emails can change, `sub` doesn't.

Expired rows in `mcp_auth_codes`, `mcp_tokens`, `web_sessions` are lazily garbage-collected on access (same pattern as the current in-memory `gc()` in `oauth.ts`), plus a periodic sweep on an interval timer.

## Components

### `src/utils/db.ts` (new)

- Opens the `node:sqlite` `DatabaseSync` at `DATABASE_PATH`, runs schema migrations (idempotent `CREATE TABLE IF NOT EXISTS`) on startup.
- Exports typed accessor functions: `upsertUser`, `getUserByAppleSub`, `saveHevyKey`, `getHevyKeyStatus(userId): { configured: boolean, updatedAt?: number }`, `getDecryptedHevyKey(userId): string | null`, `createWebSession`, `getWebSession`, `deleteWebSession`, `createAuthCode`, `consumeAuthCode`, `createMcpToken`, `getMcpToken`.
- No caller outside `db.ts` ever sees `ciphertext`/`iv`/`auth_tag` directly — encryption/decryption is internal to `saveHevyKey`/`getDecryptedHevyKey`.

### `src/utils/crypto.ts` (new)

- `encryptSecret(plaintext: string, masterKey: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer }` — AES-256-GCM, random 12-byte IV per call.
- `decryptSecret(fields, masterKey: Buffer): string`.
- `loadMasterKey(env): Buffer` — reads `ENCRYPTION_KEY` (base64, 32 bytes), exits process with a clear error if missing/wrong length in HTTP mode.

### `src/utils/apple.ts` (new)

- `buildAppleAuthUrl(state: string): string` — constructs the `https://appleid.apple.com/auth/authorize` redirect URL (`client_id`, `redirect_uri`, `response_type=code id_token`, `scope=name email`, `response_mode=form_post`, `state`).
- `exchangeAppleCode(code: string): Promise<{ sub: string; email?: string }>` — POSTs to `https://appleid.apple.com/auth/token` with a signed client-assertion JWT (ES256, signed with `APPLE_PRIVATE_KEY`, per Apple's requirement that confidential clients authenticate via JWT rather than a static secret), receives Apple's `id_token`, verifies it against Apple's JWKS (`https://appleid.apple.com/auth/keys`, fetched and cached) using `jose`, and returns the verified `sub`/`email` claims.
- JWKS response cached in-memory with the `Cache-Control` TTL Apple returns (typically ~24h), refetched on expiry or verification key-not-found.

### `src/utils/session.ts` (new)

- `requireWebSession: RequestHandler` — reads the signed session cookie, loads `web_sessions` → `user_id`, attaches `req.userId`; redirects to `/login` (preserving the original URL via a `next` query param) if absent/expired.
- Cookie: httpOnly, `SameSite=Lax`, `Secure` in production, signed with a cookie-secret derived from `ENCRYPTION_KEY` (HMAC, not the raw key) so no new secret is required.

### `src/routes/auth.ts` (new — dashboard + Apple handshake)

- `GET /login` → redirect to Apple (`buildAppleAuthUrl`), state includes an optional `next` path.
- `POST /auth/apple/callback` (Apple calls back via `form_post`) → `exchangeAppleCode` is not needed here since Apple posts the `id_token` directly in `response_mode=form_post`; verify it in-place via `jose` against Apple's JWKS, `upsertUser`, `createWebSession`, set cookie, redirect to `state`'s `next` (default `/account`).
- `GET /account` (requires `requireWebSession`) → renders key status (configured/not, `updated_at`) + save form + sign-out link. Never renders key material.
- `POST /account/hevy-key` (requires `requireWebSession`) → validates non-empty body, `saveHevyKey(userId, plaintext)`, redirect back to `/account` with a "Saved" flash.
- `POST /account/logout` → `deleteWebSession`, clear cookie, redirect to `/`.

### `src/utils/oauth.ts` (modified)

- Remove `clientSecret` option and the `renderForm` secret-entry form.
- `GET /authorize`: if no valid web session, redirect to `/login?next=<original query string re-encoded>`. If a session exists, render a consent screen ("Authorize hevy-mcp for {client_id}?") instead of a secret form.
- `POST /authorize`: no `secret` field; requires `requireWebSession`; on submit calls `createAuthCode({ userId: req.userId, redirectUri, codeChallenge, codeChallengeMethod, clientId })`, then redirects to `redirect_uri` with `code`/`state` as before.
- `POST /token`: unchanged PKCE verification, but persists/reads via `db.ts` (`createMcpToken`/`consumeAuthCode`) instead of in-memory `Map`s.
- `requireBearer`: looks up `getMcpToken(token)` → `user_id`; attaches `req.userId` (or the equivalent context passed to the `/mcp` handler) instead of a boolean pass/fail.

### `src/http.ts` (modified)

- `runHttpServer` drops the shared `apiKey` parameter and `HttpAuth` (`clientId`/`clientSecret`) entirely for HTTP mode.
- Mounts `src/routes/auth.ts` (login/callback/account).
- `mcpAuth` becomes exclusively `oauth.requireBearer` (Basic auth path removed).
- In the `POST /mcp` handler, after auth resolves `req.userId`, fetch `getDecryptedHevyKey(userId)`; if null, respond `403` with a JSON-RPC error telling the client to visit `/account` and configure a key first. Otherwise `buildServer(apiKey)` as today, scoped to that session's transport.

### `src/utils/config.ts` (modified)

- Remove `clientId`/`clientSecret`/`assertHttpCreds`.
- Add `databasePath` (env `DATABASE_PATH`, default `./hevy-mcp.sqlite` for local dev), `encryptionKey` (env `ENCRYPTION_KEY`), Apple settings (`APPLE_TEAM_ID`, `APPLE_CLIENT_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY`, `APPLE_REDIRECT_URI`).
- `assertHttpEnv(cfg)` replaces `assertHttpCreds`: exits with a clear stderr message listing any missing required var when `cfg.http` is true.
- Stdio/local mode (`HEVY_API_KEY`) path is entirely unaffected — `apiKey` remains optional/required only for that mode.

### `Dockerfile` / `docker-compose.yml` (modified)

- `VOLUME /data`, `ENV DATABASE_PATH=/data/hevy-mcp.sqlite`.
- Drop `MCP_CLIENT_ID`/`MCP_CLIENT_SECRET` from required env comments; add the Apple + `ENCRYPTION_KEY` vars.
- `docker-compose.yml`: mount a named volume at `/data`, drop the two removed required env vars, add the new ones (Apple vars can be blank/optional for pure local dev without testing the Apple flow — `assertHttpEnv` only enforces them when actually booting HTTP mode for real use, but for straightforward local dev we keep the compose file requiring them since it's specifically the "run this like production" path).

### `fly.toml` (new)

- App name, `[build]` pointing at the existing Dockerfile, `[[mounts]]` for a volume mounted at `/data`, `[[services]]`/`[http_service]` on port 3000 with `/health` as the check path, `min_machines_running = 1` (SQLite + a single writer volume means we deliberately don't auto-scale to N machines).

## Data flow — MCP tool call (steady state)

```
MCP client → HTTPS (Fly-terminated) → POST /mcp, Authorization: Bearer <token>
  → requireBearer: mcp_tokens[token] → user_id (401 if missing/expired)
  → getDecryptedHevyKey(user_id) (403 + "configure your key at /account" if none)
  → buildServer(apiKey) for this session's transport
  → tool handler → Hevy API with that user's key
```

## Error handling

| Condition | Response |
|---|---|
| `/mcp` request with missing/invalid/expired bearer token | `401` + `WWW-Authenticate: Bearer` (existing shape) |
| `/mcp` request from a valid user with no Hevy key configured | `403` JSON-RPC error pointing to `/account` |
| `/authorize` with no web session | `302` to `/login?next=...` |
| `/login` / Apple callback: `id_token` fails JWKS verification | `401`, generic "sign-in failed" page, no claim details leaked |
| `/account/hevy-key` POST with empty body | `400`, re-render form with inline error |
| HTTP mode boot with missing `ENCRYPTION_KEY` / Apple vars | Process exits 1, stderr lists exactly which vars are missing |
| SQLite file inaccessible/unwritable at `DATABASE_PATH` | Process exits 1 at startup (fail fast, not on first request) |

## Testing

Unit tests:
- `src/utils/crypto.test.ts` — encrypt/decrypt round-trip, wrong key fails, tamper with `authTag` fails.
- `src/utils/apple.test.ts` — JWT verification against a mocked JWKS (valid, expired, wrong issuer, wrong audience all rejected); client-assertion JWT has correct claims/alg.
- `src/utils/db.test.ts` — user upsert idempotency by `apple_sub`, key save overwrites prior row, `getHevyKeyStatus` never returns plaintext, expired session/code/token lookups return null.
- `src/utils/oauth.test.ts` (extend existing) — `/authorize` redirects to `/login` without a session; consent + code issuance with a session; `/token` PKCE exchange unchanged; bearer lookups resolve to the right `user_id`.

HTTP-level tests (extend `src/http.test.ts`):
- Full flow against an in-memory/tmp SQLite db: fake Apple callback → session cookie → `/account` key save → `/authorize` consent → `/token` → `POST /mcp` succeeds and reaches the tool handler using that user's key (assert the mock Hevy client received the right key).
- `POST /mcp` for a user with no key configured → `403` with the expected message.
- Two different users' bearer tokens resolve to two different keys (isolation check).

Manual smoke test (documented in README): `fly deploy`, visit `/login`, complete Apple sign-in, save a key at `/account`, refresh and confirm no key material is shown, connect Claude via `/authorize`, run a tool call.

## Security notes

- `ENCRYPTION_KEY` (AES-256-GCM master key) and Apple's `APPLE_PRIVATE_KEY` are the two crown-jewel secrets — set via `fly secrets set`, never committed, never logged.
- A stolen SQLite file/volume snapshot alone does not yield plaintext Hevy keys without `ENCRYPTION_KEY` too (defense in depth vs. a volume-level leak).
- Dashboard session cookies are httpOnly + `Secure` + `SameSite=Lax` — not readable by JS, not sent cross-site.
- Apple `id_token` verification checks `iss=https://appleid.apple.com`, `aud=<APPLE_CLIENT_ID>`, and expiry — rejects anything else before trusting `sub`.
- The write-only guarantee is enforced structurally: no route/query ever selects `ciphertext` back out in a response; `getHevyKeyStatus` is the only read path exposed to request handlers outside `db.ts`/`http.ts`'s internal per-request decrypt.
- TLS is mandatory in production — Fly terminates it at the edge; the app itself doesn't need to (same posture as the prior design).
- Rotation: user can overwrite their key any time from `/account`; existing MCP bearer tokens keep working transparently against the new key (no forced re-auth on rotation).

## Out-of-scope follow-ups

- Multi-instance/horizontal scaling (would need LiteFS/Turso or a move to Postgres).
- Revoking a specific MCP client's token from the dashboard (currently: only full account key rotation or waiting out the 7-day token TTL).
- Apple account deletion / GDPR-style data export endpoints.
- Alternate identity providers (Google, GitHub, etc.).
