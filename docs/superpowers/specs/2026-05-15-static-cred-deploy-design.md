# Static-Credential Internet Deploy for hevy-mcp

**Status:** Approved design — ready for implementation plan.
**Date:** 2026-05-15

## Goal

Make hevy-mcp deployable on the public internet as a remote MCP server, gated by a single shared `client_id` / `client_secret` pair presented via HTTP Basic auth. All authenticated callers share one upstream Hevy account via the server's `HEVY_API_KEY`.

## Non-goals

- Per-user Hevy API keys / multi-tenancy.
- OAuth 2.0 dynamic client registration or token endpoints.
- Credential rotation without redeploy.
- Rate limiting (out of scope; rely on platform/Hevy upstream).
- TLS termination (deployment responsibility, not application).

## Architecture

The existing `src/http.ts` already exposes the MCP Streamable HTTP transport at `POST/GET/DELETE /mcp` plus an open `GET /health`. We add:

1. A Basic-auth middleware that gates `/mcp` only.
2. Two new required env vars in HTTP mode: `MCP_CLIENT_ID`, `MCP_CLIENT_SECRET`.
3. Dockerfile defaults that make `docker run` start the HTTP server on port 3000.

All MCP traffic flows through one process; sessions remain in-memory (matches today's behavior).

## Components

### `src/utils/auth.ts` (new)

Exports `requireBasicAuth(clientId: string, clientSecret: string)` returning an Express `RequestHandler`.

Behavior:

- Parse the `Authorization` header. If missing or not starting with `Basic `, respond `401` with `WWW-Authenticate: Basic realm="hevy-mcp", charset="UTF-8"`.
- Base64-decode the credential, split on the first `:`. If decoding or split fails, respond `401`.
- Compare presented id and secret to expected values using `crypto.timingSafeEqual` on equal-length `Buffer`s. To preserve constant-time behavior when lengths differ, first compare against a same-length scratch buffer, then OR in a length-mismatch flag. The function always returns `false` on mismatch but takes the same time regardless of where the mismatch occurs.
- On success, call `next()`.
- On failure, respond `401` with a JSON-RPC-shaped body:
  ```json
  { "jsonrpc": "2.0", "error": { "code": -32001, "message": "Unauthorized" }, "id": null }
  ```
  so MCP clients log something useful.
- Never log the presented or expected secret. Log only client IP + outcome (`auth.ok` / `auth.fail`) at info / warn.

### `src/http.ts` (modified)

- `runHttpServer` signature becomes `(apiKey: string, port: number, creds: { clientId: string; clientSecret: string })`.
- Mount `requireBasicAuth(creds.clientId, creds.clientSecret)` on all three `/mcp` handlers (POST, GET, DELETE). Do not gate `/health`.
- No other behavior changes.

### `src/utils/config.ts` (modified)

- Extend `HevyConfig` with `clientId?: string` and `clientSecret?: string`.
- Source them from env only (`MCP_CLIENT_ID`, `MCP_CLIENT_SECRET`). Do not accept them as CLI flags — argv leaks to `ps`.
- Add `assertHttpCreds(cfg: HevyConfig)` that, when `cfg.http` is true, exits with a clear error if either value is missing or empty.

### `src/index.ts` (modified)

- In `runServer()`, after `parseConfig`, if `cfg.http`, call `assertHttpCreds(cfg)` and pass `{ clientId, clientSecret }` into `runHttpServer`.

### `Dockerfile` (modified)

- Add `ENV MCP_HTTP=true PORT=3000` so `docker run` defaults to HTTP mode.
- Add `EXPOSE 3000`.
- Update the env documentation comment to list `HEVY_API_KEY`, `MCP_CLIENT_ID`, `MCP_CLIENT_SECRET` as required at runtime.

### `README.md` (modified)

- Add a "Deploying as a remote MCP server" section covering: required env vars, the Basic-auth contract, and a one-liner reminder that the deployment must terminate TLS.

## Data flow

```
MCP client
  → HTTPS (terminated by platform)
  → POST /mcp with Authorization: Basic base64(client_id:client_secret)
  → requireBasicAuth middleware (constant-time compare)
  → existing session manager / StreamableHTTPServerTransport
  → tool handler
  → Hevy API with server's single HEVY_API_KEY
```

All authenticated callers act as the same Hevy user. This is the explicit trade-off of the single-shared-secret model.

## Error handling

| Condition | Response |
|---|---|
| Missing `Authorization` header on `/mcp` | `401` + `WWW-Authenticate` |
| Malformed Basic header (bad base64, no colon) | `401` + `WWW-Authenticate` |
| Wrong id or secret | `401` + `WWW-Authenticate` |
| HTTP mode requested but `MCP_CLIENT_ID` or `MCP_CLIENT_SECRET` unset at startup | Process exits 1 with a clear stderr message |
| `/health` | Always `200`, no auth |

## Testing

Unit tests (`src/utils/auth.test.ts`):

- No header → 401, `WWW-Authenticate` set.
- Non-Basic scheme → 401.
- Malformed base64 → 401.
- Missing colon in decoded value → 401.
- Wrong id, right secret → 401.
- Right id, wrong secret → 401.
- Right id, right secret → `next()` called, no response written.
- Length-mismatched id/secret → 401 without throwing on `timingSafeEqual` length assertion.

HTTP-level tests (extend `src/index.test.ts` or new `src/http.test.ts`):

- Boot express app with stub creds.
- `GET /health` → 200 without auth header.
- `POST /mcp` without auth → 401.
- `POST /mcp` with correct Basic creds → reaches transport (initialize handshake succeeds or returns the existing "no session id and not initialize" 400, which proves we passed auth).

Manual smoke:

```
docker build -t hevy-mcp .
docker run --rm -p 3000:3000 \
  -e HEVY_API_KEY=... \
  -e MCP_CLIENT_ID=demo \
  -e MCP_CLIENT_SECRET=$(openssl rand -base64 32) \
  hevy-mcp
curl -s http://localhost:3000/health           # 200
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://localhost:3000/mcp            # 401
curl -u demo:$SECRET -X POST http://localhost:3000/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0",...}'                   # auth passes
```

## Security notes

- **TLS is mandatory in production.** Basic auth over plaintext leaks the secret on every request. Deployment must sit behind an HTTPS terminator (every container host provides one).
- Use a high-entropy secret (≥ 32 bytes, base64 or hex). The README will recommend `openssl rand -base64 32`.
- Constant-time comparison prevents timing-oracle attacks on the secret.
- Rotation: redeploy with new env values. No persistent token state to revoke.
- A leaked secret grants full access to the configured Hevy account via this server until redeploy. Treat the env vars as production secrets.
- The `client_id` is not itself a secret, but it is still compared in constant time so the response time doesn't reveal which half of the credential was wrong.

## Out-of-scope follow-ups

- Multiple `client_id:client_secret` pairs (for per-consumer revocation without rotating everyone).
- Per-user Hevy API keys passed by client.
- OAuth or PAT-style tokens.
- Audit logging beyond auth.ok / auth.fail.
