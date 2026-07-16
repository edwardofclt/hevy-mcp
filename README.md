# hevy-mcp: Model Context Protocol Server for Hevy Fitness API

[![smithery badge](https://smithery.ai/badge/@chrisdoc/hevy-mcp)](https://smithery.ai/server/@chrisdoc/hevy-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server implementation that interfaces with the [Hevy fitness tracking app](https://www.hevyapp.com/) and its [API](https://api.hevyapp.com/docs/). This server enables AI assistants to access and manage workout data, routines, exercise templates, and more through the Hevy API (requires PRO subscription).

## Features

- **Workout Management**: Fetch, create, and update workouts
- **Routine Management**: Access and manage workout routines
- **Exercise Templates**: Browse available exercise templates
- **Folder Organization**: Manage routine folders
- **Webhook Subscriptions**: Create, view, and delete webhook subscriptions for workout events

> **Note:** HTTP transport and Docker images remain deprecated. Smithery deployment now uses the official TypeScript runtime flow (no Docker required), or you can run the server locally via stdio (e.g., `npx hevy-mcp`). Existing GHCR images remain available but are no longer updated.

## Quick start

Pick the workflow that fits your setup:

| Scenario | Command | Requirements |
| --- | --- | --- |
| One-off stdio run | `HEVY_API_KEY=sk_live... npx -y hevy-mcp` | Node.js ≥ 20, Hevy API key |
| Local development | `pnpm install && pnpm run dev` | `.env` with `HEVY_API_KEY`, pnpm via Corepack |
| Smithery playground / deploy | `pnpm run smithery:dev` / `pnpm run smithery:build` | `HEVY_API_KEY`, `SMITHERY_API_KEY` (or `pnpm dlx @smithery/cli login`) |

## Prerequisites

- Node.js (v20 or higher; strongly recommended to use the exact version pinned in
  `.nvmrc` to match CI)
- pnpm (via Corepack)
- A Hevy API key
  - Optional: A Smithery account + API key/login if you plan to deploy via Smithery

## Installation

### Run via npx (recommended)

You can launch the server directly without cloning:

```bash
HEVY_API_KEY=your_hevy_api_key_here npx -y hevy-mcp
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/chrisdoc/hevy-mcp.git
cd hevy-mcp

# Install dependencies
corepack use pnpm@10.22.0
pnpm install

# Create .env and add your keys (never commit real keys)
cp .env.sample .env
# Edit .env and add at least HEVY_API_KEY. Add SMITHERY_API_KEY if you use Smithery CLI.
```

### Integration with Cursor

To use this MCP server with Cursor, add/merge this server entry under
`"mcpServers"` in `~/.cursor/mcp.json`:

```json
{
  "hevy-mcp": {
    "command": "npx",
    "args": ["-y", "hevy-mcp"],
    "env": {
      "HEVY_API_KEY": "your-api-key-here"
    }
  }
}
```

Make sure to replace `your-api-key-here` with your actual Hevy API key.

If your `mcp.json` already contains other servers, do not replace the whole
file—merge the `"hevy-mcp"` entry into your existing `"mcpServers"` object.

The `"hevy-mcp"` key name is arbitrary. If you already have an existing config
using a different name (for example `"hevy-mcp-server"`), you can keep it.

If you already have an existing `"mcpServers"` object, merge the `"hevy-mcp"`
entry into it without removing other servers.

<details>
<summary><strong>Example full ~/.cursor/mcp.json</strong></summary>

```json
{
  "mcpServers": {
    "hevy-mcp": {
      "command": "npx",
      "args": ["-y", "hevy-mcp"],
      "env": {
        "HEVY_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

</details>


## Configuration

You can supply your Hevy API key in two ways:

1. Environment variable (`HEVY_API_KEY`)
2. Command-line argument (`--hevy-api-key=your_key` or `hevy-api-key=your_key` after `--` when using pnpm scripts)

Create a `.env` file in the project root (you can copy from [.env.sample](.env.sample)) with the following content if using the environment variable approach:

```env
HEVY_API_KEY=your_hevy_api_key_here
```

Replace `your_hevy_api_key_here` with your actual Hevy API key. If you prefer the command argument approach you can skip setting the environment variable and start the server with for example:

```bash
pnpm start -- --hevy-api-key=your_hevy_api_key_here
```

### Sentry monitoring

`hevy-mcp` ships with Sentry monitoring baked into the built MCP server so
that usage and errors from published builds can be observed.

The server initializes `@sentry/node` with a fixed DSN, release name derived
from the package version, and tracing settings
directly in the code (see `src/index.ts`), and wraps the underlying
`McpServer` with `Sentry.wrapMcpServerWithSentry` so requests and tool calls
are captured by Sentry automatically. The configuration uses
`sendDefaultPii: false` to keep Sentry's default PII collection disabled.

There is currently no built-in toggle to disable Sentry for the published
package. If you need a build without Sentry telemetry, you can fork the
repository and remove the Sentry initialization in `src/index.ts`.

## Transport

### Deploy via Smithery (TypeScript runtime)

Smithery can bundle and host `hevy-mcp` without Docker by importing the exported `createServer` and `configSchema` from `src/index.ts`.

1. Ensure dependencies are installed: `pnpm install`
2. Launch the Smithery playground locally:

   ```bash
   pnpm run smithery:dev
   ```

   The CLI will prompt for `HEVY_API_KEY`, invoke `createServer({ config })`, and open the Smithery MCP playground.

3. Build the deployable bundle:

   ```bash
   pnpm run smithery:build
   ```

4. Connect the repository to Smithery and trigger a deployment from their dashboard. Configuration is handled entirely through the exported Zod schema, so no additional `smithery.yaml` env mapping is required.

> **Why are `chalk`, `cors`, and `@smithery/sdk` dependencies?** Smithery’s TypeScript runtime injects its own Express bootstrap that imports these packages. Declaring them in `package.json` ensures the Smithery CLI can bundle your server successfully.

### Self-hosted remote MCP (Sign in with Apple + per-user Hevy keys)

Deploy `hevy-mcp` as a genuine multi-tenant remote MCP server on Fly.io. Each
user authenticates with Sign in with Apple, manages their own Hevy API key
from a web dashboard (`/account`), and MCP clients (e.g., Claude) connect on
that user's behalf via OAuth after the user authorizes the client. The old
shared `MCP_CLIENT_ID`/`MCP_CLIENT_SECRET` Basic-auth model is completely
replaced — no more shared secrets.

#### Required runtime environment variables

| Variable | Purpose |
|---|---|
| `ENCRYPTION_KEY` | Base64-encoded 32-byte AES-256-GCM master key. Generate via `openssl rand -base64 32`. Encrypts stored Hevy API keys at rest. |
| `APPLE_TEAM_ID` | Your Apple Developer Team ID. |
| `APPLE_CLIENT_ID` | The Services ID registered in the Apple Developer portal for Sign in with Apple. |
| `APPLE_KEY_ID` | The Key ID of your Sign in with Apple private key (.p8 file). |
| `APPLE_PRIVATE_KEY` | Contents of your `.p8` private key file from Apple (the full PEM-encoded key). |
| `APPLE_REDIRECT_URI` | OAuth redirect URI (must match exactly what you registered in the Apple portal; e.g., `https://your-app-name.fly.dev/auth/apple/callback`). |
| `DATABASE_PATH` | Path to the SQLite database file (default: `/data/hevy-mcp.sqlite` in Docker, `./hevy-mcp.sqlite` for local dev). |
| `PORT` | HTTP port (default `3000`; setting `PORT` enables HTTP mode). |

**Note:** `HEVY_API_KEY` is **no longer required** for HTTP/remote MCP mode — each user supplies their own Hevy API key via the dashboard and it is encrypted at rest with `ENCRYPTION_KEY`. `HEVY_API_KEY` is only used by the separate local stdio/single-user mode (unaffected by this change, documented elsewhere in the README).

#### Apple Developer prerequisites

1. A **Services ID** configured for "Sign in with Apple" in the Apple Developer portal.
2. A **verified redirect domain** (Apple requires a real domain, not a bare IP or `*.fly.dev`-style hostname unless it is your actual custom domain). The `APPLE_REDIRECT_URI` environment variable must match exactly.
3. A **private key** (.p8 file) generated for Sign in with Apple. Note its Key ID (`APPLE_KEY_ID`).
4. The **Team ID** from your Apple Developer account.

#### Fly.io deployment

1. **First-time setup: create the data volume**

   ```bash
   fly volumes create hevy_mcp_data --size 1
   ```

   This volume will store the SQLite database across app recreations. The size is intentionally small (1 GB) — adjust if you expect very large datasets.

2. **Create the app and set secrets**

   First, edit `fly.toml`: replace the placeholder `app` name with your desired app name (must be globally unique on Fly.io) and pick a `primary_region` closest to your users (see fly.toml comments).

   Then:

   ```bash
   fly secrets set \
     ENCRYPTION_KEY=$(openssl rand -base64 32) \
     APPLE_TEAM_ID=<your-team-id> \
     APPLE_CLIENT_ID=<your-services-id> \
     APPLE_KEY_ID=<your-key-id> \
     APPLE_PRIVATE_KEY="$(cat AuthKey_XXXXXXXXXX.p8)" \
     APPLE_REDIRECT_URI=https://<your-app-name>.fly.dev/auth/apple/callback
   ```

3. **Deploy**

   ```bash
   fly deploy
   ```

   Fly.io terminates TLS at the edge automatically, so the app does not need to manage certificates.

#### Docker Compose / local self-test

To run locally with Docker Compose (useful for testing before Fly.io deployment):

```bash
# Copy .env.sample and fill in all required vars (ENCRYPTION_KEY, APPLE_* vars, APPLE_REDIRECT_URI)
cp .env.sample .env.local
# Edit .env.local with your Apple credentials
docker compose --env-file .env.local up
```

The `docker-compose.yml` mounts a named volume at `/data` for the SQLite database and requires all Apple authentication variables to be set.

#### Using the dashboard

After deployment (or Docker Compose startup), visit `https://your-app-name.fly.dev/login` (or `http://localhost:3000/login` for local testing):

1. **Sign in with Apple** — you are redirected through Apple's OAuth flow.
2. **Dashboard at `/account`** — after sign-in, you can view whether a Hevy API key is configured (including the date it was last updated) and save/replace it via an HTML form.
3. **Write-only guarantee** — your Hevy API key is never displayed or returned in any API response. Once saved, only the dashboard shows that a key exists; the key itself is encrypted at rest and only decrypted server-side per API call.
4. **Sign out** — click the sign-out link on `/account` to clear your session.

#### Connecting an MCP client (Claude, Cursor, etc.)

Point your MCP client to `https://your-app-name.fly.dev/mcp` (or `http://localhost:3000/mcp` for local testing). The first time a client connects:

1. The client will be redirected to `/authorize`.
2. You sign in with Apple (if not already signed in on the dashboard).
3. A consent screen asks you to authorize the client to access your Hevy data.
4. The client receives an OAuth token and can make MCP calls on your behalf.

This replaces the old shared-secret model — no more HTTP Basic auth or shared credentials.

#### Endpoints

- `GET /login` — Redirect to Apple Sign in with Apple, with optional `next` parameter to return to after sign-in.
- `POST /auth/apple/callback` — Apple posts the `id_token` here (internal redirect target; you don't call this directly).
- `GET /account` — Dashboard for viewing key status and saving a new Hevy API key (requires web session).
- `POST /account/hevy-key` — Save or replace your Hevy API key (requires web session).
- `POST /account/logout` — Sign out and clear your session.
- `GET /authorize` — OAuth authorization endpoint for MCP clients (redirects to `/login` if you're not signed in).
- `POST /token` — OAuth token endpoint (PKCE exchange, returns a bearer token for the MCP client).
- `POST /mcp`, `GET /mcp`, `DELETE /mcp` — MCP Streamable HTTP transport (requires a valid bearer token in `Authorization: Bearer <token>`).
- `GET /health` — Open health check for platform probes.

**Production deployments must terminate TLS in front of the server.** Fly.io handles TLS termination automatically at the edge. For other hosting platforms (Render, Railway, Cloud Run, etc.), ensure HTTPS is configured in front of the app to protect the bearer tokens and session cookies in transit.

### Stdio Only (Current)

**As of version 1.18.0, hevy-mcp only supports stdio transport.** HTTP/SSE
transport has been completely removed.

hevy-mcp runs exclusively over stdio, which works seamlessly with MCP-aware clients like Claude Desktop and Cursor. The server communicates via standard input/output streams using JSON-RPC messages.

### Migration from HTTP/SSE Transport

**If you were using HTTP or SSE transport in an older version (< 1.18.0), you must migrate to stdio.**

The HTTP/SSE transport was removed in v1.18.0 to simplify the codebase and focus
on the stdio-native MCP experience. If you're encountering errors like:

- `"stream is not readable"` when making HTTP requests
- `"HTTP transport mode has been removed from hevy-mcp"`
- Server messages about SSE mode on `http://localhost:3001`

You are likely running an outdated build or trying to connect with an HTTP-based client. Here's how to fix it:

#### Steps to Migrate:

1. **Update to the latest version:**
   ```bash
   npx -y hevy-mcp@latest
   # or if installed locally:
   pnpm install hevy-mcp@latest
   ```

2. **Update your client configuration** to use stdio transport instead of HTTP. For example, in Cursor's `~/.cursor/mcp.json`:
   
   **Old HTTP-based config (no longer supported):**
   ```json
   {
     "hevy-mcp": {
       "url": "http://localhost:3001/sse"
     }
   }
   ```
   
   **New stdio-based config (current):**
   ```json
   {
     "hevy-mcp": {
       "command": "npx",
       "args": ["-y", "hevy-mcp"],
       "env": {
         "HEVY_API_KEY": "your-api-key-here"
       }
     }
   }
   ```

3. **Clear any cached builds:**
   ```bash
   # If you have a local clone, rebuild
   pnpm run build
   
   # Or remove node_modules and reinstall
   rm -rf node_modules dist
   pnpm install
   pnpm run build
   ```

4. **Ensure you're not running a custom HTTP server.** If you have custom code that imports `createHttpServer()`, it will now throw an error. Remove those imports and use stdio transport instead.

If you absolutely need HTTP/SSE transport, you can use version `1.17.x` or earlier, but those versions are no longer maintained and contain known bugs (including the "stream is not readable" issue caused by middleware conflicts).

## Usage

### Development

```bash
pnpm run dev
```

This starts the MCP server in development mode with hot reloading.

### Production

```bash
pnpm run build
pnpm start
```

### Docker (deprecated)

Docker-based workflows have been retired so we can focus on the stdio-native experience. The bundled `Dockerfile` now exits with a clear message to prevent accidental builds, and `.dockerignore` simply documents the deprecation. Previously published images remain available on GHCR (for example `ghcr.io/chrisdoc/hevy-mcp:latest`), but they are **no longer updated**. For the best experience, run the server locally via `npx hevy-mcp` or your own Node.js runtime.

## Available MCP Tools

The server implements the following MCP tools for interacting with the Hevy API:

### Workout Tools
- `get-workouts`: Fetch and format workout data
- `get-workout`: Get a single workout by ID
- `create-workout`: Create a new workout
- `update-workout`: Update an existing workout
- `get-workout-count`: Get the total count of workouts
- `get-workout-events`: Get workout update/delete events

### Routine Tools
- `get-routines`: Fetch and format routine data
- `create-routine`: Create a new routine
- `update-routine`: Update an existing routine
- `get-routine-by-id`: Get a single routine by ID using direct endpoint

### Exercise Template Tools
- `get-exercise-templates`: Fetch exercise templates
- `get-exercise-template`: Get a template by ID

### Routine Folder Tools
- `get-routine-folders`: Fetch routine folders
- `create-routine-folder`: Create a new folder
- `get-routine-folder`: Get a folder by ID

### Webhook Tools
- `get-webhook-subscription`: Get the current webhook subscription
- `create-webhook-subscription`: Create a new webhook subscription
- `delete-webhook-subscription`: Delete the current webhook subscription

## Project Structure

```plaintext
hevy-mcp/
├── .env                   # Environment variables (API keys)
├── src/
│   ├── index.ts           # Main entry point
│   ├── tools/             # Directory for MCP tool implementations
│   │   ├── workouts.ts    # Workout-related tools
│   │   ├── routines.ts    # Routine-related tools
│   │   ├── templates.ts   # Exercise template tools
│   │   ├── folders.ts     # Routine folder tools
│   │   └── webhooks.ts    # Webhook subscription tools
│   ├── generated/         # API client (generated code)
│   │   ├── client/        # Kubb-generated client
│   │   │   ├── api/       # API client methods
│   │   │   ├── types/     # TypeScript types
│   │   │   ├── schemas/   # Zod schemas
│   │   │   └── mocks/     # Mock data
│   └── utils/             # Helper utilities
│       ├── config.ts              # Env/CLI config parsing
│       ├── error-handler.ts       # Tool error wrapper + response builder
│       ├── formatters.ts          # Domain formatting helpers
│       ├── hevyClient.ts          # API client factory
│       ├── httpServer.ts          # Legacy HTTP transport (deprecated; throws explicit error; kept only for backward compatibility - removing may be breaking)
│       ├── response-formatter.ts  # MCP response utilities
│       └── tool-helpers.ts        # Zod schema -> TS type inference
├── scripts/               # Build and utility scripts
└── tests/                 # Test suite
    ├── integration/       # Integration tests with real API
    │   └── hevy-mcp.integration.test.ts  # MCP server integration tests
```

## Development Guide

### Code Style

This project uses Biome for code formatting and linting:

```bash
pnpm run check
```

### Testing

#### Run All Tests

To run all tests (unit and integration), use:

```bash
pnpm test
```

> **Note:** `pnpm test` runs **all** tests. Integration tests will fail by design if
> `HEVY_API_KEY` is missing. If you don’t have an API key locally, use the unit
> test command below.

#### Run Only Unit Tests

To run only unit tests (excluding integration tests):

```bash
pnpm vitest run --exclude tests/integration/**
```

Or with coverage:

```bash
pnpm vitest run --coverage --exclude tests/integration/**
```

#### Run Only Integration Tests

To run only the integration tests (requires a valid `HEVY_API_KEY`):

```bash
pnpm vitest run tests/integration
```

**Note:** The integration tests will fail if the `HEVY_API_KEY` environment variable is not set. This is by design to ensure that the tests are always run with a valid API key.

##### GitHub Actions Configuration

For GitHub Actions:

1. Unit + integration tests are executed as part of the normal `Build and Test` workflow
2. Integration tests require the `HEVY_API_KEY` secret to be set

The workflow runs `pnpm vitest run --coverage` and provides `HEVY_API_KEY` from
repository secrets.

To set up the `HEVY_API_KEY` secret:

1. Go to your GitHub repository
2. Click on "Settings" > "Secrets and variables" > "Actions"
3. Click on "New repository secret"
4. Set the name to `HEVY_API_KEY` and the value to your Hevy API key
5. Click "Add secret"

If the secret is not set, the integration tests will fail (by design).

To set up Sentry secrets for source map uploads during builds:

The build process uses Sentry's Rollup plugin to upload source maps. You need to configure three secrets:

1. Go to your GitHub repository
2. Click on "Settings" > "Secrets and variables" > "Actions"
3. Add the following secrets:
   - `SENTRY_ORG`: Your Sentry organization slug
   - `SENTRY_PROJECT`: Your Sentry project slug
   - `SENTRY_AUTH_TOKEN`: A Sentry auth token with `project:releases` scope

   You can create a Sentry auth token at: https://sentry.io/settings/account/api/auth-tokens/

If these secrets are not set, the build will still succeed, but source maps will not be uploaded to Sentry.

Note: GitHub does not provide secrets to pull requests from forks by default, so
fork PRs may fail CI unless a maintainer reruns the checks with `HEVY_API_KEY`
available.

If CI is failing only because the fork PR is missing `HEVY_API_KEY`, that is
expected; maintainers may rerun the workflow with secrets enabled.

For contributors from forks: CI failures caused solely by missing `HEVY_API_KEY`
do not indicate a problem with your changes.

All other CI checks (build, formatting/linting, unit tests, etc.) are still
expected to pass.

Only failures caused solely by missing `HEVY_API_KEY` on forked PRs are
considered acceptable.

### Generating API Client

The API client is generated from the OpenAPI specification using [Kubb](https://kubb.dev/):

```bash
pnpm run export-specs
pnpm run build:client
```

Kubb generates TypeScript types, API clients, Zod schemas, and mock data from the OpenAPI specification.

### Troubleshooting

- **Rollup optional dependency missing**: If you see an error similar to `Cannot find module @rollup/rollup-linux-x64-gnu`, set the environment variable `ROLLUP_SKIP_NODEJS_NATIVE_BUILD=true` before running `pnpm run build`. This forces Rollup to use the pure JavaScript fallback and avoids the npm optional dependency bug on some Linux runners.

### Troubleshooting Smithery deployments

- **`smithery.yaml` validation failed (unexpected fields)**: Only `runtime`, `target`, and `env` are allowed for the TypeScript runtime. Remove `entry`, `name`, or other fields.
- **`Could not resolve "chalk"/"cors"`**: Run `pnpm install` so the runtime dependencies listed in `package.json` are present before invoking Smithery.
- **`Failed to connect to Smithery API: Unauthorized`**: Log in via `pnpm dlx @smithery/cli login` or set `SMITHERY_API_KEY` in `.env`.
- **Tunnel crashes with `RangeError: Invalid count value`**: This is a known issue in certain `@smithery/cli` builds. Upgrade/downgrade the CLI (e.g., `pnpm add -D @smithery/cli@latest`) or contact Smithery support.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Acknowledgements

- [Model Context Protocol](https://github.com/modelcontextprotocol) for the MCP SDK
- [Hevy](https://www.hevyapp.com/) for their fitness tracking platform and API
