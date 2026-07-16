# Build stage
FROM node:22-alpine AS builder

# Install pnpm
RUN corepack enable && corepack prepare pnpm@10.22.0 --activate

WORKDIR /app

# Copy package files first for better layer caching
COPY package.json pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the project
RUN pnpm run build

# Prune dev dependencies for production
RUN pnpm prune --prod

# Production stage
FROM node:22-alpine AS production

WORKDIR /app

# Copy built artifacts and production dependencies
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Set environment
ENV NODE_ENV=production \
    MCP_HTTP=true \
    PORT=3000 \
    DATABASE_PATH=/data/hevy-mcp.sqlite

# Persist the SQLite database across container recreations
VOLUME /data

EXPOSE 3000

# Required at runtime when deploying as a remote MCP server (multi-tenant HTTP mode):
#   ENCRYPTION_KEY      - base64-encoded 32-byte AES-256-GCM master key
#                         Generate: openssl rand -base64 32
#   APPLE_TEAM_ID       - Apple developer team ID
#   APPLE_CLIENT_ID     - Apple Services ID (OAuth client_id for Sign in with Apple)
#   APPLE_KEY_ID        - Apple Sign in key ID
#   APPLE_PRIVATE_KEY   - Contents of the Apple Sign in .p8 private key file
#   APPLE_REDIRECT_URI  - Apple OAuth redirect URI (e.g. https://<app>.fly.dev/auth/apple/callback)
#   DATABASE_PATH       - Path to SQLite database file (defaults to /data/hevy-mcp.sqlite above)
#
# NOTE: HEVY_API_KEY is NOT required for HTTP mode anymore — each user brings their own
# Hevy API key via the web dashboard (/account), encrypted at rest with ENCRYPTION_KEY.
# HEVY_API_KEY is still required/used for the separate stdio/local single-user mode,
# which is unaffected by this change.
#
# Production deployments MUST terminate TLS in front of this container.

ENTRYPOINT ["node", "dist/cli.mjs"]
