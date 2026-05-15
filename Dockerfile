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
    PORT=3000

EXPOSE 3000

# Required at runtime when deploying as a remote MCP server:
#   HEVY_API_KEY       - Hevy API key used for all upstream calls
#   MCP_CLIENT_ID      - shared client ID required from MCP clients
#   MCP_CLIENT_SECRET  - shared client secret required from MCP clients
# Clients authenticate with HTTP Basic auth: Authorization: Basic base64(id:secret).
# Production deployments MUST terminate TLS in front of this container.

ENTRYPOINT ["node", "dist/cli.mjs"]
