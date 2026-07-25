# --- Build stage: install dependencies with dev tools available ---
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# --- Runtime stage: minimal image, no build tooling, non-root user ---
FROM node:22-slim AS runtime
WORKDIR /app

# Run as an unprivileged user rather than root, limiting blast radius if the
# container is ever compromised.
RUN groupadd -r vaultshare && useradd -r -g vaultshare -m vaultshare

COPY --from=build /app/node_modules ./node_modules
COPY package*.json ./
COPY src ./src
COPY scripts ./scripts

RUN mkdir -p data uploads logs \
    && chown -R vaultshare:vaultshare /app

USER vaultshare

ENV NODE_ENV=production
EXPOSE 3000

# Basic healthcheck so orchestrators (docker-compose, k8s) can detect a dead app.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/login', r => process.exit(r.statusCode < 500 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "src/server.js"]
