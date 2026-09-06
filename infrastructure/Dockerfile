# Ward — the estate's identity service.
#
# Build context is the REPO ROOT (one root lockfile covers the api, ui and
# client workspaces). Multi-stage: the TypeScript compiler and the native build
# toolchain live in build stages and never reach the runtime image.
#
#   docker compose -f infrastructure/docker-compose.yml up ward-api
#
# ── Why this container runs as root ─────────────────────────────────────────
#
# It looks alarming and is not. On the VPS this runs under a ROOTLESS Docker
# daemon owned by an unprivileged account, where the container's uid 0 maps to
# that account's own uid on the host — so "root" here is already a normal
# unprivileged user out there, and a container escape lands on an account with
# no sudo and no docker group.
#
# It has to be uid 0 specifically because /data is a BIND MOUNT of the host's
# /srv/ward-api/data, which holds the credential database and the estate's
# signing key. Under rootless Docker only container-root maps back to the owning
# account; a non-root in-container user maps to a subuid the host sees as a
# stranger, and the service could not write its own database.

# ---------------------------------------------------------------------------
# deps — full workspace install, with the toolchain native modules may need
# ---------------------------------------------------------------------------
FROM node:24-alpine AS deps
# better-sqlite3 13 ships Node-API prebuilds including linuxmusl-x64, so this is
# a fallback rather than the normal path — but a version bump that drops the
# musl prebuild would otherwise fail the build with a cryptic node-gyp error.
RUN apk add --no-cache python3 make g++
WORKDIR /app
# Manifests first, for layer caching: one root lockfile, one npm ci. All three
# workspace manifests are needed because `npm ci` validates the lockfile against
# every workspace the root package.json declares and bails on a missing one.
COPY package.json package-lock.json tsconfig.base.json ./
COPY api/package.json ./api/
COPY ui/package.json ./ui/
COPY client/package.json ./client/
RUN npm ci

# ---------------------------------------------------------------------------
# builder — compile the API (tsc → api/dist)
# ---------------------------------------------------------------------------
FROM deps AS builder
COPY api ./api
RUN npm run build -w @ward/api

# ---------------------------------------------------------------------------
# proddeps — runtime dependencies only, native modules built here
# ---------------------------------------------------------------------------
FROM node:24-alpine AS proddeps
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json ./
COPY api/package.json ./api/
COPY ui/package.json ./ui/
COPY client/package.json ./client/
# Scoped to the api workspace: unscoped this would also install whatever the ui
# grows (React and its tree), which the server never runs.
RUN npm ci --omit=dev -w @ward/api --include-workspace-root
# Drop native build intermediates and the prebuilds for operating systems this
# image can never be.
#
# Deliberately a BLACKLIST of foreign platforms rather than a whitelist of the
# ones to keep. The first version of this was a whitelist, and it silently
# deleted everything: better-sqlite3 ships prebuilds as FILES
# (`prebuilds/linuxmusl-x64.node`), not as directories, so a `case` matching
# bare names like `linux-x64` matched nothing and the else-branch removed the
# lot. The image built clean and then crash-looped on
# `Cannot find module .../build/Release/better_sqlite3.node`, because with no
# prebuild left the loader falls back to a compiled binding that was never
# built. Keeping every linux prebuild costs a few megabytes; getting this wrong
# costs a boot.
RUN cd node_modules \
 && find . -name '*.o' -delete \
 && find . -type d -name obj.target -prune -exec rm -rf {} + \
 && rm -rf better-sqlite3/deps better-sqlite3/src \
 && find . -type d -name prebuilds -exec sh -c \
      'rm -f "$1"/darwin-*.node "$1"/win32-*.node "$1"/android-*.node' _ {} \;

# ---------------------------------------------------------------------------
# prod — slim runtime: no compiler, no test code, no TypeScript
# ---------------------------------------------------------------------------
FROM node:24-alpine AS prod
LABEL org.opencontainers.image.title="Ward" \
      org.opencontainers.image.description="The estate's identity service"
# wget, for the healthcheck below, ships in node:alpine's busybox.
WORKDIR /app
COPY --from=proddeps /app/node_modules ./node_modules
COPY --from=builder /app/api/dist ./api/dist
COPY package.json ./
COPY api/package.json ./api/
# tsc compiles src/**/* including the tests. They import a runner that
# --omit=dev never installed, so shipping them would be dead weight that also
# fails if anything ever tried to run it.
RUN find ./api/dist -name '*.test.js' -delete \
 && find ./api/dist -name '*.test.js.map' -delete \
 && rm -f ./api/dist/db/test-support.js ./api/dist/db/test-support.js.map \
 && rm -rf ./api/dist/integration
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8791 \
    WARD_DB_PATH=/data/ward.db \
    WARD_SIGNING_KEY_PATH=/data/signing-key.pem \
    WARD_MAIL_FILE_DIR=/data/mail
# The credential database, the estate's signing key and the mail spool. A BIND
# MOUNT on the VPS (the host's /srv/ward-api/data), so this survives every
# deploy and stays where the backups already point.
VOLUME /data
EXPOSE 8791
# `pm2 start` used to exit 0 for a process that died a second later; so does
# `compose up`. This is the same guard, now owned by the image.
# Shell form, so it follows the runtime PORT rather than a baked constant — the
# compose file publishes ${PORT} and the service listens on it.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" || exit 1
CMD ["node", "api/dist/index.js"]
