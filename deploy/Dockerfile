# Sysible Connect — the fleet terminal workspace, single container.
#
# One image: the FastAPI app (backend.app:app) serves both the JSON API and the
# built React console on :8700, over HTTPS with a self-signed cert by default.
# Login, host inventory, the encrypted Controller link and the per-install secret
# key live on the /data volume, so they survive rebuilds.
#
#   docker compose -f deploy/docker-compose.yml up -d --build
#   open https://localhost:8700

# ---- stage 1: build the React console -------------------------------------
FROM node:22-slim AS web
WORKDIR /web
COPY webgui/frontend/package.json webgui/frontend/package-lock.json ./
RUN npm ci
COPY webgui/frontend/ ./
RUN npm run build      # -> /web/dist

# ---- stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim

# bash (entrypoint + the "Local shell" PTY), openssl (self-signed TLS cert),
# openssh-client (host-key scanning / SFTP niceties alongside paramiko),
# ca-certificates (verify Controller/HTTPS), curl (healthcheck).
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash openssl openssh-client ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY webgui/ webgui/
COPY deploy/entrypoint.sh /entrypoint.sh
COPY --from=web /web/dist webgui/frontend/dist

ENV PYTHONPATH=/app \
    SYSIBLE_CONNECT_DATA=/data \
    SYSIBLE_CONNECT_TLS=1 \
    PORT=8700 \
    PYTHONUNBUFFERED=1

# Non-root. Declare the volume AFTER chown so a fresh named volume inherits the
# connect user's ownership (Docker seeds it from the image path).
RUN chmod +x /entrypoint.sh \
    && useradd -r -m -d /home/connect connect \
    && mkdir -p /data \
    && chown -R connect:connect /app /data
USER connect
VOLUME ["/data"]
EXPOSE 8700

# Liveness: the console answers on 8700 — HTTPS (self-signed, hence -k) by
# default, or plain HTTP when SYSIBLE_CONNECT_TLS=0.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsk https://127.0.0.1:8700/healthz >/dev/null 2>&1 \
   || curl -fs  http://127.0.0.1:8700/healthz  >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
