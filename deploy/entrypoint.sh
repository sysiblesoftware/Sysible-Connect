#!/usr/bin/env bash
# Sysible Connect container entrypoint. Serves the app (API + console) on :8700,
# over HTTPS with a self-signed cert by default so the browser terminal runs in a
# secure context (clipboard/paste) and traffic is encrypted on the network.
# Set SYSIBLE_CONNECT_TLS=0 to serve plain HTTP behind a TLS-terminating proxy.
set -euo pipefail

: "${PORT:=8700}"
: "${SYSIBLE_CONNECT_DATA:=/data}"
: "${SYSIBLE_CONNECT_TLS:=1}"
: "${SYSIBLE_CONNECT_TLS_HOSTS:=}"

TLS_DIR="${SYSIBLE_CONNECT_DATA}/tls"

SSL_ARGS=()
if [[ "${SYSIBLE_CONNECT_TLS}" != "0" ]]; then
  mkdir -p "${TLS_DIR}"
  CRT="${TLS_DIR}/server.crt"; KEY="${TLS_DIR}/server.key"
  if [[ ! -f "${CRT}" || ! -f "${KEY}" ]]; then
    echo "[entrypoint] generating a self-signed TLS certificate in ${TLS_DIR}"
    # Cover localhost + any host/IP listed in SYSIBLE_CONNECT_TLS_HOSTS so the
    # name-mismatch warning goes away for those. Comma-separated SANs.
    san="DNS:localhost,IP:127.0.0.1"
    IFS=',' read -ra _hosts <<< "${SYSIBLE_CONNECT_TLS_HOSTS}"
    for h in "${_hosts[@]}"; do
      [[ -z "${h}" ]] && continue
      if [[ "${h}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then san="${san},IP:${h}"; else san="${san},DNS:${h}"; fi
    done
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "${KEY}" -out "${CRT}" -subj "/CN=sysible-connect" \
      -addext "subjectAltName=${san}" >/dev/null 2>&1
    chmod 600 "${KEY}"; chmod 644 "${CRT}"
  fi
  SSL_ARGS=(--ssl-certfile "${CRT}" --ssl-keyfile "${KEY}")
  echo "[entrypoint] console: https://0.0.0.0:${PORT} (self-signed TLS)"
else
  echo "[entrypoint] console: http://0.0.0.0:${PORT} (TLS disabled)"
fi

exec uvicorn backend.app:app --host 0.0.0.0 --port "${PORT}" "${SSL_ARGS[@]}"
