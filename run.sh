#!/bin/sh
# Self-bootstrapping launcher for Sysible Connect.
#
#   ./run.sh            # venv + deps + build the SPA + serve over HTTPS on :8700
#   HOST=127.0.0.1 PORT=9443 ./run.sh
#   SYSIBLE_CONNECT_PASSWORD=... ./run.sh          # admin password on first run
#   SYSIBLE_CONNECT_TLS_HOSTS=192.168.8.249,connect.lan ./run.sh   # cert SANs
#   SYSIBLE_CONNECT_TLS=0 ./run.sh                 # plain HTTP (front with a proxy)
#
# Set SYSIBLE_CONNECT_NO_BOOTSTRAP=1 to skip the venv/deps/SPA/cert steps.
set -e
cd "$(dirname "$0")"

DATA="${SYSIBLE_CONNECT_DATA:-$HOME/.sysible-connect}"
TLS_DIR="$DATA/tls"
PY="python3"

if [ "${SYSIBLE_CONNECT_NO_BOOTSTRAP:-0}" != "1" ]; then
  VENV="${SYSIBLE_CONNECT_VENV:-.venv}"
  if [ ! -x "$VENV/bin/python" ]; then
    echo "==> creating virtualenv in $VENV"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1090
  . "$VENV/bin/activate"
  PY="python"
  echo "==> installing Python dependencies"
  python -m pip install -q --upgrade pip >/dev/null 2>&1 || true
  python -m pip install -q -r requirements.txt

  # Build the web console EVERY run so a `git pull` is reflected without stale
  # dist/ (npm ci only when node_modules is absent — that's the slow part).
  if command -v npm >/dev/null 2>&1; then
    echo "==> building the web console (npm)"
    ( cd webgui/frontend
      [ -d node_modules ] || npm ci --no-audit --no-fund
      npm run build )
  else
    echo "WARNING: npm not found — the browser UI won't be (re)built." >&2
  fi
fi

# ---- HTTPS by default: a self-signed cert like Controller/SLEP, so the console is
# a secure context (clipboard/paste) and traffic is encrypted on the LAN. ----
SSL_ARGS=""
if [ "${SYSIBLE_CONNECT_TLS:-1}" != "0" ]; then
  mkdir -p "$TLS_DIR"
  CRT="$TLS_DIR/server.crt"; KEY="$TLS_DIR/server.key"
  if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
    if command -v openssl >/dev/null 2>&1; then
      echo "==> generating a self-signed TLS certificate in $TLS_DIR"
      # Cover localhost + any host/IP the operator lists, so the name-mismatch
      # warning goes away for those. Comma-separated SANs.
      _san="DNS:localhost,IP:127.0.0.1"
      OLD_IFS=$IFS; IFS=','
      for h in ${SYSIBLE_CONNECT_TLS_HOSTS:-}; do
        [ -z "$h" ] && continue
        if echo "$h" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then _san="$_san,IP:$h"; else _san="$_san,DNS:$h"; fi
      done
      IFS=$OLD_IFS
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$KEY" -out "$CRT" -subj "/CN=sysible-connect" \
        -addext "subjectAltName=$_san" >/dev/null 2>&1
      chmod 600 "$KEY"; chmod 644 "$CRT"
    else
      echo "WARNING: openssl not found — serving plain HTTP. Set SYSIBLE_CONNECT_TLS=0 to silence, or install openssl." >&2
    fi
  fi
  [ -f "$CRT" ] && [ -f "$KEY" ] && SSL_ARGS="--ssl-certfile $CRT --ssl-keyfile $KEY"
fi

SCHEME="http"; [ -n "$SSL_ARGS" ] && SCHEME="https"
echo "==> serving on ${SCHEME}://${HOST:-0.0.0.0}:${PORT:-8700}"
# shellcheck disable=SC2086
exec "$PY" -m uvicorn backend.app:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8700}" $SSL_ARGS
