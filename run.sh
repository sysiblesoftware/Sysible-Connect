#!/bin/sh
# Self-bootstrapping launcher for Sysible Connect.
#
#   ./run.sh            # creates a venv, installs deps, builds the SPA if needed,
#                       # then serves API + SPA on :8700
#   HOST=127.0.0.1 PORT=9000 ./run.sh     # override the listen address
#   SYSIBLE_CONNECT_PASSWORD=... ./run.sh # set the admin password on first run
#
# Set SYSIBLE_CONNECT_NO_BOOTSTRAP=1 to skip the venv/deps/SPA steps (e.g. when the
# environment is already prepared, or in a container that bakes them in).
set -e
cd "$(dirname "$0")"

if [ "${SYSIBLE_CONNECT_NO_BOOTSTRAP:-0}" != "1" ]; then
  VENV="${SYSIBLE_CONNECT_VENV:-.venv}"
  if [ ! -x "$VENV/bin/python" ]; then
    echo "==> creating virtualenv in $VENV"
    python3 -m venv "$VENV"
  fi
  # shellcheck disable=SC1090
  . "$VENV/bin/activate"
  echo "==> installing Python dependencies"
  python -m pip install -q --upgrade pip >/dev/null 2>&1 || true
  python -m pip install -q -r requirements.txt

  # Build the web console once if it isn't built yet (run.sh serves dist/).
  if [ ! -f webgui/frontend/dist/index.html ]; then
    if command -v npm >/dev/null 2>&1; then
      echo "==> building the web console (npm)"
      (cd webgui/frontend && npm ci && npm run build)
    else
      echo "WARNING: the web console isn't built and npm isn't installed — the API will" >&2
      echo "         run but the browser UI won't be served. Install Node/npm, or build it" >&2
      echo "         elsewhere and copy webgui/frontend/dist/ into place." >&2
    fi
  fi
fi

# Prefer the venv's interpreter; fall back to python3 / python on PATH.
PY="python"
command -v "$PY" >/dev/null 2>&1 || PY="python3"
echo "==> serving on ${HOST:-0.0.0.0}:${PORT:-8700}"
exec "$PY" -m uvicorn backend.app:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8700}"
