#!/bin/sh
# Dev/prod launcher. Build the SPA first (cd webgui/frontend && npm ci && npm run build),
# then:  ./run.sh   (serves API + SPA on :8700). Override host/port with HOST/PORT.
exec uvicorn backend.app:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8700}"
