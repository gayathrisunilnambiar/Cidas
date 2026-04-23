#!/usr/bin/env bash
# start-daemon.sh — activate venv and launch the CIDAS daemon.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON_DIR="${SCRIPT_DIR}/../daemon"

# Load .env if it exists in the project root
ENV_FILE="${SCRIPT_DIR}/../.env"
if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "${ENV_FILE}"
  set +a
  echo "[CIDAS] Loaded environment from ${ENV_FILE}"
fi

# Activate venv
VENV="${DAEMON_DIR}/.venv"
if [[ ! -d "${VENV}" ]]; then
  echo "[CIDAS] Creating Python virtual environment…"
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q --upgrade pip
  "${VENV}/bin/pip" install -q -e "${DAEMON_DIR}[dev]"
fi

echo "[CIDAS] Starting daemon on ${DAEMON_HOST:-127.0.0.1}:${DAEMON_PORT:-7979}"
exec "${VENV}/bin/python" -m daemon.main
