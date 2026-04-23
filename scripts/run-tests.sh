#!/usr/bin/env bash
# run-tests.sh — run all daemon (pytest) and extension (vitest) tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SCRIPT_DIR}/.."
DAEMON_DIR="${ROOT}/daemon"
EXT_DIR="${ROOT}/extension"
VENV="${DAEMON_DIR}/.venv"

echo "══════════════════════════════════════════"
echo "  CIDAS Test Suite"
echo "══════════════════════════════════════════"

# ── Daemon tests (pytest) ──────────────────────────────────────────────────
echo ""
echo "▶ Running daemon tests (pytest)…"

if [[ ! -d "${VENV}" ]]; then
  echo "[CIDAS] Venv not found — installing daemon dependencies first…"
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q --upgrade pip
  "${VENV}/bin/pip" install -q -e "${DAEMON_DIR}[dev]"
fi

cd "${ROOT}"
"${VENV}/bin/pytest" daemon/tests -v --tb=short
PYTEST_EXIT=$?

# ── Extension tests (vitest) ───────────────────────────────────────────────
echo ""
echo "▶ Running extension tests (vitest)…"

cd "${EXT_DIR}"
if [[ ! -d "node_modules" ]]; then
  echo "[CIDAS] Installing extension dependencies…"
  npm install
fi

npm test
VITEST_EXIT=$?

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
if [[ ${PYTEST_EXIT} -eq 0 && ${VITEST_EXIT} -eq 0 ]]; then
  echo "  ALL TESTS PASSED"
  exit 0
else
  echo "  SOME TESTS FAILED (pytest=${PYTEST_EXIT}, vitest=${VITEST_EXIT})"
  exit 1
fi
