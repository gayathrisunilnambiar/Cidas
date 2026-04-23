#!/usr/bin/env bash
# install-shim.sh — installs the CIDAS npm shim on the current system.
# The real npm binary path is saved so the shim can delegate to it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIM_SRC="${SCRIPT_DIR}/npm-shim.js"
CIDAS_DIR="${HOME}/.cidas"
SHIM_LINK="${CIDAS_DIR}/npm"
REAL_NPM_FILE="${CIDAS_DIR}/real-npm"

echo "[CIDAS] Installing npm shim…"

# Find the real npm
REAL_NPM="$(command -v npm)"
if [[ -z "${REAL_NPM}" ]]; then
  echo "[CIDAS] Error: npm not found on PATH. Install Node.js first." >&2
  exit 1
fi

# Refuse to wrap ourselves
if [[ "${REAL_NPM}" == "${SHIM_LINK}" ]]; then
  echo "[CIDAS] Shim already installed. Run uninstall-shim.sh first if you want to reinstall." >&2
  exit 1
fi

mkdir -p "${CIDAS_DIR}"
echo "${REAL_NPM}" > "${REAL_NPM_FILE}"
echo "[CIDAS] Real npm saved: ${REAL_NPM}"

# Copy shim and make executable
cp "${SHIM_SRC}" "${SHIM_LINK}"
chmod +x "${SHIM_LINK}"
echo "[CIDAS] Shim installed at ${SHIM_LINK}"

# Prepend ~/.cidas to PATH if not already there
SHELL_RC=""
case "${SHELL}" in
  */zsh)  SHELL_RC="${HOME}/.zshrc" ;;
  */bash) SHELL_RC="${HOME}/.bashrc" ;;
  *)      SHELL_RC="${HOME}/.profile" ;;
esac

PATH_LINE='export PATH="${HOME}/.cidas:${PATH}"  # CIDAS npm shim'
if ! grep -qF "CIDAS npm shim" "${SHELL_RC}" 2>/dev/null; then
  echo "" >> "${SHELL_RC}"
  echo "${PATH_LINE}" >> "${SHELL_RC}"
  echo "[CIDAS] Added PATH entry to ${SHELL_RC}"
fi

echo "[CIDAS] Installation complete."
echo "[CIDAS] Open a new terminal (or run: source ${SHELL_RC}) for changes to take effect."
