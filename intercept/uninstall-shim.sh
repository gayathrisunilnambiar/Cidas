#!/usr/bin/env bash
# uninstall-shim.sh — removes the CIDAS npm shim.

set -euo pipefail

CIDAS_DIR="${HOME}/.cidas"
SHIM_LINK="${CIDAS_DIR}/npm"
REAL_NPM_FILE="${CIDAS_DIR}/real-npm"

echo "[CIDAS] Uninstalling npm shim…"

if [[ -f "${SHIM_LINK}" ]]; then
  rm -f "${SHIM_LINK}"
  echo "[CIDAS] Removed shim: ${SHIM_LINK}"
else
  echo "[CIDAS] Shim not found at ${SHIM_LINK} — nothing to remove."
fi

# Remove PATH line from shell rc files
for RC in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.profile"; do
  if [[ -f "${RC}" ]] && grep -qF "CIDAS npm shim" "${RC}"; then
    # Portable in-place deletion (works on both Linux sed and macOS)
    grep -vF "CIDAS npm shim" "${RC}" > "${RC}.cidas_tmp" && mv "${RC}.cidas_tmp" "${RC}"
    echo "[CIDAS] Removed PATH entry from ${RC}"
  fi
done

echo "[CIDAS] Uninstallation complete. Open a new terminal or re-source your shell RC."
