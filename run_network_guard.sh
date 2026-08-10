#!/usr/bin/env bash
# Network Guard launcher for Linux (local + LAN, interactive triage)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3."
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Re-launching with sudo for firewall / process control..."
  exec sudo -E python3 ./network_guard.py --lan "$@"
fi

exec python3 ./network_guard.py --lan "$@"
