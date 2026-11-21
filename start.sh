#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi

if ! .venv/bin/python -c 'import PyQt5, scapy' >/dev/null 2>&1; then
  .venv/bin/pip install --disable-pip-version-check -q -r requirements.txt
fi

if [[ ${EUID:-$(id -u)} -ne 0 && -z ${ARP_LAB_ELEVATED:-} ]]; then
  exec sudo -E env ARP_LAB_ELEVATED=1 bash "$0" "$@"
fi

exec .venv/bin/python run.py "$@"
