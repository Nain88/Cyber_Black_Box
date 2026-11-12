#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -z "${LAB_SHARED_KEY:-}" ]]; then
  read -r -s -p 'Enter the same LAB_SHARED_KEY used for Windows relay: ' LAB_SHARED_KEY
  echo
  export LAB_SHARED_KEY
fi
if [[ ${#LAB_SHARED_KEY} -lt 24 ]]; then
  echo 'LAB_SHARED_KEY must contain at least 24 characters' >&2
  exit 1
fi
exec python3 target.py --host 0.0.0.0 --port 8088 --data .lab-kali-data
