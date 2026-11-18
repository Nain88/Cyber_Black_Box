#!/bin/sh
# Trust container: isolated Ed25519 signer (8766) + checkpoint witness (8767).
# The witness pins the signer's public key, which is the deployment key when
# the app uses the remote signer. Both processes share one container to keep
# the stack small; for a production deployment run the witness elsewhere.
set -eu
mkdir -p /data/signer /data/witness

python -m cbb.signer --host 0.0.0.0 --port 8766 --data /data/signer &
SIGNER=$!

KEY=""
for _ in $(seq 1 60); do
  KEY=$(python - <<'PY' 2>/dev/null || true
import json, os, urllib.request
req = urllib.request.Request("http://127.0.0.1:8766/public-key",
                             headers={"Authorization": "Bearer " + os.environ["CBB_SIGNER_TOKEN"]})
print(json.load(urllib.request.urlopen(req, timeout=2))["public_key"])
PY
)
  [ -n "$KEY" ] && break
  sleep 1
done
if [ -z "$KEY" ]; then
  echo "trust: signer did not become ready" >&2
  kill "$SIGNER" 2>/dev/null || true
  exit 1
fi
echo "trust: signer ready, deployment public key $KEY"

python -m cbb.witness --host 0.0.0.0 --port 8767 --data /data/witness --trusted-key "$KEY" &
WITNESS=$!

# Exit (and let Docker restart us) if either process stops.
while kill -0 "$SIGNER" 2>/dev/null && kill -0 "$WITNESS" 2>/dev/null; do
  sleep 2
done
kill "$SIGNER" "$WITNESS" 2>/dev/null || true
exit 1
