#!/bin/bash
set -e
echo "============================================"
echo "  Scenario 4: Replay Rejected"
echo "============================================"
echo ""

echo "[1/2] Re-posting an old message (seq=1) to simulate replay attack..."
python client.py replay --channel incident-2026 --seq 1
echo ""
sleep 2

echo "[2/2] Bob fetches messages..."
python client.py fetch --channel incident-2026 --receiver bob
echo ""
echo "============================================"
echo "  Expected: the replayed message is rejected"
echo "  with [REPLAY] because seq=1 has already"
echo "  been accepted. The monotonic counter per"
echo "  sender prevents acceptance of old messages."
echo "============================================"
