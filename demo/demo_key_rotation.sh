#!/bin/bash
set -e
echo "============================================"
echo "  Scenario 5: Key Lifecycle"
echo "  (add member, revoke, key rotation)"
echo "============================================"
echo ""

echo "[1/7] Generating keypairs for carol..."
python client.py keygen --name carol
echo ""

echo "[2/7] Adding carol to the channel..."
python client.py addmember --channel incident-2026 --admin alice --member carol
echo ""

echo "[3/7] Alice posts a message (carol should be able to read)..."
python client.py post --channel incident-2026 --sender alice --message 'Carol can now read this'
echo ""
sleep 2

echo "[4/7] Carol fetches and decrypts..."
python client.py fetch --channel incident-2026 --receiver carol
echo ""

echo "[5/7] Revoking carol (rotates group key, excludes carol)..."
python client.py revoke --channel incident-2026 --admin alice --member carol
echo ""

echo "[6/7] Alice posts with the new key..."
python client.py post --channel incident-2026 --sender alice --message 'Carol CANNOT read this -- she has been revoked'
echo ""
sleep 2

echo "[7/7] Carol tries to fetch (should fail)..."
python client.py fetch --channel incident-2026 --receiver carol
echo ""
echo "============================================"
echo "  Expected: carol's last fetch fails with"
echo "  [ERROR] Cannot decrypt because she was"
echo "  excluded from the new key distribution."
echo "============================================"
