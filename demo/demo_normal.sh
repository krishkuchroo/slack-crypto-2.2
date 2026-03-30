#!/bin/bash
set -e
echo "============================================"
echo "  Scenario 1: Normal Flow"
echo "============================================"
echo ""

echo "[1/6] Generating keypairs for alice..."
python client.py keygen --name alice
echo ""

echo "[2/6] Generating keypairs for bob..."
python client.py keygen --name bob
echo ""

echo "[3/6] Verifying fingerprints..."
python client.py fingerprint --name alice
python client.py fingerprint --name bob
echo ""

echo "[4/6] Initializing encrypted channel..."
python client.py init-channel --channel incident-2026 --admin alice --members bob
echo ""

echo "[5/6] Alice posts an encrypted message..."
python client.py post --channel incident-2026 --sender alice --message 'Isolate host 10.0.0.5 immediately'
echo ""
echo "--- Check Slack channel: you should see an opaque JSON ciphertext blob ---"
sleep 2

echo ""
echo "[6/6] Bob fetches and decrypts..."
python client.py fetch --channel incident-2026 --receiver bob
echo ""
echo "============================================"
echo "  Normal flow complete. Message encrypted,"
echo "  posted, fetched, verified, and decrypted."
echo "============================================"
