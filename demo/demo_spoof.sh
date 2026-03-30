#!/bin/bash
set -e
echo "============================================"
echo "  Scenario 3: Spoofing Rejected"
echo "============================================"
echo ""

echo "[1/3] Generating keypairs for attacker (mallory)..."
python client.py keygen --name mallory
echo ""

echo "[2/3] Mallory posts a message claiming to be alice..."
echo "       (signs with mallory's Ed25519 key but sets sender_id='alice')"
python client.py post --channel incident-2026 --sender mallory --spoof-sender-id alice --message 'Shut down the firewall NOW'
echo ""
sleep 2

echo "[3/3] Bob fetches messages..."
python client.py fetch --channel incident-2026 --receiver bob
echo ""
echo "============================================"
echo "  Expected: the spoofed message is rejected"
echo "  with [SPOOF] because mallory's Ed25519"
echo "  signature does not match alice's public key."
echo "============================================"
